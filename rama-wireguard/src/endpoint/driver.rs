//! Socket I/O, protocol scheduling and dynamic peer commands.
use super::{DriverError, EndpointError, PacketQueue, PeerRegistration};
use crate::{
    DeviceError, EphemeralPrivateKey, PeerConfig, PeerId, ServiceError, Tai64n, WireGuardCrypto,
    WireGuardService,
};
use ahash::HashMap;
use rama_core::rt::Executor;
use rama_net::ip::IpPacket;
use rama_udp::{DatagramMetadata, DatagramSocket};
use rand::TryRng as _;
use std::{
    io,
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, mpsc, oneshot, watch};

pub(super) struct Delivery {
    queue: PacketQueue,
    life: Arc<PeerRegistration>,
}

/// Sole owner of a socket, engine and scheduling. Both modes share one dispatch map.
#[must_use = "the endpoint driver must be run or spawned for packets to flow"]
pub struct EndpointDriver<C, S: DatagramSocket> {
    pub(super) service: WireGuardService<C, S>,
    pub(super) commands: mpsc::Receiver<Command>,
    pub(super) delivery: HashMap<PeerId, Delivery>,
    pub(super) wake: Arc<Notify>,
    pub(super) stop: watch::Receiver<bool>,
}
impl<C: WireGuardCrypto, S: DatagramSocket> EndpointDriver<C, S> {
    /// Runs until explicitly closed, all handles are dropped, or local I/O fails.
    /// Protocol-invalid traffic and full peer receive queues are discarded.
    pub async fn run(mut self) -> Result<(), DriverError> {
        let epoch = tokio::time::Instant::now();
        let offset = self.service.engine().current_time();
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buffer = vec![0; 65_535];
        let mut last_timestamp = None;
        loop {
            if *self.stop.borrow() {
                return Ok(());
            }
            self.remove_dropped_peers();
            self.maintain(offset.saturating_add(epoch.elapsed()), &mut last_timestamp)
                .await?;
            enum Event {
                Stop,
                Tick,
                PeerDropped,
                Command(Option<Command>),
                Datagram(Result<DatagramMetadata, rama_udp::DatagramError>),
            }
            // Only cancellation-safe receives are selected; protocol processing and writes
            // finish before the next select, preserving responses to consumed handshakes.
            let event = tokio::select! {
                _ = self.stop.changed() => Event::Stop,
                _ = timer.tick() => Event::Tick,
                _ = self.wake.notified() => Event::PeerDropped,
                command = self.commands.recv() => Event::Command(command),
                result = self.service.transport_mut().recv(&mut buffer) => Event::Datagram(result),
            };
            if *self.stop.borrow()
                || self.stop.has_changed().is_err()
                || matches!(event, Event::Stop | Event::Command(None))
            {
                return Ok(());
            }
            self.remove_dropped_peers();
            self.maintain(offset.saturating_add(epoch.elapsed()), &mut last_timestamp)
                .await?;
            match event {
                Event::Stop | Event::Command(None) => return Ok(()),
                Event::Tick | Event::PeerDropped => {}
                Event::Command(Some(command)) => self.command(command).await?,
                Event::Datagram(result) => {
                    let metadata = result
                        .map_err(|error| DriverError::WireGuard(ServiceError::Datagram(error)))?;
                    let ephemeral = if metadata.len >= 4 && buffer[..4] == 1u32.to_le_bytes() {
                        Some(ephemeral()?)
                    } else {
                        None
                    };
                    match self
                        .service
                        .process_received_ip_datagram(metadata, &mut buffer, ephemeral)
                        .await
                    {
                        Ok(packets) => {
                            for packet in packets {
                                if let Some(delivery) = self.delivery.get(&packet.peer) {
                                    delivery.queue.deliver(packet);
                                }
                            }
                        }
                        Err(
                            ServiceError::Engine(_)
                            | ServiceError::TruncatedDatagram
                            | ServiceError::CoalescedDatagram,
                        ) => {}
                        Err(error) => return Err(DriverError::WireGuard(error)),
                    }
                }
            }
        }
    }

    pub(super) fn remove_dropped_peers(&mut self) {
        let removed: Vec<_> = self
            .delivery
            .iter()
            .filter_map(|(id, delivery)| {
                (!delivery.life.active.load(Ordering::Acquire)).then_some(*id)
            })
            .collect();
        for peer in removed {
            drop(self.remove(peer));
        }
    }
    fn remove(&mut self, peer: PeerId) -> Result<(), DeviceError> {
        self.service.engine_mut().remove_peer(peer)?;
        self.delivery.remove(&peer);
        Ok(())
    }
    pub(super) async fn command(&mut self, command: Command) -> Result<(), DriverError> {
        match command {
            Command::Add {
                config,
                queue,
                life,
                reply,
            } => {
                if reply.is_closed() || !life.active.load(Ordering::Acquire) {
                    return Ok(());
                }
                match self.service.engine_mut().add_peer(&config) {
                    Ok(id) => {
                        self.delivery.insert(id, Delivery { queue, life });
                        if reply.send(Ok(id)).is_err() {
                            drop(self.remove(id));
                        }
                    }
                    Err(error) => drop(reply.send(Err(EndpointError::Configuration(error)))),
                }
            }
            Command::Remove { peer, reply } => {
                drop(reply.send(self.remove(peer).map_err(EndpointError::Configuration)));
            }
            Command::Keepalive {
                peer,
                interval,
                reply,
            } => {
                let result = if self.delivery.contains_key(&peer) {
                    self.service
                        .engine_mut()
                        .set_persistent_keepalive(peer, interval);
                    Ok(())
                } else {
                    Err(EndpointError::Configuration(DeviceError::UnknownPeer))
                };
                drop(reply.send(result));
            }
            Command::Send {
                peer,
                destination,
                packet,
                reply,
            } => {
                if let Some(peer) = peer {
                    if !self.delivery.contains_key(&peer) {
                        drop(reply.send(Err(EndpointError::Closed)));
                        return Ok(());
                    }
                    if self.service.engine().device().peer_for_ip(destination) != Some(peer) {
                        drop(reply.send(Err(EndpointError::WrongPeer)));
                        return Ok(());
                    }
                }
                match self.service.send_ip_packet(&packet).await {
                    Ok(()) => drop(reply.send(Ok(()))),
                    Err(ServiceError::Engine(error)) => {
                        drop(reply.send(Err(EndpointError::Engine(error))))
                    }
                    Err(error) => return Err(DriverError::WireGuard(error)),
                }
            }
        }
        Ok(())
    }

    async fn maintain(
        &mut self,
        now: Duration,
        last_timestamp: &mut Option<Duration>,
    ) -> Result<(), DriverError> {
        for peer in self
            .service
            .tick(now)
            .await
            .map_err(DriverError::WireGuard)?
        {
            let mut timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?;
            if let Some(last) = *last_timestamp {
                timestamp = timestamp.max(last.saturating_add(Duration::from_nanos(1)));
            }
            *last_timestamp = Some(timestamp);
            self.service
                .start_handshake_auto(peer, Tai64n::from_unix_duration(timestamp), ephemeral()?)
                .await
                .map_err(DriverError::WireGuard)?;
        }
        Ok(())
    }
}
impl<C: WireGuardCrypto + Send + 'static, S: DatagramSocket + Send + 'static> EndpointDriver<C, S> {
    /// Spawns this one driver through Rama's executor; graceful cancellation stops it.
    /// Await the returned task to inspect local I/O failures (`None` means cancellation).
    pub fn spawn(
        self,
        exec: &Executor,
    ) -> tokio::task::JoinHandle<Option<Result<(), DriverError>>> {
        exec.spawn_cancellable_task(self.run())
    }
}

pub(super) enum Command {
    Add {
        config: PeerConfig,
        queue: PacketQueue,
        life: Arc<PeerRegistration>,
        reply: oneshot::Sender<Result<PeerId, EndpointError>>,
    },
    Remove {
        peer: PeerId,
        reply: oneshot::Sender<Result<(), EndpointError>>,
    },
    Keepalive {
        peer: PeerId,
        interval: Option<Duration>,
        reply: oneshot::Sender<Result<(), EndpointError>>,
    },
    Send {
        peer: Option<PeerId>,
        destination: core::net::IpAddr,
        packet: Vec<u8>,
        reply: oneshot::Sender<Result<(), EndpointError>>,
    },
}
pub(super) async fn register(
    commands: &mpsc::Sender<Command>,
    config: PeerConfig,
    queue: PacketQueue,
    life: Arc<PeerRegistration>,
) -> Result<PeerId, EndpointError> {
    let (reply, result) = oneshot::channel();
    commands
        .send(Command::Add {
            config,
            queue,
            life,
            reply,
        })
        .await
        .map_err(|_closed| EndpointError::Closed)?;
    result.await.map_err(|_closed| EndpointError::Closed)?
}
pub(super) async fn keepalive(
    commands: &mpsc::Sender<Command>,
    peer: PeerId,
    interval: Option<Duration>,
) -> Result<(), EndpointError> {
    let (reply, result) = oneshot::channel();
    commands
        .send(Command::Keepalive {
            peer,
            interval,
            reply,
        })
        .await
        .map_err(|_closed| EndpointError::Closed)?;
    result.await.map_err(|_closed| EndpointError::Closed)?
}
pub(super) async fn send(
    commands: &mpsc::Sender<Command>,
    peer: Option<PeerId>,
    packet: &[u8],
) -> Result<(), EndpointError> {
    let packet = IpPacket::parse(packet)
        .map_err(|error| EndpointError::Engine(crate::EngineError::Ip(error)))?;
    if packet.as_bytes().len() > 65_472 {
        return Err(EndpointError::PacketTooLarge);
    }
    let permit = commands
        .reserve()
        .await
        .map_err(|_closed| EndpointError::Closed)?;
    let (reply, result) = oneshot::channel();
    permit.send(Command::Send {
        peer,
        destination: packet.destination(),
        packet: packet.as_bytes().to_vec(),
        reply,
    });
    result.await.map_err(|_closed| EndpointError::Closed)?
}
fn ephemeral() -> io::Result<EphemeralPrivateKey> {
    let mut bytes = [0; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(io::Error::other)?;
    Ok(EphemeralPrivateKey::from_bytes(bytes))
}
