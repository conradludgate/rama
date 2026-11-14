//! A small userspace IPv4/TCP network carried by a Rama WireGuard endpoint.
//!
//! The smoltcp device exchanges layer-3 IP packets, so neither TUN nor kernel
//! routes are involved. The WireGuard socket driver runs independently.

use ahash::{HashMap, HashMapExt as _};
use parking_lot::{Mutex, MutexGuard};
use rama_wireguard::{EndpointError, PacketEndpoint};
use smoltcp::iface::SocketHandle;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

const MTU: usize = 1420;
const QUEUE_CAPACITY: usize = 64;
const TCP_BUFFER: usize = 16 * 1024;
const LISTEN_BACKLOG: usize = 4;

#[derive(Default)]
struct PacketDevice {
    received: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}
struct ReceiveToken(Vec<u8>);
struct TransmitToken<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for ReceiveToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl TxToken for TransmitToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = ReceiveToken;
    type TxToken<'a> = TransmitToken<'a>;
    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outgoing.len() >= QUEUE_CAPACITY {
            return None;
        }
        Some((
            ReceiveToken(self.received.pop_front()?),
            TransmitToken(&mut self.outgoing),
        ))
    }
    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        (self.outgoing.len() < QUEUE_CAPACITY).then_some(TransmitToken(&mut self.outgoing))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities.max_burst_size = Some(QUEUE_CAPACITY);
        capabilities
    }
}

/// A virtual IPv4 host. Run its driver alongside application tasks.
#[derive(Clone)]
pub struct VirtualNetwork {
    shared: Arc<Shared>,
}
struct Shared {
    state: Mutex<State>,
    changed: Notify,
}
struct State {
    device: PacketDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    entries: HashMap<SocketHandle, Entry>,
    next_port: u16,
    stopped: bool,
}
#[derive(Default)]
struct Entry {
    reader: Option<Waker>,
    writer: Option<Waker>,
    detached: bool,
    received_fin: bool,
}
impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock()
    }
}
impl State {
    fn add_tcp(&mut self) -> SocketHandle {
        let handle = self.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        ));
        self.entries.insert(handle, Entry::default());
        handle
    }
    fn wake(&mut self) {
        for entry in self.entries.values_mut() {
            if let Some(waker) = entry.reader.take() {
                waker.wake();
            }
            if let Some(waker) = entry.writer.take() {
                waker.wake();
            }
        }
    }
    fn check_running(&self) -> io::Result<()> {
        if self.stopped {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "virtual network driver stopped",
            ))
        } else {
            Ok(())
        }
    }
}
/// Drives one smoltcp interface, including retransmission and connection teardown.
/// Dropping this driver wakes pending I/O with an error.
#[must_use = "run the network driver alongside application tasks"]
pub struct NetworkDriver {
    shared: Arc<Shared>,
    endpoint: PacketEndpoint,
    epoch: tokio::time::Instant,
}
#[expect(
    clippy::expect_used,
    reason = "live handles own registered sockets; fresh sockets accept nonzero ports"
)]
impl VirtualNetwork {
    /// Assigns a virtual /24 address. The seed randomizes TCP sequence numbers.
    #[expect(
        clippy::unwrap_used,
        reason = "a fresh interface has capacity for one address"
    )]
    pub fn new(endpoint: PacketEndpoint, address: Ipv4Addr, seed: u64) -> (Self, NetworkDriver) {
        let mut device = PacketDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(address), 24))
                .unwrap();
        });
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                device,
                iface,
                sockets: SocketSet::new(vec![]),
                entries: HashMap::new(),
                next_port: 49152,
                stopped: false,
            }),
            changed: Notify::new(),
        });
        (
            Self {
                shared: shared.clone(),
            },
            NetworkDriver {
                shared,
                endpoint,
                epoch: tokio::time::Instant::now(),
            },
        )
    }
    /// Listens on this host's virtual address. Each accept installs a fresh listening socket.
    pub fn listen(&self, port: u16) -> io::Result<TcpListener> {
        let mut state = self.shared.lock();
        state.check_running()?;
        if port == 0 || state.sockets.iter().any(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(s) if s.listen_endpoint().port == port || s.local_endpoint().is_some_and(|e| e.port == port))) {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "virtual TCP port unavailable"));
        }
        let handles = (0..LISTEN_BACKLOG)
            .map(|_| {
                let handle = state.add_tcp();
                state
                    .sockets
                    .get_mut::<tcp::Socket>(handle)
                    .listen(port)
                    .expect("nonzero port on a fresh socket");
                handle
            })
            .collect();
        Ok(TcpListener {
            shared: self.shared.clone(),
            handles,
            port,
        })
    }
    /// Connects from an automatically allocated virtual ephemeral port.
    pub async fn connect(&self, remote: SocketAddrV4) -> io::Result<TcpStream> {
        let stream = {
            let mut state = self.shared.lock();
            state.check_running()?;
            let port = (0..16384).find_map(|_| {
                let port = state.next_port;
                state.next_port = if port == u16::MAX { 49152 } else { port + 1 };
                (!state.sockets.iter().any(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(s) if s.local_endpoint().is_some_and(|e| e.port == port) || s.listen_endpoint().port == port))).then_some(port)
            }).ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no virtual ephemeral ports"))?;
            let handle = state.add_tcp();
            let State { iface, sockets, .. } = &mut *state;
            if let Err(error) = sockets.get_mut::<tcp::Socket>(handle).connect(
                iface.context(),
                (*remote.ip(), remote.port()),
                port,
            ) {
                state.sockets.remove(handle);
                state.entries.remove(&handle);
                return Err(io::Error::other(error));
            }
            TcpStream {
                shared: self.shared.clone(),
                handle,
                write_shutdown: false,
            }
        };
        self.shared.changed.notify_one();
        poll_fn(|cx| {
            let mut state = self.shared.lock();
            state.check_running()?;
            let socket = state.sockets.get::<tcp::Socket>(stream.handle);
            if socket.may_send() {
                return Poll::Ready(Ok(()));
            }
            if !socket.is_open() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "virtual TCP connection refused",
                )));
            }
            state
                .entries
                .get_mut(&stream.handle)
                .expect("registered stream")
                .writer = Some(cx.waker().clone());
            Poll::Pending
        })
        .await?;
        Ok(stream)
    }
}
impl NetworkDriver {
    /// Runs until the WireGuard endpoint closes or an outgoing packet fails.
    pub async fn run(self) -> io::Result<()> {
        loop {
            let (packets, delay) = {
                let mut state = self.shared.lock();
                let now = Instant::from_millis(
                    i64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(i64::MAX),
                );
                let State {
                    iface,
                    device,
                    sockets,
                    ..
                } = &mut *state;
                iface.poll(now, device, sockets);
                let delay = iface
                    .poll_delay(now, sockets)
                    .map_or(Duration::from_secs(3600), |d| {
                        Duration::from_millis(d.total_millis())
                    });
                let retired: Vec<_> = state
                    .entries
                    .iter()
                    .filter_map(|(&handle, entry)| {
                        (entry.detached && !state.sockets.get::<tcp::Socket>(handle).is_open())
                            .then_some(handle)
                    })
                    .collect();
                for handle in retired {
                    state.sockets.remove(handle);
                    state.entries.remove(&handle);
                }
                let State {
                    entries, sockets, ..
                } = &mut *state;
                for (&handle, entry) in entries.iter_mut() {
                    entry.received_fin |= matches!(
                        sockets.get::<tcp::Socket>(handle).state(),
                        tcp::State::CloseWait
                            | tcp::State::LastAck
                            | tcp::State::Closing
                            | tcp::State::TimeWait
                    );
                }
                state.wake();
                (state.device.outgoing.drain(..).collect::<Vec<_>>(), delay)
            };
            for packet in packets {
                match self.endpoint.send_ip_packet(&packet).await {
                    Ok(()) => {}
                    Err(EndpointError::Closed) => return Ok(()),
                    Err(error) => return Err(io::Error::other(error)),
                }
            }
            tokio::select! {
                packet = self.endpoint.recv() => {
                    let Some(packet) = packet else { return Ok(()); };
                    let mut state = self.shared.lock();
                    if packet.payload.len() <= MTU && state.device.received.len() < QUEUE_CAPACITY { state.device.received.push_back(packet.payload); }
                }
                _ = self.shared.changed.notified() => {},
                _ = tokio::time::sleep(delay) => {},
            }
        }
    }
}
impl Drop for NetworkDriver {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.stopped = true;
        state.wake();
    }
}
/// A listener for virtual TCP connections, independent of OS TCP sockets.
pub struct TcpListener {
    shared: Arc<Shared>,
    handles: Vec<SocketHandle>,
    port: u16,
}
#[expect(
    clippy::expect_used,
    reason = "live handles own registered sockets; fresh sockets accept nonzero ports"
)]
impl TcpListener {
    /// Accepts one connection and immediately rearms the listener for the next.
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddrV4)> {
        poll_fn(|cx| {
            let mut state = self.shared.lock();
            state.check_running()?;
            for slot in &mut self.handles {
                let socket = state.sockets.get::<tcp::Socket>(*slot);
                if matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    let remote = socket
                        .remote_endpoint()
                        .expect("connected socket has a remote address");
                    let IpAddress::Ipv4(address) = remote.addr;
                    let next = state.add_tcp();
                    state
                        .sockets
                        .get_mut::<tcp::Socket>(next)
                        .listen(self.port)
                        .expect("nonzero port on a fresh socket");
                    let handle = std::mem::replace(slot, next);
                    return Poll::Ready(Ok((
                        TcpStream {
                            shared: self.shared.clone(),
                            handle,
                            write_shutdown: false,
                        },
                        SocketAddrV4::new(address, remote.port),
                    )));
                }
                if !socket.is_open() {
                    state
                        .sockets
                        .get_mut::<tcp::Socket>(*slot)
                        .listen(self.port)
                        .expect("nonzero port on a closed socket");
                }
                state
                    .entries
                    .get_mut(slot)
                    .expect("registered listener")
                    .reader = Some(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }
}
#[expect(
    clippy::expect_used,
    reason = "live handles own registered sockets; fresh sockets accept nonzero ports"
)]
impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        for handle in &self.handles {
            state.sockets.get_mut::<tcp::Socket>(*handle).abort();
            state
                .entries
                .get_mut(handle)
                .expect("registered listener")
                .detached = true;
        }
        self.shared.changed.notify_one();
    }
}
/// A virtual TCP byte stream implementing Tokio's standard I/O traits.
/// Drop closes the send half; the network driver finishes teardown in the background.
pub struct TcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
    write_shutdown: bool,
}
#[expect(
    clippy::expect_used,
    reason = "live handles own registered sockets; fresh sockets accept nonzero ports"
)]
impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.shared.lock();
        state.check_running()?;
        let socket = state.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_recv() {
            let n = socket
                .recv_slice(buffer.initialize_unfilled())
                .map_err(io::Error::other)?;
            buffer.advance(n);
            self.shared.changed.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !socket.may_recv() {
            return Poll::Ready(
                if socket.state() == tcp::State::Closed
                    && !state
                        .entries
                        .get(&self.handle)
                        .expect("registered stream")
                        .received_fin
                {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "virtual TCP connection reset",
                    ))
                } else {
                    Ok(())
                },
            );
        }
        state
            .entries
            .get_mut(&self.handle)
            .expect("registered stream")
            .reader = Some(cx.waker().clone());
        Poll::Pending
    }
}
#[expect(
    clippy::expect_used,
    reason = "live handles own registered sockets; fresh sockets accept nonzero ports"
)]
impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.shared.lock();
        state.check_running()?;
        let socket = state.sockets.get_mut::<tcp::Socket>(self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "virtual TCP send half closed",
            )));
        }
        if socket.can_send() {
            let n = socket.send_slice(bytes).map_err(io::Error::other)?;
            self.shared.changed.notify_one();
            return Poll::Ready(Ok(n));
        }
        state
            .entries
            .get_mut(&self.handle)
            .expect("registered stream")
            .writer = Some(cx.waker().clone());
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_shutdown {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.shared.lock();
        state.check_running()?;
        let socket = state.sockets.get::<tcp::Socket>(self.handle);
        if socket.state() == tcp::State::Closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "virtual TCP connection reset",
            )));
        }
        if socket.send_queue() == 0 {
            return Poll::Ready(Ok(()));
        }
        state
            .entries
            .get_mut(&self.handle)
            .expect("registered stream")
            .writer = Some(cx.waker().clone());
        Poll::Pending
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_shutdown {
            return Poll::Ready(Ok(()));
        }
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        {
            let mut state = self.shared.lock();
            state.sockets.get_mut::<tcp::Socket>(self.handle).close();
            self.shared.changed.notify_one();
        }
        self.write_shutdown = true;
        Poll::Ready(Ok(()))
    }
}
#[expect(
    clippy::expect_used,
    reason = "live handles own registered sockets; fresh sockets accept nonzero ports"
)]
impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.sockets.get_mut::<tcp::Socket>(self.handle).close();
        state
            .entries
            .get_mut(&self.handle)
            .expect("registered stream")
            .detached = true;
        self.shared.changed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    mod faults;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn echo(mut stream: TcpStream) -> io::Result<()> {
        let (mut read, mut write) = tokio::io::split(&mut stream);
        tokio::io::copy(&mut read, &mut write).await?;
        write.shutdown().await
    }
    async fn verify(stream: TcpStream, message: &[u8]) -> io::Result<()> {
        let (mut read, mut write) = tokio::io::split(stream);
        let (_, received) = tokio::try_join!(
            async {
                write.write_all(message).await?;
                write.shutdown().await?;
                write.shutdown().await
            },
            async {
                let mut bytes = Vec::new();
                read.read_to_end(&mut bytes).await?;
                assert_eq!(read.read(&mut [0; 1]).await?, 0);
                io::Result::Ok(bytes)
            }
        )?;
        assert_eq!(received, message);
        Ok(())
    }
    use rama_core::rt::Executor;
    use rama_net::address::SocketAddress;
    use rama_udp::test_utils::MemoryDatagramSocket;
    use rama_wireguard::{EndpointConfig, PeerConfig, StaticPrivateKey};
    use std::num::NonZeroUsize;

    #[tokio::test]
    async fn dropping_driver_wakes_pending_accept_and_connect() {
        use std::future::Future as _;
        let (socket, _remote) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(46100),
            SocketAddress::local_ipv4(46101),
            NonZeroUsize::new(16).unwrap(),
        );
        let (endpoint, _wireguard_driver) = PacketEndpoint::new(
            StaticPrivateKey::from_bytes([74; 32]),
            socket,
            EndpointConfig::default(),
        );
        let (network, driver) = VirtualNetwork::new(endpoint, Ipv4Addr::new(10, 77, 0, 1), 103);
        let mut listener = network.listen(7000).unwrap();
        assert_eq!(
            network.listen(7000).err().unwrap().kind(),
            io::ErrorKind::AddrInUse
        );
        let mut accept = std::pin::pin!(listener.accept());
        let mut connect =
            std::pin::pin!(network.connect(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 7000)));
        poll_fn(|cx| {
            assert!(accept.as_mut().poll(cx).is_pending());
            assert!(connect.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(driver);
        assert_eq!(
            accept.await.err().unwrap().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            connect.await.err().unwrap().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test(start_paused = true)]
    async fn virtual_tcp_recovers_handshake_and_data_loss_with_partial_io() {
        let a_addr = SocketAddress::local_ipv4(46000);
        let b_addr = SocketAddress::local_ipv4(46001);
        let (a_socket, b_socket, a_faults, b_faults, relays) = faults::pair(a_addr, b_addr);
        // The initial WireGuard initiation is lost; its driver must retry.
        a_faults.drop_next(1);
        let (a, ad) = PacketEndpoint::new(
            StaticPrivateKey::from_bytes([71; 32]),
            a_socket,
            EndpointConfig::default(),
        );
        let (b, bd) = PacketEndpoint::new(
            StaticPrivateKey::from_bytes([72; 32]),
            b_socket,
            EndpointConfig::default(),
        );
        let at = ad.spawn(&Executor::new());
        let bt = bd.spawn(&Executor::new());
        b.add_peer(PeerConfig {
            public_key: a.public_key(),
            preshared_key: Some([73; 32]),
            endpoint: None,
            allowed_ips: vec!["10.77.0.1/32".parse().unwrap()],
        })
        .await
        .unwrap();
        a.add_peer(PeerConfig {
            public_key: b.public_key(),
            preshared_key: Some([73; 32]),
            endpoint: Some(b_addr),
            allowed_ips: vec!["10.77.0.2/32".parse().unwrap()],
        })
        .await
        .unwrap();
        let (client, client_driver) =
            VirtualNetwork::new(a.clone(), Ipv4Addr::new(10, 77, 0, 1), 101);
        let (server, server_driver) =
            VirtualNetwork::new(b.clone(), Ipv4Addr::new(10, 77, 0, 2), 102);
        let ct = tokio::spawn(client_driver.run());
        let st = tokio::spawn(server_driver.run());
        let mut listener = server.listen(7000).unwrap();
        let message: Vec<u8> = (0..192 * 1024).map(|index| (index % 251) as u8).collect();
        let result = tokio::time::timeout(Duration::from_secs(120), async {
            tokio::try_join!(
                async {
                    // Repeated accepts, including a simultaneous pair of connections.
                    for _ in 0..2 {
                        let ((first, _), (second, _)) = {
                            let first = listener.accept().await?;
                            let second = listener.accept().await?;
                            (first, second)
                        };
                        tokio::try_join!(echo(first), echo(second))?;
                    }
                    io::Result::Ok(())
                },
                async {
                    for round in 0..2 {
                        let (first, second) = tokio::try_join!(
                            client.connect(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 7000)),
                            client.connect(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 7000))
                        )?;
                        if round == 0 {
                            a_faults.drop_next(1);
                            a_faults.duplicate_next(3);
                            b_faults.drop_next(1);
                        }
                        tokio::try_join!(verify(first, &message), verify(second, &message))?;
                    }
                    io::Result::Ok(())
                }
            )
        })
        .await;
        result.unwrap().unwrap();
        a.close();
        b.close();
        at.await.unwrap().unwrap().unwrap();
        bt.await.unwrap().unwrap().unwrap();
        ct.await.unwrap().unwrap();
        st.await.unwrap().unwrap();
        assert_eq!(a_faults.stats().dropped, 2);
        assert_eq!(b_faults.stats().dropped, 1);
        assert!(a_faults.stats().duplicated > 0);
        relays.stop().await;
    }
}
