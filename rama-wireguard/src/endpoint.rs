//! One socket driver with dynamically registered packet or handle-owned peers.
use crate::{
    BuiltinCrypto, Device, DeviceError, PeerConfig, PeerId, PublicKey, ServiceError,
    StaticPrivateKey, TunnelPacket, WireGuardCrypto, WireGuardEngine, WireGuardService,
};
use ahash::{HashMap, HashMapExt as _};
use rama_net::address::SocketAddress;
use rama_udp::DatagramSocket;
use std::{
    io,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};

mod driver;
pub use driver::EndpointDriver;
use driver::{Command, keepalive, register, send};

#[cfg(all(test, feature = "test-utils"))]
mod tests;

/// Queue bounds. Receive overflow drops the newest packet.
#[derive(Clone, Copy, Debug)]
pub struct EndpointConfig {
    /// Shared bound for pending send, registration and configuration commands.
    pub command_capacity: NonZeroUsize,
    /// Per-peer receive bound in peer-handle mode.
    pub peer_receive_capacity: NonZeroUsize,
    /// Shared receive bound in direct packet mode.
    pub packet_receive_capacity: NonZeroUsize,
}
impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            command_capacity: const { NonZeroUsize::new(64).unwrap() },
            peer_receive_capacity: const { NonZeroUsize::new(64).unwrap() },
            packet_receive_capacity: const { NonZeroUsize::new(64).unwrap() },
        }
    }
}

#[derive(Default)]
struct PeerChanges {
    dirty: AtomicBool,
    notify: Notify,
}
struct PeerRegistration {
    active: AtomicBool,
    wake: Arc<PeerChanges>,
}
struct RegistrationGuard {
    life: Arc<PeerRegistration>,
    remove_on_drop: bool,
}
// The driver retains the registration state, but never its guard. Cancellation
// or the last Peer handle dropping can therefore deactivate it independently.
impl RegistrationGuard {
    /// Packet-mode registrations survive their temporary registration guard.
    fn persist(mut self) {
        self.remove_on_drop = false;
    }
}
impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        if self.remove_on_drop {
            self.life.active.store(false, Ordering::Release);
            self.life.wake.dirty.store(true, Ordering::Release);
            self.life.wake.notify.notify_one();
        }
    }
}
struct PeerInner {
    id: PeerId,
    commands: mpsc::Sender<Command>,
    received: Mutex<mpsc::Receiver<TunnelPacket>>,
    dropped: Arc<AtomicU64>,
    _shutdown: watch::Sender<bool>,
    _lease: RegistrationGuard,
}

/// A configured peer owned by its handles. Dropping the last clone unregisters it.
/// Clones share a receive queue. Peer identifiers are deliberately not exposed.
#[derive(Clone)]
pub struct Peer(Arc<PeerInner>);

/// An authenticated IP packet received through a known peer handle.
#[derive(Debug)]
pub struct PeerPacket {
    pub source: SocketAddress,
    pub payload: Vec<u8>,
}
impl Peer {
    /// Number of packets dropped because this peer's receive queue was full.
    #[must_use]
    pub fn dropped_packets(&self) -> u64 {
        self.0.dropped.load(Ordering::Relaxed)
    }
    /// Waits for driver acceptance, not remote delivery. During a handshake only the
    /// latest queued IP packet is retained. The destination must belong to this peer.
    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<(), PeerError> {
        send(&self.0.commands, Some(self.0.id), packet)
            .await
            .map_err(PeerError::from)
    }
    /// Configures periodic keepalives; `None` or zero disables them.
    pub async fn set_persistent_keepalive(
        &self,
        interval: Option<Duration>,
    ) -> Result<(), PeerError> {
        keepalive(&self.0.commands, self.0.id, interval)
            .await
            .map_err(PeerError::from)
    }
    /// Cancellation-safe. Drains queued packets after driver shutdown, then returns `None`.
    pub async fn recv(&self) -> Option<PeerPacket> {
        self.0
            .received
            .lock()
            .await
            .recv()
            .await
            .map(|packet| PeerPacket {
                source: packet.source,
                payload: packet.payload,
            })
    }
}

/// Direct packet receive state, with one sender shared by all registered peers.
#[derive(Clone)]
pub struct PacketMode {
    received: Arc<Mutex<mpsc::Receiver<TunnelPacket>>>,
    queue: PacketQueue,
}
/// Peer-handle receive state, with an independent queue for each registration.
#[derive(Clone)]
pub struct PeerMode {
    capacity: NonZeroUsize,
}

/// Sealed receive modes: direct packets or lifetime-owned peer handles.
/// ```compile_fail
/// #[derive(Clone)]
/// struct CustomMode;
/// impl rama_wireguard::ReceiveMode for CustomMode {}
/// ```
pub trait ReceiveMode: private::Sealed + Clone {}
impl ReceiveMode for PacketMode {}
impl ReceiveMode for PeerMode {}
mod private {
    pub trait Sealed {}
    impl Sealed for super::PacketMode {}
    impl Sealed for super::PeerMode {}
}

/// A cloneable endpoint whose mode determines receive ownership.
/// Construction starts without peers; register them after starting its socket driver.
#[derive(Clone)]
pub struct Endpoint<M: ReceiveMode> {
    commands: mpsc::Sender<Command>,
    mode: M,
    shutdown: watch::Sender<bool>,
    public_key: PublicKey,
    wake: Arc<PeerChanges>,
}

/// Direct packet I/O with explicit peer registration and removal by identifier.
/// ```compile_fail
/// fn cannot_get_handle(endpoint: rama_wireguard::PacketEndpoint, id: rama_wireguard::PeerId) {
///     endpoint.peer(id);
/// }
/// ```
pub type PacketEndpoint = Endpoint<PacketMode>;
/// Handle-owned peers, without identifier-based APIs or a direct packet receiver.
/// ```compile_fail
/// fn cannot_receive(endpoint: rama_wireguard::PeerEndpoint) { endpoint.recv(); }
/// ```
/// ```compile_fail
/// fn cannot_remove(endpoint: rama_wireguard::PeerEndpoint, id: rama_wireguard::PeerId) {
///     endpoint.remove_peer(id);
/// }
/// ```
/// ```compile_fail
/// fn cannot_get_id(peer: rama_wireguard::Peer) { peer.id(); }
/// ```
/// ```compile_fail
/// fn cannot_get_packet_id(packet: rama_wireguard::PeerPacket) { packet.peer; }
/// ```
/// ```compile_fail
/// use rama_wireguard::{BuiltinCrypto, EndpointConfig, PeerEndpoint, WireGuardEngine};
/// fn cannot_preconfigure(engine: WireGuardEngine<BuiltinCrypto>, socket: rama_udp::UdpPacketSocket) {
///     PeerEndpoint::new(engine, socket, EndpointConfig::default());
/// }
/// ```
pub type PeerEndpoint = Endpoint<PeerMode>;

impl Endpoint<PacketMode> {
    /// Starts with no peers. Only an identity and socket can be supplied.
    pub fn new<S: DatagramSocket>(
        key: StaticPrivateKey,
        socket: S,
        config: EndpointConfig,
    ) -> (Self, EndpointDriver<BuiltinCrypto, S>) {
        Self::new_with_crypto::<BuiltinCrypto, S>(key, socket, config)
    }
    /// Starts an empty packet endpoint using a caller-selected cryptographic provider.
    pub fn new_with_crypto<C: WireGuardCrypto, S: DatagramSocket>(
        key: StaticPrivateKey,
        socket: S,
        config: EndpointConfig,
    ) -> (Self, EndpointDriver<C, S>) {
        let (queue, received) = PacketQueue::new(config.packet_receive_capacity);
        let mode = PacketMode {
            received: Arc::new(Mutex::new(received)),
            queue,
        };
        Self::create(key, socket, config, mode)
    }
    /// Registers a peer while the driver is running. Cancellation rolls registration back.
    pub async fn add_peer(&self, config: PeerConfig) -> Result<PeerId, EndpointError> {
        let lease = self.lease();
        let id = register(
            &self.commands,
            config,
            self.mode.queue.clone(),
            lease.life.clone(),
        )
        .await?;
        lease.persist();
        Ok(id)
    }
    /// Removes configuration, routes, handshakes, keys, timers and queued outgoing data.
    /// Already delivered incoming packets may still be drained from the shared queue.
    pub async fn remove_peer(&self, peer: PeerId) -> Result<(), EndpointError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Remove { peer, reply })
            .await
            .map_err(|_closed| EndpointError::Closed)?;
        result.await.map_err(|_closed| EndpointError::Closed)?
    }
    /// Configures periodic keepalives for a registered peer; `None` or zero disables them.
    pub async fn set_persistent_keepalive(
        &self,
        peer: PeerId,
        interval: Option<Duration>,
    ) -> Result<(), EndpointError> {
        keepalive(&self.commands, peer, interval).await
    }
    /// Routes by destination IP and waits for driver acceptance, not remote delivery.
    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<(), EndpointError> {
        send(&self.commands, None, packet).await
    }
    /// Receives packets with their peer IDs. Cancellation does not consume a packet.
    pub async fn recv(&self) -> Option<TunnelPacket> {
        let mut received = self.mode.received.lock().await;
        // This endpoint retains a sender for future registrations. Driver shutdown,
        // rather than channel closure, therefore terminates an empty receive stream.
        tokio::select! {
            biased;
            packet = received.recv() => packet,
            _ = self.commands.closed() => received.try_recv().ok(),
        }
    }
    /// Number of packets dropped because the shared receive queue was full.
    #[must_use]
    pub fn dropped_packets(&self) -> u64 {
        self.mode.queue.dropped.load(Ordering::Relaxed)
    }
}
impl Endpoint<PeerMode> {
    /// Starts with no peers; each subsequent registration returns its owning handle.
    pub fn new<S: DatagramSocket>(
        key: StaticPrivateKey,
        socket: S,
        config: EndpointConfig,
    ) -> (Self, EndpointDriver<BuiltinCrypto, S>) {
        Self::new_with_crypto::<BuiltinCrypto, S>(key, socket, config)
    }
    /// Starts an empty peer endpoint using a caller-selected cryptographic provider.
    pub fn new_with_crypto<C: WireGuardCrypto, S: DatagramSocket>(
        key: StaticPrivateKey,
        socket: S,
        config: EndpointConfig,
    ) -> (Self, EndpointDriver<C, S>) {
        Self::create(
            key,
            socket,
            config,
            PeerMode {
                capacity: config.peer_receive_capacity,
            },
        )
    }
    /// Registers a peer, removed when its last handle is dropped. Cancellation rolls back.
    pub async fn add_peer(&self, config: PeerConfig) -> Result<Peer, PeerError> {
        let lease = self.lease();
        let (queue, received) = PacketQueue::new(self.mode.capacity);
        let dropped = queue.dropped.clone();
        let id = register(&self.commands, config, queue, lease.life.clone())
            .await
            .map_err(PeerError::from)?;
        Ok(Peer(Arc::new(PeerInner {
            id,
            commands: self.commands.clone(),
            received: Mutex::new(received),
            dropped,
            _shutdown: self.shutdown.clone(),
            _lease: lease,
        })))
    }
}
impl<M: ReceiveMode> Endpoint<M> {
    fn create<C: WireGuardCrypto, S: DatagramSocket>(
        key: StaticPrivateKey,
        socket: S,
        config: EndpointConfig,
        mode: M,
    ) -> (Self, EndpointDriver<C, S>) {
        let engine = WireGuardEngine::new(Device::<C>::new(key));
        let public_key = engine.device().public_key();
        let (commands, receiver) = mpsc::channel(config.command_capacity.get());
        let (shutdown, stop) = watch::channel(false);
        let wake = Arc::new(PeerChanges::default());
        (
            Self {
                commands,
                mode,
                shutdown,
                public_key,
                wake: wake.clone(),
            },
            EndpointDriver {
                admission: crate::admission::HandshakeAdmission::new::<C>(
                    public_key,
                    crate::HandshakeAdmissionConfig::default(),
                ),
                service: WireGuardService::new(engine, socket),
                commands: receiver,
                delivery: HashMap::new(),
                wake,
                stop,
            },
        )
    }
    fn lease(&self) -> RegistrationGuard {
        RegistrationGuard {
            life: Arc::new(PeerRegistration {
                active: AtomicBool::new(true),
                wake: self.wake.clone(),
            }),
            remove_on_drop: true,
        }
    }
    /// Returns the immutable local public key for configuring remote peers.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.public_key
    }
    /// Requests shutdown without waiting for command queue capacity.
    pub fn close(&self) {
        self.shutdown.send_replace(true);
    }
    /// Waits until the driver has stopped accepting commands.
    pub async fn closed(&self) {
        self.commands.closed().await;
    }
}

#[derive(Clone)]
struct PacketQueue {
    sender: mpsc::Sender<TunnelPacket>,
    dropped: Arc<AtomicU64>,
}
impl PacketQueue {
    fn new(capacity: NonZeroUsize) -> (Self, mpsc::Receiver<TunnelPacket>) {
        let (sender, receiver) = mpsc::channel(capacity.get());
        (
            Self {
                sender,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        )
    }
    fn deliver(&self, packet: TunnelPacket) {
        if matches!(
            self.sender.try_send(packet),
            Err(mpsc::error::TrySendError::Full(_))
        ) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// Failure to submit an IP packet to the endpoint.
#[derive(Debug)]
pub enum EndpointError {
    Configuration(DeviceError),
    Closed,
    WrongPeer,
    PacketTooLarge,
    Engine(crate::EngineError),
}
impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "WireGuard peer configuration failed: {error}"),
            Self::Closed => f.write_str("WireGuard endpoint is closed"),
            Self::WrongPeer => f.write_str("packet destination does not belong to this peer"),
            Self::PacketTooLarge => f.write_str("IP packet exceeds the WireGuard transport limit"),
            Self::Engine(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for EndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Engine(error) => Some(error),
            _ => None,
        }
    }
}

/// A local error that stopped the socket driver.
#[derive(Debug)]
pub enum DriverError {
    WireGuard(ServiceError),
    Io(io::Error),
}
impl From<io::Error> for DriverError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireGuard(error) => error.fmt(f),
            Self::Io(error) => write!(f, "WireGuard driver I/O failed: {error}"),
        }
    }
}
impl std::error::Error for DriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WireGuard(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

/// Peer-handle errors deliberately contain no peer identifiers.
#[derive(Debug)]
pub enum PeerError {
    Closed,
    WrongPeer,
    PacketTooLarge,
    DuplicatePublicKey,
    PeerLimitReached,
    InvalidPacket(rama_net::ip::IpPacketError),
    Crypto(crate::CryptoError),
    Protocol,
}
impl From<EndpointError> for PeerError {
    fn from(error: EndpointError) -> Self {
        match error {
            EndpointError::Closed | EndpointError::Configuration(DeviceError::UnknownPeer) => {
                Self::Closed
            }
            EndpointError::WrongPeer => Self::WrongPeer,
            EndpointError::PacketTooLarge => Self::PacketTooLarge,
            EndpointError::Configuration(DeviceError::DuplicatePeer) => Self::DuplicatePublicKey,
            EndpointError::Configuration(DeviceError::PeerSpaceExhausted) => Self::PeerLimitReached,
            EndpointError::Engine(crate::EngineError::Ip(error)) => Self::InvalidPacket(error),
            EndpointError::Configuration(DeviceError::Crypto(error))
            | EndpointError::Engine(crate::EngineError::Device(DeviceError::Crypto(error))) => {
                Self::Crypto(error)
            }
            EndpointError::Configuration(_) | EndpointError::Engine(_) => Self::Protocol,
        }
    }
}
impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("WireGuard peer is closed"),
            Self::WrongPeer => f.write_str("packet destination does not belong to this peer"),
            Self::PacketTooLarge => f.write_str("IP packet exceeds the WireGuard transport limit"),
            Self::DuplicatePublicKey => f.write_str("peer public key is already registered"),
            Self::PeerLimitReached => f.write_str("peer identifier space exhausted"),
            Self::InvalidPacket(error) => write!(f, "invalid IP packet: {error}"),
            Self::Crypto(error) => error.fmt(f),
            Self::Protocol => f.write_str("WireGuard peer protocol operation failed"),
        }
    }
}
impl std::error::Error for PeerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPacket(error) => Some(error),
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}
