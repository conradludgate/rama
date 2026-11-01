//! Rama UDP and service adapters for the WireGuard engine.

use crate::{
    WireGuardCrypto,
    crypto::EphemeralPrivateKey,
    device::PeerId,
    proto::{Cookie, Tai64n},
    transport::DatagramTransport,
};
use rama_udp::{DatagramError, DatagramMetadata, DatagramSocket};
use std::time::Duration;

use crate::device::{
    EngineError, HandshakePolicy, TunnelPacket, WireGuardAction, WireGuardDatagram,
    WireGuardEngine, WireGuardMaintenance,
};

/// Async Rama UDP adapter for [`WireGuardEngine`].
pub struct WireGuardService<C, S: DatagramSocket> {
    engine: WireGuardEngine<C>,
    transport: DatagramTransport<S>,
}

/// A bidirectional WireGuard tunnel service.
///
/// The inner Rama service receives decrypted tunnel packets and returns zero or more packets to
/// send through WireGuard. This manually driven adapter operates on raw tunnel payloads.
/// For scheduled IP packet delivery, use the runtime endpoint API instead.
pub struct WireGuardTunnelService<C, S: DatagramSocket, H> {
    endpoint: WireGuardService<C, S>,
    handler: H,
}

impl<C, S, H> WireGuardTunnelService<C, S, H>
where
    C: WireGuardCrypto,
    S: DatagramSocket,
    H: rama_core::Service<TunnelPacket, Output = Vec<TunnelPacket>>,
{
    /// Creates a tunnel service around a WireGuard engine, UDP socket, and inner Rama service.
    #[must_use]
    pub fn new(engine: WireGuardEngine<C>, socket: S, handler: H) -> Self {
        Self {
            endpoint: WireGuardService::new(engine, socket),
            handler,
        }
    }

    /// Creates a tunnel service from an already constructed WireGuard endpoint.
    #[must_use]
    pub fn from_endpoint(endpoint: WireGuardService<C, S>, handler: H) -> Self {
        Self { endpoint, handler }
    }

    /// Returns the underlying WireGuard endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &WireGuardService<C, S> {
        &self.endpoint
    }

    /// Returns mutable access to the underlying WireGuard endpoint.
    pub fn endpoint_mut(&mut self) -> &mut WireGuardService<C, S> {
        &mut self.endpoint
    }

    /// Receives one datagram, dispatches decrypted packets to the inner service, and sends its
    /// returned packets through the corresponding WireGuard peers.
    pub async fn serve_once(
        &mut self,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
    ) -> Result<usize, TunnelServiceError<H::Error>> {
        self.serve_once_with_policy(buffer, responder_ephemeral, HandshakePolicy::Accept)
            .await
    }

    /// Variant of [`Self::serve_once`] with an explicit handshake policy.
    pub async fn serve_once_with_policy(
        &mut self,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        policy: HandshakePolicy<'_>,
    ) -> Result<usize, TunnelServiceError<H::Error>> {
        let packets = self
            .endpoint
            .recv_with_policy(buffer, responder_ephemeral, policy)
            .await
            .map_err(TunnelServiceError::WireGuard)?;
        let count = packets.len();
        for packet in packets {
            let outbound = self
                .handler
                .serve(packet)
                .await
                .map_err(TunnelServiceError::Handler)?;
            for packet in outbound {
                self.endpoint
                    .send(packet.peer, &packet.payload)
                    .await
                    .map_err(TunnelServiceError::WireGuard)?;
            }
        }
        Ok(count)
    }

    /// Receives and dispatches tunnel traffic until cancelled or an error occurs.
    /// The responder-key factory is called once per receive attempt.
    ///
    /// This is a receive-only convenience loop. Applications driving protocol maintenance
    /// should call `serve_once` from their scheduler and also drive `endpoint_mut().tick`.
    /// For a complete scheduled IP endpoint, use `EndpointDriver`
    /// with the `runtime` feature instead.
    pub async fn run_receive_loop<R>(
        &mut self,
        buffer: &mut [u8],
        mut responder_ephemeral: R,
    ) -> Result<(), TunnelServiceError<H::Error>>
    where
        R: FnMut() -> Option<EphemeralPrivateKey>,
    {
        loop {
            self.serve_once(buffer, responder_ephemeral())
                .await
                .map(|_| ())?;
        }
    }
}

impl<C: WireGuardCrypto, S: DatagramSocket> WireGuardService<C, S> {
    /// Creates a WireGuard service over a Rama datagram socket.
    #[must_use]
    pub fn new(engine: WireGuardEngine<C>, socket: S) -> Self {
        Self {
            engine,
            transport: DatagramTransport::new(socket),
        }
    }

    /// Executes protocol maintenance and returns peers needing fresh handshake inputs.
    pub async fn tick(&mut self, now: Duration) -> Result<Vec<PeerId>, ServiceError> {
        let actions = self.engine.tick(now)?;
        let mut requests = Vec::new();
        for action in actions {
            match action {
                WireGuardMaintenance::HandshakeRequired(peer) => requests.push(peer),
                WireGuardMaintenance::Send(datagram) => self.transmit(datagram).await?,
            }
        }
        Ok(requests)
    }

    /// Starts an engine-requested handshake with a fresh key and timestamp.
    pub async fn start_handshake_auto(
        &mut self,
        peer: PeerId,
        timestamp: Tai64n,
        ephemeral: EphemeralPrivateKey,
    ) -> Result<(), ServiceError> {
        let datagram = self
            .engine
            .start_handshake_auto(peer, timestamp, ephemeral)?;
        self.transmit(datagram).await
    }

    /// Routes an IP packet, queuing it in the engine if its peer needs a handshake.
    pub async fn send_ip_packet(&mut self, payload: &[u8]) -> Result<(), ServiceError> {
        if let Some(datagram) = self.engine.send_ip_packet(payload)? {
            self.transmit(datagram).await?;
        }
        Ok(())
    }

    async fn transmit(&mut self, datagram: WireGuardDatagram) -> Result<(), ServiceError> {
        self.transport
            .send_to(datagram.destination, &datagram.payload)
            .await
            .map_err(ServiceError::Datagram)
    }

    /// Returns the stateful engine.
    #[must_use]
    pub const fn engine(&self) -> &WireGuardEngine<C> {
        &self.engine
    }

    /// Returns mutable access to the stateful engine.
    pub fn engine_mut(&mut self) -> &mut WireGuardEngine<C> {
        &mut self.engine
    }

    /// Starts a handshake and writes its initiation to the UDP socket.
    pub async fn start_handshake(
        &mut self,
        peer: PeerId,
        sender: u32,
        timestamp: Tai64n,
        ephemeral: EphemeralPrivateKey,
    ) -> Result<(), ServiceError> {
        let datagram = self
            .engine
            .start_handshake(peer, sender, timestamp, ephemeral)?;
        self.transport
            .send_to(datagram.destination, &datagram.payload)
            .await
            .map_err(ServiceError::Datagram)
    }

    /// Encrypts and writes a tunnel payload to a peer's learned endpoint.
    pub async fn send(&mut self, peer: PeerId, payload: &[u8]) -> Result<(), ServiceError> {
        let datagram = self.engine.send(peer, payload)?;
        self.transport
            .send_to(datagram.destination, &datagram.payload)
            .await
            .map_err(ServiceError::Datagram)
    }

    /// Receives one UDP datagram, writes any protocol response, and returns tunnel packets.
    pub async fn recv(
        &mut self,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
    ) -> Result<Vec<TunnelPacket>, ServiceError> {
        self.recv_with_policy(buffer, responder_ephemeral, HandshakePolicy::Accept)
            .await
    }

    /// Receives routed IP traffic, validating allowed sources and trimming tunnel padding.
    pub async fn recv_ip(
        &mut self,
        buffer: &mut [u8],
        ephemeral: Option<EphemeralPrivateKey>,
    ) -> Result<Vec<TunnelPacket>, ServiceError> {
        let metadata = self
            .transport
            .recv(buffer)
            .await
            .map_err(ServiceError::Datagram)?;
        self.process_datagram(metadata, buffer, ephemeral, HandshakePolicy::Accept, true)
            .await
    }

    /// Receives one UDP datagram with an optional application-selected cookie requirement.
    pub async fn recv_with_cookie(
        &mut self,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        cookie: Option<&Cookie>,
    ) -> Result<Vec<TunnelPacket>, ServiceError> {
        let policy = cookie.map_or(HandshakePolicy::Accept, HandshakePolicy::RequireCookie);
        self.recv_with_policy(buffer, responder_ephemeral, policy)
            .await
    }

    /// Receives one UDP datagram with an explicit handshake policy.
    pub async fn recv_with_policy(
        &mut self,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        policy: HandshakePolicy<'_>,
    ) -> Result<Vec<TunnelPacket>, ServiceError> {
        let metadata = self
            .transport
            .recv(buffer)
            .await
            .map_err(ServiceError::Datagram)?;
        self.process_received_datagram(metadata, buffer, responder_ephemeral, policy)
            .await
    }

    // Receive is polled separately by the socket driver so a select! cannot
    // cancel the protocol response after consuming its triggering datagram.
    pub(crate) async fn process_received_datagram(
        &mut self,
        metadata: DatagramMetadata,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        policy: HandshakePolicy<'_>,
    ) -> Result<Vec<TunnelPacket>, ServiceError> {
        self.process_datagram(metadata, buffer, responder_ephemeral, policy, false)
            .await
    }

    #[cfg(feature = "runtime")]
    pub(crate) async fn process_received_ip_datagram(
        &mut self,
        metadata: DatagramMetadata,
        buffer: &mut [u8],
        ephemeral: Option<EphemeralPrivateKey>,
        deliver: impl FnMut(TunnelPacket),
    ) -> Result<(), ServiceError> {
        self.process_datagram_with(
            metadata,
            buffer,
            ephemeral,
            HandshakePolicy::Accept,
            true,
            deliver,
        )
        .await
    }

    async fn process_datagram(
        &mut self,
        metadata: DatagramMetadata,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        policy: HandshakePolicy<'_>,
        ip_mode: bool,
    ) -> Result<Vec<TunnelPacket>, ServiceError> {
        let mut packets = Vec::new();
        self.process_datagram_with(
            metadata,
            buffer,
            responder_ephemeral,
            policy,
            ip_mode,
            |packet| packets.push(packet),
        )
        .await?;
        Ok(packets)
    }

    async fn process_datagram_with(
        &mut self,
        metadata: DatagramMetadata,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        policy: HandshakePolicy<'_>,
        ip_mode: bool,
        mut deliver: impl FnMut(TunnelPacket),
    ) -> Result<(), ServiceError> {
        if metadata.truncated {
            return Err(ServiceError::TruncatedDatagram);
        }
        if metadata.segment_count() != 1 {
            return Err(ServiceError::CoalescedDatagram);
        }

        let actions = self.engine.receive_datagram_with_policy(
            metadata.peer,
            &mut buffer[..metadata.len],
            responder_ephemeral,
            policy,
        )?;
        for action in actions {
            match action {
                WireGuardAction::Send(datagram) => {
                    self.transport
                        .send_to(datagram.destination, &datagram.payload)
                        .await
                        .map_err(ServiceError::Datagram)?;
                }
                WireGuardAction::Receive(mut packet) => {
                    if ip_mode {
                        let Ok(payload) =
                            self.engine.validate_ip_packet(packet.peer, &packet.payload)
                        else {
                            continue;
                        };
                        packet.payload.truncate(payload.len());
                    }
                    deliver(packet);
                }
            }
        }
        Ok(())
    }

    /// Receives one datagram and serves every decrypted tunnel packet through a Rama service.
    ///
    /// This intentionally processes one receive operation at a time so the surrounding
    /// application retains control over cancellation, buffering, and responder-key policy.
    pub async fn serve_once<H>(
        &mut self,
        buffer: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        handler: &H,
    ) -> Result<usize, ServiceError>
    where
        H: rama_core::Service<TunnelPacket>,
        H::Error: Into<ServiceError>,
    {
        let packets = self.recv(buffer, responder_ephemeral).await?;
        let count = packets.len();
        for packet in packets {
            handler.serve(packet).await.map_err(|error| error.into())?;
        }
        Ok(count)
    }

    /// Returns the underlying Rama datagram transport.
    #[must_use]
    pub const fn transport(&self) -> &DatagramTransport<S> {
        &self.transport
    }

    /// Returns mutable access to the underlying Rama datagram transport.
    pub fn transport_mut(&mut self) -> &mut DatagramTransport<S> {
        &mut self.transport
    }
}

/// Errors raised by the async UDP adapter.
#[derive(Debug)]
pub enum ServiceError {
    Datagram(DatagramError),
    Engine(EngineError),
    TruncatedDatagram,
    CoalescedDatagram,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Datagram(error) => write!(f, "WireGuard datagram I/O failed: {error}"),
            Self::Engine(error) => error.fmt(f),
            Self::TruncatedDatagram => f.write_str("truncated WireGuard UDP datagram"),
            Self::CoalescedDatagram => f.write_str("WireGuard requires individual UDP datagrams"),
        }
    }
}
impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            Self::Engine(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EngineError> for ServiceError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

/// Errors produced by the bidirectional tunnel service.
#[derive(Debug)]
pub enum TunnelServiceError<E> {
    WireGuard(ServiceError),
    Handler(E),
}

impl<E: std::fmt::Display> std::fmt::Display for TunnelServiceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireGuard(error) => error.fmt(f),
            Self::Handler(error) => write!(f, "WireGuard tunnel handler failed: {error}"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for TunnelServiceError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WireGuard(error) => Some(error),
            Self::Handler(error) => Some(error),
        }
    }
}

impl<E> From<ServiceError> for TunnelServiceError<E> {
    fn from(error: ServiceError) -> Self {
        Self::WireGuard(error)
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::{
        StaticPrivateKey,
        crypto::{BuiltinCrypto, CookieState},
        device::{Device, PeerConfig},
        proto::KEY_SIZE,
    };
    use rama_net::address::SocketAddress;

    #[cfg(feature = "test-utils")]
    struct EchoTunnel;

    #[cfg(feature = "test-utils")]
    impl rama_core::Service<TunnelPacket> for EchoTunnel {
        type Output = Vec<TunnelPacket>;
        type Error = ServiceError;

        async fn serve(&self, packet: TunnelPacket) -> Result<Self::Output, Self::Error> {
            Ok(vec![packet])
        }
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn service_drives_memory_udp_and_cookie_retry() {
        use std::num::NonZeroUsize;

        use rama_udp::test_utils::MemoryDatagramSocket;

        tokio_test::block_on(async {
            let client_device =
                Device::<BuiltinCrypto>::new(StaticPrivateKey::from_bytes([11; KEY_SIZE]));
            let server_device =
                Device::<BuiltinCrypto>::new(StaticPrivateKey::from_bytes([12; KEY_SIZE]));
            let client_addr = SocketAddress::local_ipv4(42_000);
            let server_addr = SocketAddress::local_ipv4(42_001);
            let mut client_engine = WireGuardEngine::new(client_device);
            let mut server_engine = WireGuardEngine::new(server_device);
            let client_peer = client_engine
                .add_peer(&PeerConfig {
                    public_key: server_engine.device().public_key(),
                    preshared_key: Some([13; KEY_SIZE]),
                    endpoint: Some(server_addr),
                    allowed_ips: Vec::new(),
                })
                .unwrap();
            server_engine
                .add_peer(&PeerConfig {
                    public_key: client_engine.device().public_key(),
                    preshared_key: Some([13; KEY_SIZE]),
                    endpoint: None,
                    allowed_ips: Vec::new(),
                })
                .unwrap();
            let (client_socket, server_socket) =
                MemoryDatagramSocket::pair(client_addr, server_addr, NonZeroUsize::new(8).unwrap());
            let mut client = WireGuardService::new(client_engine, client_socket);
            let mut server = WireGuardTunnelService::new(server_engine, server_socket, EchoTunnel);
            let cookie_state = CookieState::new([14; KEY_SIZE]);
            let cookie = cookie_state.new_cookie::<BuiltinCrypto>(client_addr.into_std());
            let mut buffer = [0; 256];

            client
                .start_handshake(
                    client_peer,
                    20,
                    Tai64n::from_bytes([15; 12]),
                    EphemeralPrivateKey::from_bytes([16; KEY_SIZE]),
                )
                .await
                .unwrap();
            assert!(
                server
                    .serve_once_with_policy(
                        &mut buffer,
                        None,
                        HandshakePolicy::ReplyWithCookie {
                            cookie_state: &cookie_state,
                            nonce: [17; 24],
                        },
                    )
                    .await
                    .unwrap()
                    == 0
            );
            assert!(client.recv(&mut buffer, None).await.unwrap().is_empty());

            client.tick(Duration::from_secs(5)).await.unwrap();
            client
                .start_handshake(
                    client_peer,
                    21,
                    Tai64n::from_bytes([18; 12]),
                    EphemeralPrivateKey::from_bytes([19; KEY_SIZE]),
                )
                .await
                .unwrap();
            assert!(
                server
                    .serve_once_with_policy(
                        &mut buffer,
                        Some(EphemeralPrivateKey::from_bytes([20; KEY_SIZE])),
                        HandshakePolicy::RequireCookie(&cookie),
                    )
                    .await
                    .unwrap()
                    == 0
            );
            assert!(client.recv(&mut buffer, None).await.unwrap().is_empty());

            assert_eq!(server.serve_once(&mut buffer, None).await.unwrap(), 0);
            client.send(client_peer, b"through udp").await.unwrap();
            assert_eq!(server.serve_once(&mut buffer, None).await.unwrap(), 1);
            let packets = client.recv(&mut buffer, None).await.unwrap();
            assert_eq!(packets[0].peer, client_peer);
            assert_eq!(&packets[0].payload[..11], b"through udp");
        });
    }
}
