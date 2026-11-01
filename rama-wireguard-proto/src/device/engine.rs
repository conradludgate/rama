//! Runtime-neutral WireGuard protocol engine and routing.

use crate::{
    WireGuardCrypto,
    crypto::{CookieState, EphemeralPrivateKey},
    device::{Device, DeviceError, InitiatorHandshake, PeerConfig, PeerId, TransportSession},
    proto::{Cookie, DecodeError, HandshakeResponse, Mac, Message, Tai64n, TransportPacket},
};
use ahash::{HashMap, HashMapExt as _};
use rama_net::{
    address::SocketAddress,
    ip::{IpPacket, IpPacketError},
};
use std::time::Duration;
use zerocopy::IntoBytes;

/// A WireGuard datagram ready to be sent over the configured UDP endpoint.
#[derive(Debug)]
pub struct WireGuardDatagram {
    pub destination: SocketAddress,
    pub payload: Vec<u8>,
}

/// A decrypted packet delivered from a WireGuard peer.
#[derive(Debug)]
pub struct TunnelPacket {
    pub peer: PeerId,
    pub source: SocketAddress,
    pub payload: Vec<u8>,
}

/// An encrypted datagram borrowing caller-provided output storage.
#[derive(Debug)]
pub struct WireGuardDatagramRef<'a> {
    pub destination: SocketAddress,
    pub payload: &'a mut [u8],
}

/// Authenticated, padded transport plaintext borrowing the incoming datagram.
#[derive(Debug)]
pub struct TunnelPacketRef<'a> {
    pub peer: PeerId,
    pub source: SocketAddress,
    pub payload: &'a mut [u8],
}

/// Errors from sending into caller-provided storage.
#[derive(Debug)]
pub enum SendIntoError {
    /// No packet was encrypted and no transport counter was consumed.
    BufferTooSmall {
        required: usize,
        available: usize,
    },
    Engine(EngineError),
}

impl core::fmt::Display for SendIntoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall {
                required,
                available,
            } => {
                write!(
                    f,
                    "WireGuard output needs {required} bytes, but only {available} are available"
                )
            }
            Self::Engine(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for SendIntoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BufferTooSmall { .. } => None,
            Self::Engine(error) => Some(error),
        }
    }
}
impl From<EngineError> for SendIntoError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

/// Effects produced while processing one WireGuard datagram.
#[derive(Debug)]
pub enum WireGuardAction {
    /// A handshake or cookie response that must be sent over UDP.
    Send(WireGuardDatagram),
    /// An authenticated and decrypted tunnel payload.
    Receive(TunnelPacket),
}

struct EstablishedSession<C> {
    peer: PeerId,
    transport: TransportSession<C>,
    created_at: Duration,
    initiator: bool,
    response_mac1: Option<Mac>,
}

/// Stateful WireGuard handshake and transport engine.
pub struct WireGuardEngine<C> {
    device: Device<C>,
    // Configuration changes are controlled by this engine. Keep IDs ready for
    // timer walks instead of allocating and collecting them for every tick.
    maintenance_peers: Vec<PeerId>,
    pending: HashMap<u32, InitiatorHandshake>,
    sessions: HashMap<u32, EstablishedSession<C>>,
    peer_sessions: HashMap<PeerId, u32>,
    next_sessions: HashMap<PeerId, u32>,
    previous_sessions: HashMap<PeerId, u32>,
    next_receiver: u32,
    now: Duration,
    timings: HashMap<PeerId, PeerTimers>,
    pending_created: HashMap<u32, Duration>,
    queued_ip: HashMap<PeerId, Vec<u8>>,
}

impl<C: WireGuardCrypto> WireGuardEngine<C> {
    /// Creates an endpoint around a configured device.
    #[must_use]
    pub fn new(device: Device<C>) -> Self {
        let maintenance_peers = device.peer_ids().collect();
        Self {
            device,
            maintenance_peers,
            pending: HashMap::new(),
            sessions: HashMap::new(),
            peer_sessions: HashMap::new(),
            next_sessions: HashMap::new(),
            previous_sessions: HashMap::new(),
            next_receiver: 1,
            now: Duration::ZERO,
            timings: HashMap::new(),
            pending_created: HashMap::new(),
            queued_ip: HashMap::new(),
        }
    }

    /// Returns the current device configuration. Mutate peers through the engine
    /// so configuration and protocol state stay consistent.
    ///
    /// ```compile_fail
    /// use rama_wireguard_proto::{BuiltinCrypto, PeerId, WireGuardEngine};
    /// fn remove(engine: &mut WireGuardEngine<BuiltinCrypto>, peer: PeerId) {
    ///     engine.device().remove_peer(peer);
    /// }
    /// ```
    #[must_use]
    pub const fn device(&self) -> &Device<C> {
        &self.device
    }

    /// Updates a configured peer's UDP destination without replacing its
    /// identity, routes or protocol state. Authenticated input also learns it.
    pub fn set_peer_endpoint(
        &mut self,
        peer: PeerId,
        endpoint: SocketAddress,
    ) -> Result<(), DeviceError> {
        self.device.set_peer_endpoint(peer, endpoint)
    }

    /// Adds a peer to the underlying device.
    pub fn add_peer(&mut self, config: &PeerConfig) -> Result<PeerId, DeviceError> {
        let peer = self.device.add_peer(config)?;
        self.maintenance_peers.push(peer);
        Ok(peer)
    }

    /// Removes configuration, routes, handshakes, all key generations, timers and queued IP data.
    pub fn remove_peer(&mut self, peer: PeerId) -> Result<(), DeviceError> {
        self.device.remove_peer(peer)?;
        self.maintenance_peers
            .retain(|candidate| *candidate != peer);
        self.discard_pending_handshakes(peer);
        self.expire_sessions(peer);
        self.timings.remove(&peer);
        self.queued_ip.remove(&peer);
        Ok(())
    }

    /// Starts a handshake and returns the first datagram to send.
    ///
    /// The sender index is supplied by the caller so applications can choose their own index
    /// allocation policy. A subsequent response is matched by this index.
    pub fn start_handshake(
        &mut self,
        peer: PeerId,
        sender: u32,
        timestamp: Tai64n,
        ephemeral: EphemeralPrivateKey,
    ) -> Result<WireGuardDatagram, EngineError> {
        if self.pending.contains_key(&sender) || self.sessions.contains_key(&sender) {
            return Err(EngineError::ReceiverInUse(sender));
        }
        if self
            .timings
            .get(&peer)
            .and_then(|t| t.last_handshake)
            .is_some_and(|last| self.now.saturating_sub(last) < HANDSHAKE_RETRY)
        {
            return Err(EngineError::HandshakeRateLimited(peer));
        }
        let destination = self
            .device
            .peer_endpoint(peer)
            .ok_or(EngineError::MissingPeerEndpoint(peer))?;
        let handshake = self
            .device
            .initiate_handshake(peer, sender, timestamp, ephemeral)?;
        let payload = handshake.message.as_bytes().to_vec();
        self.discard_pending_handshakes(peer);
        self.pending.insert(sender, handshake);
        self.pending_created.insert(sender, self.now);
        let timers = self.timings.entry(peer).or_default();
        timers.last_handshake = Some(self.now);
        timers.attempt_started.get_or_insert(self.now);
        timers.want_handshake = true;
        Ok(WireGuardDatagram {
            destination,
            payload,
        })
    }

    /// Encrypts a tunnel payload for an established peer session.
    pub fn send(&mut self, peer: PeerId, payload: &[u8]) -> Result<WireGuardDatagram, EngineError> {
        let (destination, payload) = self.send_with(peer, !payload.is_empty(), |session| {
            session.encrypt_datagram(payload)
        })?;
        Ok(WireGuardDatagram {
            destination,
            payload,
        })
    }

    /// Encrypts an established-session payload into caller-provided storage.
    /// Needs 32 bytes plus the payload length rounded up to a multiple of 16.
    /// The returned slice covers only the completed datagram; remaining storage
    /// is unchanged. A short buffer consumes no nonce and leaves timers unchanged.
    /// Like `send`, this handles arbitrary transport payloads without IP policy.
    pub fn send_into<'a>(
        &mut self,
        peer: PeerId,
        payload: &[u8],
        output: &'a mut [u8],
    ) -> Result<WireGuardDatagramRef<'a>, SendIntoError> {
        let required = super::transport_datagram_len(payload.len());
        if output.len() < required {
            return Err(SendIntoError::BufferTooSmall {
                required,
                available: output.len(),
            });
        }
        let (destination, payload) = self.send_with(peer, !payload.is_empty(), |session| {
            session.encrypt_datagram_into(payload, output)
        })?;
        Ok(WireGuardDatagramRef {
            destination,
            payload,
        })
    }

    fn send_with<T>(
        &mut self,
        peer: PeerId,
        nonempty: bool,
        encrypt: impl FnOnce(&mut TransportSession<C>) -> Result<T, DeviceError>,
    ) -> Result<(SocketAddress, T), EngineError> {
        let receiver = *self
            .peer_sessions
            .get(&peer)
            .ok_or(EngineError::NoEstablishedSession(peer))?;
        let destination = self
            .device
            .peer_endpoint(peer)
            .ok_or(EngineError::MissingPeerEndpoint(peer))?;
        let session = self
            .sessions
            .get_mut(&receiver)
            .ok_or(EngineError::UnknownReceiver(receiver))?;
        if self.now.saturating_sub(session.created_at) >= REJECT_AFTER {
            return Err(EngineError::SessionExpired(peer));
        }
        let payload = encrypt(&mut session.transport)?;
        let timers = self.timings.entry(peer).or_default();
        timers.last_sent = Some(self.now);
        timers.keepalive_due = None;
        if nonempty {
            timers.awaiting_reply.get_or_insert(self.now);
        }
        Ok((destination, payload))
    }

    /// Authenticates one transport-data datagram and decrypts it in place.
    /// Handshake/cookie messages are rejected; process those with `receive_datagram`.
    /// Empty confirmations/keepalives return `None` after updating session state.
    /// Plaintext includes padding and has not undergone allowed-IP validation;
    /// use `validate_ip_packet` before delivering it as IP traffic.
    /// On error, bytes may have changed and must not be used as authenticated data.
    /// Packet processing needs no payload/action allocation; session confirmation
    /// and other handshake bookkeeping can still allocate.
    pub fn receive_transport_in_place<'a>(
        &mut self,
        source: SocketAddress,
        datagram: &'a mut [u8],
    ) -> Result<Option<TunnelPacketRef<'a>>, EngineError> {
        self.receive_transport(source, TransportPacket::decode(datagram)?)
    }

    /// Processes a datagram without imposing a cookie challenge.
    /// Transport plaintext replaces ciphertext in the input buffer; returned
    /// packets own a separate copy. Input bytes may also change on failure.
    pub fn receive_datagram(
        &mut self,
        source: SocketAddress,
        datagram: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
    ) -> Result<Vec<WireGuardAction>, EngineError> {
        self.receive_datagram_with_policy(
            source,
            datagram,
            responder_ephemeral,
            HandshakePolicy::Accept,
        )
    }

    /// Processes a datagram, optionally requiring a cookie on an incoming initiation.
    ///
    /// Cookie load detection remains an application policy decision. Supplying a cookie here
    /// enables the protocol path without requiring the endpoint to guess when it is overloaded.
    pub fn receive_datagram_with_cookie(
        &mut self,
        source: SocketAddress,
        datagram: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        cookie: Option<&Cookie>,
    ) -> Result<Vec<WireGuardAction>, EngineError> {
        let policy = cookie.map_or(HandshakePolicy::Accept, HandshakePolicy::RequireCookie);
        self.receive_datagram_with_policy(source, datagram, responder_ephemeral, policy)
    }

    /// Processes a datagram with an explicit handshake policy.
    pub fn receive_datagram_with_policy(
        &mut self,
        source: SocketAddress,
        datagram: &mut [u8],
        responder_ephemeral: Option<EphemeralPrivateKey>,
        policy: HandshakePolicy<'_>,
    ) -> Result<Vec<WireGuardAction>, EngineError> {
        match Message::decode(datagram)? {
            Message::HandshakeInitiation(initiation) => {
                if let HandshakePolicy::ReplyWithCookie {
                    cookie_state,
                    nonce,
                } = policy
                {
                    let reply =
                        self.device
                            .create_cookie_reply(cookie_state, source, initiation, nonce)?;
                    return Ok(vec![WireGuardAction::Send(WireGuardDatagram {
                        destination: source,
                        payload: reply.as_bytes().to_vec(),
                    })]);
                }
                let ephemeral =
                    responder_ephemeral.ok_or(EngineError::MissingResponderEphemeral)?;
                let sender = self.allocate_receiver()?;
                let cookie = match policy {
                    HandshakePolicy::RequireCookie(cookie) => Some(cookie),
                    HandshakePolicy::Accept | HandshakePolicy::ReplyWithCookie { .. } => None,
                };
                let (peer, response, session) = self.device.accept_handshake_with_cookie_for_peer(
                    initiation, sender, &ephemeral, cookie,
                )?;
                let response_bytes = response.as_bytes().to_vec();
                self.device.set_peer_endpoint(peer, source)?;
                self.install_responder_session(peer, session, response.mac1);
                Ok(vec![WireGuardAction::Send(WireGuardDatagram {
                    destination: source,
                    payload: response_bytes,
                })])
            }
            Message::HandshakeResponse(response) => self.receive_response(source, response),
            Message::CookieReply(reply) => {
                let receiver = reply.receiver.get();
                if let Some(handshake) = self.pending.get(&receiver) {
                    self.device.accept_cookie_reply(handshake, reply)?;
                } else if let Some(session) = self.sessions.get(&receiver)
                    && self.next_sessions.get(&session.peer) == Some(&receiver)
                    && let Some(mac1) = &session.response_mac1
                {
                    self.device
                        .accept_cookie_for_peer(session.peer, mac1, reply)?;
                } else {
                    return Err(EngineError::UnknownHandshake(receiver));
                }
                // Cache only. The initiator's existing retry timer drives the
                // next exchange, avoiding cookie-triggered bandwidth loops.
                Ok(Vec::new())
            }
            Message::Transport(packet) => Ok(self
                .receive_transport(source, packet)?
                .into_iter()
                .map(|packet| {
                    WireGuardAction::Receive(TunnelPacket {
                        peer: packet.peer,
                        source: packet.source,
                        payload: packet.payload.to_vec(),
                    })
                })
                .collect()),
        }
    }

    fn receive_transport<'a>(
        &mut self,
        source: SocketAddress,
        packet: TransportPacket<'a>,
    ) -> Result<Option<TunnelPacketRef<'a>>, EngineError> {
        let receiver = packet.receiver();
        let session = self
            .sessions
            .get_mut(&receiver)
            .ok_or(EngineError::UnknownReceiver(receiver))?;
        if self.now.saturating_sub(session.created_at) >= REJECT_AFTER {
            return Err(EngineError::SessionExpired(session.peer));
        }
        let payload = session.transport.decrypt_packet_in_place(packet)?;
        let peer = session.peer;
        self.device.set_peer_endpoint(peer, source)?;
        let timers = self.timings.entry(peer).or_default();
        timers.awaiting_reply = None;
        // Empty confirmations/keepalives establish liveness, but must not
        // solicit another keepalive and keep an otherwise idle tunnel busy.
        if !payload.is_empty() {
            timers
                .keepalive_due
                .get_or_insert(self.now.saturating_add(KEEPALIVE_TIMEOUT));
        }
        if self.next_sessions.get(&peer) == Some(&receiver) {
            // Confirmation satisfies queued outgoing traffic unless an
            // independent initiation is still awaiting its response.
            if !self
                .pending
                .values()
                .any(|handshake| handshake.peer == peer)
            {
                timers.want_handshake = false;
                timers.attempt_started = None;
            }
            self.next_sessions.remove(&peer);
            self.promote_session(peer, receiver);
        }
        if payload.is_empty() {
            return Ok(None);
        }
        Ok(Some(TunnelPacketRef {
            peer,
            source,
            payload,
        }))
    }

    fn receive_response(
        &mut self,
        source: SocketAddress,
        response: &mut HandshakeResponse,
    ) -> Result<Vec<WireGuardAction>, EngineError> {
        let receiver = response.receiver.get();
        let handshake = self
            .pending
            .get(&receiver)
            .ok_or(EngineError::UnknownHandshake(receiver))?;
        let peer = handshake.peer;
        let session = self.device.complete_handshake(handshake, response)?;
        self.pending.remove(&receiver);
        self.pending_created.remove(&receiver);
        let timers = self.timings.entry(peer).or_default();
        timers.want_handshake = false;
        timers.attempt_started = None;
        timers.awaiting_reply = None;
        self.device.set_peer_endpoint(peer, source)?;
        self.install_session(peer, session);
        // An initiator confirms the responder's next keypair even when no IP packet is queued.
        Ok(vec![WireGuardAction::Send(self.send(peer, &[])?)])
    }

    /// Returns the active transport's local receiver index, if a confirmed session exists.
    #[must_use]
    pub fn current_receiver(&self, peer: PeerId) -> Option<u32> {
        self.peer_sessions.get(&peer).copied()
    }

    fn pending_responder_receiver(&self, peer: PeerId) -> Option<u32> {
        self.next_sessions.get(&peer).copied()
    }

    /// Discards outstanding initiations for a peer before a retry or cancellation.
    pub fn discard_pending_handshakes(&mut self, peer: PeerId) {
        self.pending.retain(|_, handshake| handshake.peer != peer);
        self.pending_created
            .retain(|receiver, _| self.pending.contains_key(receiver));
    }

    /// Removes all transport keys for a peer when the application's lifetime policy expires.
    pub fn expire_sessions(&mut self, peer: PeerId) {
        self.sessions.retain(|_, session| session.peer != peer);
        self.peer_sessions.remove(&peer);
        self.next_sessions.remove(&peer);
        self.previous_sessions.remove(&peer);
    }

    fn promote_session(&mut self, peer: PeerId, receiver: u32) {
        if let Some(previous) = self.peer_sessions.insert(peer, receiver)
            && previous != receiver
            && let Some(expired) = self.previous_sessions.insert(peer, previous)
        {
            self.sessions.remove(&expired);
        }
    }

    fn install_responder_session(
        &mut self,
        peer: PeerId,
        transport: TransportSession<C>,
        mac1: Mac,
    ) {
        let receiver = transport.local_receiver();
        // Receiving an initiation does not provide confirmed send keys. Keep
        // an outstanding retry budget when outgoing IP data is still queued.
        if !self.queued_ip.contains_key(&peer)
            && !self
                .pending
                .values()
                .any(|handshake| handshake.peer == peer)
        {
            let timers = self.timings.entry(peer).or_default();
            timers.want_handshake = false;
            timers.attempt_started = None;
        }
        if let Some(previous) = self.next_sessions.insert(peer, receiver) {
            self.sessions.remove(&previous);
        }
        self.sessions.insert(
            receiver,
            EstablishedSession {
                peer,
                transport,
                created_at: self.now,
                initiator: false,
                response_mac1: Some(mac1),
            },
        );
    }

    fn install_session(&mut self, peer: PeerId, transport: TransportSession<C>) {
        let receiver = transport.local_receiver();
        // Retain a simultaneous responder handshake and one previous receive keypair.
        self.promote_session(peer, receiver);
        self.sessions.insert(
            receiver,
            EstablishedSession {
                peer,
                transport,
                created_at: self.now,
                initiator: true,
                response_mac1: None,
            },
        );
    }

    pub(crate) fn allocate_receiver(&mut self) -> Result<u32, EngineError> {
        for _ in 0..u32::MAX {
            let receiver = self.next_receiver;
            self.next_receiver = self.next_receiver.wrapping_add(1).max(1);
            if !self.pending.contains_key(&receiver) && !self.sessions.contains_key(&receiver) {
                return Ok(receiver);
            }
        }
        Err(EngineError::ReceiverSpaceExhausted)
    }
}

/// Application-selected policy for incoming handshake initiations.
#[derive(Clone, Copy)]
pub enum HandshakePolicy<'a> {
    /// Accept the initiation and create a transport session.
    Accept,
    /// Require the initiation to contain this previously issued cookie.
    RequireCookie(&'a Cookie),
    /// Return a stateless cookie reply without creating a session.
    ReplyWithCookie {
        cookie_state: &'a CookieState,
        nonce: [u8; 24],
    },
}

/// Errors raised by the stateful WireGuard engine.
#[derive(Debug)]
pub enum EngineError {
    Device(DeviceError),
    Decode(DecodeError),
    MissingPeerEndpoint(PeerId),
    NoEstablishedSession(PeerId),
    UnknownHandshake(u32),
    UnknownReceiver(u32),
    ReceiverInUse(u32),
    MissingResponderEphemeral,
    ReceiverSpaceExhausted,
    HandshakeRateLimited(PeerId),
    SessionExpired(PeerId),
    TimeWentBackwards,
    Ip(IpPacketError),
    NoIpRoute(core::net::IpAddr),
    DisallowedSource(PeerId),
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Device(error) => error.fmt(f),
            Self::Decode(error) => error.fmt(f),
            Self::Ip(error) => error.fmt(f),
            Self::MissingPeerEndpoint(peer) => write!(f, "peer {peer:?} has no UDP endpoint"),
            Self::NoEstablishedSession(peer) => {
                write!(f, "peer {peer:?} has no established session")
            }
            Self::UnknownHandshake(id) => write!(f, "unknown handshake receiver {id}"),
            Self::UnknownReceiver(id) => write!(f, "unknown transport receiver {id}"),
            Self::ReceiverInUse(id) => write!(f, "receiver index {id} is already in use"),
            Self::MissingResponderEphemeral => {
                f.write_str("incoming handshake requires a responder ephemeral key")
            }
            Self::ReceiverSpaceExhausted => f.write_str("receiver index space exhausted"),
            Self::HandshakeRateLimited(peer) => {
                write!(f, "handshake retry for peer {peer:?} is rate limited")
            }
            Self::SessionExpired(peer) => write!(f, "session for peer {peer:?} has expired"),
            Self::TimeWentBackwards => f.write_str("WireGuard monotonic time moved backwards"),
            Self::NoIpRoute(ip) => write!(f, "no WireGuard route to {ip}"),
            Self::DisallowedSource(peer) => write!(f, "IP source is not allowed for peer {peer:?}"),
        }
    }
}
impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Device(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::Ip(error) => Some(error),
            _ => None,
        }
    }
}

impl From<IpPacketError> for EngineError {
    fn from(error: IpPacketError) -> Self {
        Self::Ip(error)
    }
}

impl From<DeviceError> for EngineError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

impl From<DecodeError> for EngineError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

/// Maintenance requested by the engine's monotonic-clock tick.
#[derive(Debug)]
pub enum WireGuardMaintenance {
    /// Transmit an encrypted keepalive or queued IP packet.
    Send(WireGuardDatagram),
    /// Start a handshake with fresh randomness and a wall-clock timestamp.
    HandshakeRequired(PeerId),
}

const HANDSHAKE_RETRY: Duration = Duration::from_secs(5);
const REKEY_ATTEMPT: Duration = Duration::from_secs(90);
const REKEY_AFTER: Duration = Duration::from_secs(120);
const REJECT_AFTER: Duration = Duration::from_secs(180);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

struct PeerTimers {
    want_handshake: bool,
    attempt_started: Option<Duration>,
    last_handshake: Option<Duration>,
    last_request: Option<Duration>,
    last_sent: Option<Duration>,
    keepalive_due: Option<Duration>,
    awaiting_reply: Option<Duration>,
    persistent_keepalive: Option<Duration>,
}
impl Default for PeerTimers {
    fn default() -> Self {
        Self {
            want_handshake: true,
            attempt_started: None,
            last_handshake: None,
            last_request: None,
            last_sent: None,
            keepalive_due: None,
            awaiting_reply: None,
            persistent_keepalive: None,
        }
    }
}

impl<C: WireGuardCrypto> WireGuardEngine<C> {
    /// Returns the most recent supplied monotonic time.
    #[must_use]
    pub const fn current_time(&self) -> Duration {
        self.now
    }

    /// Starts a requested handshake with an engine-allocated receiver index.
    pub fn start_handshake_auto(
        &mut self,
        peer: PeerId,
        timestamp: Tai64n,
        ephemeral: EphemeralPrivateKey,
    ) -> Result<WireGuardDatagram, EngineError> {
        let sender = self.allocate_receiver()?;
        self.start_handshake(peer, sender, timestamp, ephemeral)
    }

    /// Configures optional persistent keepalives. Zero disables them.
    pub fn set_persistent_keepalive(&mut self, peer: PeerId, interval: Option<Duration>) {
        self.timings.entry(peer).or_default().persistent_keepalive =
            interval.filter(|d| !d.is_zero());
    }

    /// Advances a caller-supplied monotonic clock and emits protocol maintenance actions.
    ///
    /// Call before processing I/O, at least once per second. Time is elapsed since
    /// engine creation and must never decrease. Execute `Send` actions and fulfill
    /// `HandshakeRequired` actions with fresh keys and a wall-clock TAI64N timestamp.
    /// No runtime, wall clock, randomness or OS interface is accessed here.
    pub fn tick(&mut self, now: Duration) -> Result<Vec<WireGuardMaintenance>, EngineError> {
        if now < self.now {
            return Err(EngineError::TimeWentBackwards);
        }
        self.now = now;
        self.sessions.retain(|_, s| {
            now.saturating_sub(s.created_at) < REJECT_AFTER
                && s.transport.send_counter() < crate::crypto::REJECT_AFTER_MESSAGES
        });
        self.peer_sessions
            .retain(|_, id| self.sessions.contains_key(id));
        self.next_sessions
            .retain(|_, id| self.sessions.contains_key(id));
        self.previous_sessions
            .retain(|_, id| self.sessions.contains_key(id));
        let stale: Vec<_> = self
            .pending_created
            .iter()
            .filter(|(_, created)| now.saturating_sub(**created) >= REKEY_ATTEMPT)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.pending.remove(&id);
            self.pending_created.remove(&id);
        }
        let mut actions = Vec::new();
        for index in 0..self.maintenance_peers.len() {
            let peer = self.maintenance_peers[index];
            let active = self
                .current_receiver(peer)
                .and_then(|id| self.sessions.get(&id));
            let rekey = active.is_some_and(|s| {
                (s.initiator && now.saturating_sub(s.created_at) >= REKEY_AFTER)
                    || s.transport.send_counter() >= REKEY_AFTER_MESSAGES
            });
            let active_created = active.map(|s| s.created_at);
            let unconfirmed = self.pending_responder_receiver(peer).is_some();
            let timers = self.timings.entry(peer).or_default();
            if rekey
                || timers.awaiting_reply.is_some_and(|sent| {
                    now.saturating_sub(sent) >= KEEPALIVE_TIMEOUT + HANDSHAKE_RETRY
                })
            {
                timers.want_handshake = true;
            }
            if timers
                .attempt_started
                .is_some_and(|started| now.saturating_sub(started) >= REKEY_ATTEMPT)
            {
                timers.want_handshake = false;
                timers.attempt_started = None;
                timers.awaiting_reply = None;
                self.queued_ip.remove(&peer);
                self.pending.retain(|_, handshake| handshake.peer != peer);
                self.pending_created
                    .retain(|id, _| self.pending.contains_key(id));
            }
            if timers.want_handshake
                // A lost confirmation must not strand outgoing packets behind
                // receive keys that cannot yet be used for sending.
                && (!unconfirmed || self.queued_ip.contains_key(&peer))
                && self.device.peer_endpoint(peer).is_some()
                && timers
                    .last_request
                    .into_iter()
                    .chain(timers.last_handshake)
                    .max()
                    .is_none_or(|last| now.saturating_sub(last) >= HANDSHAKE_RETRY)
            {
                timers.attempt_started.get_or_insert(now);
                timers.last_request = Some(now);
                actions.push(WireGuardMaintenance::HandshakeRequired(peer));
            }
            let keepalive = timers.keepalive_due.is_some_and(|due| now >= due)
                || timers.persistent_keepalive.is_some_and(|interval| {
                    active_created.is_some_and(|created| {
                        now.saturating_sub(timers.last_sent.unwrap_or(created)) >= interval
                    })
                });
            if active_created.is_some() {
                if let Some(packet) = self.queued_ip.remove(&peer) {
                    actions.push(WireGuardMaintenance::Send(self.send(peer, &packet)?));
                } else if keepalive {
                    actions.push(WireGuardMaintenance::Send(self.send(peer, &[])?));
                }
            }
        }
        Ok(actions)
    }

    /// Routes an IP packet by destination, or retains the latest packet for a
    /// peer while its handshake completes. A subsequent tick requests the handshake.
    pub fn send_ip_packet(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<WireGuardDatagram>, EngineError> {
        let packet = IpPacket::parse(payload)?;
        let peer = self
            .device
            .peer_for_ip(packet.destination())
            .ok_or(EngineError::NoIpRoute(packet.destination()))?;
        if self.current_receiver(peer).is_some() {
            return Ok(Some(self.send(peer, packet.as_bytes())?));
        }
        self.queued_ip.insert(peer, packet.as_bytes().to_vec());
        let timers = self.timings.entry(peer).or_default();
        timers.want_handshake = true;
        timers.attempt_started = Some(self.now);
        Ok(None)
    }

    /// Validates a decrypted packet's source against the same longest-prefix
    /// routing table used for outgoing destinations, and removes tunnel padding.
    pub fn validate_ip_packet<'a>(
        &self,
        peer: PeerId,
        payload: &'a [u8],
    ) -> Result<&'a [u8], EngineError> {
        let packet = IpPacket::parse(payload)?;
        if self.device.peer_for_ip(packet.source()) != Some(peer) {
            return Err(EngineError::DisallowedSource(peer));
        }
        Ok(packet.as_bytes())
    }

    /// Processes WireGuard input with IP framing and allowed-source validation.
    /// Invalid inner packets are discarded after outer transport authentication.
    pub fn receive_ip_datagram(
        &mut self,
        source: SocketAddress,
        datagram: &mut [u8],
        ephemeral: Option<EphemeralPrivateKey>,
    ) -> Result<Vec<WireGuardAction>, EngineError> {
        let actions = self.receive_datagram(source, datagram, ephemeral)?;
        Ok(actions
            .into_iter()
            .filter_map(|action| match action {
                WireGuardAction::Receive(mut packet) => {
                    let length = self
                        .validate_ip_packet(packet.peer, &packet.payload)
                        .ok()?
                        .len();
                    packet.payload.truncate(length);
                    Some(WireGuardAction::Receive(packet))
                }
                action @ WireGuardAction::Send(_) => Some(action),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuiltinCrypto, PublicKey, StaticPrivateKey, proto::KEY_SIZE};
    type TestEngine = WireGuardEngine<BuiltinCrypto>;

    #[test]
    fn maintenance_tracks_preconfigured_added_and_removed_peers() {
        let config = |key: u8| PeerConfig {
            public_key: BuiltinCrypto::x25519_pubkey(&StaticPrivateKey::from_bytes([key; 32])),
            endpoint: Some(SocketAddress::local_ipv4(43000 + u16::from(key))),
            preshared_key: None,
            allowed_ips: vec![],
        };
        let mut device = Device::<BuiltinCrypto>::new(StaticPrivateKey::from_bytes([1; 32]));
        let first = device.add_peer(&config(2)).unwrap();
        let removed = device.add_peer(&config(3)).unwrap();
        let mut engine = TestEngine::new(device);
        engine.remove_peer(removed).unwrap();
        let added = engine.add_peer(&config(4)).unwrap();
        let requested: Vec<_> = engine
            .tick(Duration::ZERO)
            .unwrap()
            .into_iter()
            .filter_map(|a| match a {
                WireGuardMaintenance::HandshakeRequired(peer) => Some(peer),
                WireGuardMaintenance::Send(_) => None,
            })
            .collect();
        assert_eq!(requested.len(), 2);
        assert!(requested.contains(&first));
        assert!(requested.contains(&added));
        assert!(!engine.timings.contains_key(&removed));
        engine.remove_peer(first).unwrap();
        let replacement = engine.add_peer(&config(3)).unwrap();
        let requested: Vec<_> = engine
            .tick(Duration::from_secs(5))
            .unwrap()
            .into_iter()
            .filter_map(|a| match a {
                WireGuardMaintenance::HandshakeRequired(peer) => Some(peer),
                WireGuardMaintenance::Send(_) => None,
            })
            .collect();
        assert_eq!(requested.len(), 2);
        assert!(requested.contains(&added));
        assert!(requested.contains(&replacement));
        assert!(!engine.timings.contains_key(&first));
    }

    fn engine_pair() -> (
        TestEngine,
        TestEngine,
        PeerId,
        PeerId,
        SocketAddress,
        SocketAddress,
    ) {
        let mut client = WireGuardEngine::new(Device::<BuiltinCrypto>::new(
            StaticPrivateKey::from_bytes([1; 32]),
        ));
        let mut server = WireGuardEngine::new(Device::<BuiltinCrypto>::new(
            StaticPrivateKey::from_bytes([2; 32]),
        ));
        let client_addr = SocketAddress::local_ipv4(43_000);
        let server_addr = SocketAddress::local_ipv4(43_001);
        let client_peer = client
            .add_peer(&PeerConfig {
                public_key: server.device().public_key(),
                preshared_key: None,
                endpoint: Some(server_addr),
                allowed_ips: Vec::new(),
            })
            .unwrap();
        let server_peer = server
            .add_peer(&PeerConfig {
                public_key: client.device().public_key(),
                preshared_key: None,
                endpoint: Some(client_addr),
                allowed_ips: Vec::new(),
            })
            .unwrap();
        (
            client,
            server,
            client_peer,
            server_peer,
            client_addr,
            server_addr,
        )
    }

    fn outgoing(actions: Vec<WireGuardAction>) -> Vec<u8> {
        match actions.into_iter().next().unwrap() {
            WireGuardAction::Send(packet) => packet.payload,
            WireGuardAction::Receive(_) => panic!("expected protocol response"),
        }
    }

    #[test]
    fn invalid_response_preserves_pending_handshake_and_confirmation_is_not_ip_data() {
        use crate::crypto::HasMac as _;
        let (mut client, mut server, client_peer, server_peer, client_addr, server_addr) =
            engine_pair();
        let mut initiation = client
            .start_handshake(
                client_peer,
                10,
                Tai64n::from_bytes([4; 12]),
                EphemeralPrivateKey::from_bytes([5; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            server
                .receive_datagram(
                    client_addr,
                    &mut initiation,
                    Some(EphemeralPrivateKey::from_bytes([6; 32])),
                )
                .unwrap(),
        );
        assert!(server.current_receiver(server_peer).is_none());
        assert!(matches!(
            server.send(server_peer, b"unconfirmed"),
            Err(EngineError::NoEstablishedSession(_))
        ));
        let mut forged = response.clone();
        if let Message::HandshakeResponse(response) = Message::decode(&mut forged).unwrap() {
            response.empty.tag.0[0] ^= 1;
            // MAC1 is public-key-derived: even passing MAC1 must not consume pending state.
            let key = BuiltinCrypto::blake2s_hash(b"mac1----", &client.device().public_key().0);
            response.mac1 = response.compute_mac1::<BuiltinCrypto>(&key);
        } else {
            panic!("expected handshake response");
        }
        assert!(matches!(
            client.receive_datagram(server_addr, &mut forged, None),
            Err(EngineError::Device(DeviceError::Crypto(
                crate::CryptoError::Decryption
            )))
        ));
        assert!(client.pending.contains_key(&10));
        let mut confirmation = outgoing(
            client
                .receive_datagram(server_addr, &mut response, None)
                .unwrap(),
        );
        assert!(
            server
                .receive_datagram(client_addr, &mut confirmation, None)
                .unwrap()
                .is_empty()
        );
        assert!(server.current_receiver(server_peer).is_some());
        assert!(!client.pending.contains_key(&10));
    }

    #[test]
    fn rekey_waits_for_confirmation_and_retains_previous_receive_keys() {
        let (mut client, mut server, client_peer, server_peer, client_addr, server_addr) =
            engine_pair();
        let mut previous_server_receiver = None;
        let mut delayed: Option<Vec<u8>> = None;
        let handshake_addr = SocketAddress::local_ipv4(44_002);
        let roaming_addr = SocketAddress::local_ipv4(44_003);
        let forged_addr = SocketAddress::local_ipv4(44_004);
        for round in 1..=2 {
            client
                .tick(Duration::from_secs(u64::from(round) * 6))
                .unwrap();
            server
                .tick(Duration::from_secs(u64::from(round) * 6))
                .unwrap();
            let mut initiation = client
                .start_handshake(
                    client_peer,
                    10 + u32::from(round),
                    Tai64n::from_bytes([round; 12]),
                    EphemeralPrivateKey::from_bytes([round + 3; 32]),
                )
                .unwrap()
                .payload;
            let mut response = outgoing(
                server
                    .receive_datagram(
                        if round == 2 {
                            handshake_addr
                        } else {
                            client_addr
                        },
                        &mut initiation,
                        Some(EphemeralPrivateKey::from_bytes([round + 5; 32])),
                    )
                    .unwrap(),
            );
            assert_eq!(
                server.current_receiver(server_peer),
                previous_server_receiver
            );
            if round == 2 {
                let packet = server
                    .send(server_peer, b"old session still works")
                    .unwrap();
                // A new handshake updates the destination even before its keys are confirmed.
                assert_eq!(packet.destination, handshake_addr);
                let mut packet = packet.payload;
                assert!(matches!(
                    client
                        .receive_datagram(server_addr, &mut packet, None)
                        .unwrap()
                        .as_slice(),
                    [WireGuardAction::Receive(_)]
                ));
            }
            let mut confirmation = outgoing(
                client
                    .receive_datagram(server_addr, &mut response, None)
                    .unwrap(),
            );
            assert!(
                server
                    .receive_datagram(client_addr, &mut confirmation, None)
                    .unwrap()
                    .is_empty()
            );
            assert_ne!(
                server.current_receiver(server_peer),
                previous_server_receiver
            );
            previous_server_receiver = server.current_receiver(server_peer);
            if let Some(mut packet) = delayed.take() {
                let mut forged = packet.clone();
                let last = forged.len() - 1;
                forged[last] ^= 1;
                assert!(matches!(
                    server.receive_datagram(forged_addr, &mut forged, None),
                    Err(EngineError::Device(DeviceError::Crypto(
                        crate::CryptoError::Decryption
                    )))
                ));
                assert_eq!(
                    server.device().peer_endpoint(server_peer),
                    Some(client_addr)
                );
                let mut replay = packet.clone();
                assert!(matches!(
                    server
                        .receive_datagram(roaming_addr, &mut packet, None)
                        .unwrap()
                        .as_slice(),
                    [WireGuardAction::Receive(_)]
                ));
                // Roaming learned through previous receive keys applies to current send keys.
                assert_eq!(
                    server
                        .send(server_peer, b"current keys")
                        .unwrap()
                        .destination,
                    roaming_addr
                );
                assert!(matches!(
                    server.receive_datagram(forged_addr, &mut replay, None),
                    Err(EngineError::Device(DeviceError::Crypto(
                        crate::CryptoError::Rejected
                    )))
                ));
                assert_eq!(
                    server.device().peer_endpoint(server_peer),
                    Some(roaming_addr)
                );
            }
            delayed = Some(
                client
                    .send(client_peer, b"delayed old packet")
                    .unwrap()
                    .payload,
            );
        }
        let mut keepalive = client.send(client_peer, &[]).unwrap().payload;
        assert!(
            server
                .receive_datagram(handshake_addr, &mut keepalive, None)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            server
                .send(server_peer, b"after keepalive")
                .unwrap()
                .destination,
            handshake_addr
        );
        assert_eq!(server.sessions.len(), 2);
        server.expire_sessions(server_peer);
        assert!(server.sessions.is_empty());
        assert!(server.current_receiver(server_peer).is_none());
    }

    #[test]
    fn simultaneous_initiations_keep_both_receive_keypairs() {
        let (mut client, mut server, client_peer, server_peer, client_addr, server_addr) =
            engine_pair();
        let mut client_init = client
            .start_handshake(
                client_peer,
                10,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([3; 32]),
            )
            .unwrap()
            .payload;
        let mut server_init = server
            .start_handshake(
                server_peer,
                20,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([4; 32]),
            )
            .unwrap()
            .payload;
        let mut server_response = outgoing(
            server
                .receive_datagram(
                    client_addr,
                    &mut client_init,
                    Some(EphemeralPrivateKey::from_bytes([5; 32])),
                )
                .unwrap(),
        );
        let mut client_response = outgoing(
            client
                .receive_datagram(
                    server_addr,
                    &mut server_init,
                    Some(EphemeralPrivateKey::from_bytes([6; 32])),
                )
                .unwrap(),
        );
        let mut client_confirmation = outgoing(
            client
                .receive_datagram(server_addr, &mut server_response, None)
                .unwrap(),
        );
        let mut server_confirmation = outgoing(
            server
                .receive_datagram(client_addr, &mut client_response, None)
                .unwrap(),
        );
        client
            .receive_datagram(server_addr, &mut server_confirmation, None)
            .unwrap();
        server
            .receive_datagram(client_addr, &mut client_confirmation, None)
            .unwrap();
        let mut packet = client.send(client_peer, b"client").unwrap().payload;
        assert!(matches!(
            server
                .receive_datagram(client_addr, &mut packet, None)
                .unwrap()
                .as_slice(),
            [WireGuardAction::Receive(_)]
        ));
        let mut packet = server.send(server_peer, b"server").unwrap().payload;
        assert!(matches!(
            client
                .receive_datagram(server_addr, &mut packet, None)
                .unwrap()
                .as_slice(),
            [WireGuardAction::Receive(_)]
        ));
    }

    #[test]
    fn engine_drives_handshake_and_transport() {
        let client_device =
            Device::<BuiltinCrypto>::new(StaticPrivateKey::from_bytes([1; KEY_SIZE]));
        let server_device =
            Device::<BuiltinCrypto>::new(StaticPrivateKey::from_bytes([2; KEY_SIZE]));
        let client_addr = SocketAddress::local_ipv4(41_000);
        let server_addr = SocketAddress::local_ipv4(41_001);
        let mut client = WireGuardEngine::new(client_device);
        let mut server = WireGuardEngine::new(server_device);
        let client_peer = client
            .add_peer(&PeerConfig {
                public_key: server.device().public_key(),
                preshared_key: Some([3; KEY_SIZE]),
                endpoint: Some(server_addr),
                allowed_ips: Vec::new(),
            })
            .unwrap();
        let server_peer = server
            .add_peer(&PeerConfig {
                public_key: client.device().public_key(),
                preshared_key: Some([3; KEY_SIZE]),
                endpoint: None,
                allowed_ips: Vec::new(),
            })
            .unwrap();

        let initiation = client
            .start_handshake(
                client_peer,
                10,
                Tai64n::from_bytes([4; 12]),
                EphemeralPrivateKey::from_bytes([5; KEY_SIZE]),
            )
            .unwrap();
        let mut initiation_bytes = initiation.payload;
        let response_actions = server
            .receive_datagram(
                client_addr,
                &mut initiation_bytes,
                Some(EphemeralPrivateKey::from_bytes([6; KEY_SIZE])),
            )
            .unwrap();
        let response = match response_actions.into_iter().next().unwrap() {
            WireGuardAction::Send(response) => response,
            WireGuardAction::Receive(_) => panic!("handshake produced an unexpected action"),
        };
        let mut response_bytes = response.payload;
        client
            .receive_datagram(server_addr, &mut response_bytes, None)
            .unwrap();

        let data = client.send(client_peer, b"hello").unwrap();
        let mut data_bytes = data.payload;
        let packets = server
            .receive_datagram(server_addr, &mut data_bytes, None)
            .unwrap();
        let packet = match packets.into_iter().next().unwrap() {
            WireGuardAction::Receive(packet) => packet,
            WireGuardAction::Send(_) => panic!("transport produced an unexpected action"),
        };
        assert_eq!(packet.peer, server_peer);
        assert_eq!(&packet.payload[..5], b"hello");
    }
    fn established_pair() -> (
        TestEngine,
        TestEngine,
        PeerId,
        PeerId,
        SocketAddress,
        SocketAddress,
    ) {
        let (mut client, mut server, cp, sp, ca, sa) = engine_pair();
        let mut init = client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([3; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            server
                .receive_datagram(
                    ca,
                    &mut init,
                    Some(EphemeralPrivateKey::from_bytes([4; 32])),
                )
                .unwrap(),
        );
        let mut confirmation = outgoing(client.receive_datagram(sa, &mut response, None).unwrap());
        server
            .receive_datagram(ca, &mut confirmation, None)
            .unwrap();
        (client, server, cp, sp, ca, sa)
    }

    #[test]
    fn caller_buffers_match_owned_packets_and_clear_reused_padding() {
        let (mut owned_tx, mut owned_rx, cp, sp, ca, sa) = established_pair();
        let (mut tx, mut rx, peer, _, _, _) = established_pair();
        let mut output = [0xa5; 65_535];
        for len in [0, 1, 15, 16, 17, 64, 1280, 1420, 65_472] {
            output.fill(0xa5);
            let payload = vec![7; len];
            let mut expected = owned_tx.send(cp, &payload).unwrap();
            let packet = tx.send_into(peer, &payload, &mut output).unwrap();
            assert_eq!(packet.destination, sa);
            assert_eq!(packet.payload, expected.payload);
            let wire_len = packet.payload.len();
            let plaintext_start = packet.payload[16..].as_ptr();
            let received = rx.receive_transport_in_place(ca, packet.payload).unwrap();
            let owned = owned_rx
                .receive_datagram(ca, &mut expected.payload, None)
                .unwrap();
            if len == 0 {
                assert!(received.is_none());
                assert!(owned.is_empty());
            } else {
                let received = received.unwrap();
                assert_eq!(received.peer, sp);
                assert_eq!(received.source, ca);
                assert_eq!(received.payload.as_ptr(), plaintext_start);
                assert_eq!(&received.payload[..len], payload);
                assert!(received.payload[len..].iter().all(|byte| *byte == 0));
                assert!(matches!(&owned[..], [WireGuardAction::Receive(packet)]
                    if packet.payload == received.payload));
            }
            assert!(output[wire_len..].iter().all(|byte| *byte == 0xa5));
        }
    }

    #[test]
    fn short_output_changes_neither_nonce_timers_nor_storage() {
        let (mut tx, _, peer, _, _, _) = established_pair();
        tx.tick(Duration::from_secs(1)).unwrap();
        let receiver = tx.current_receiver(peer).unwrap();
        let counter = tx.sessions[&receiver].transport.send_counter();
        let last_sent = tx.timings[&peer].last_sent;
        let awaiting_reply = tx.timings[&peer].awaiting_reply;
        let mut short = [0xa5; 63];
        assert!(matches!(
            tx.send_into(peer, &[7; 17], &mut short),
            Err(SendIntoError::BufferTooSmall {
                required: 64,
                available: 63
            })
        ));
        assert_eq!(short, [0xa5; 63]);
        assert_eq!(tx.sessions[&receiver].transport.send_counter(), counter);
        assert_eq!(tx.timings[&peer].last_sent, last_sent);
        assert_eq!(tx.timings[&peer].awaiting_reply, awaiting_reply);
        let mut output = [0; 64];
        let packet = tx.send_into(peer, &[7; 17], &mut output).unwrap();
        assert_eq!(
            TransportPacket::decode(packet.payload).unwrap().counter(),
            counter
        );
        assert_eq!(tx.timings[&peer].last_sent, Some(Duration::from_secs(1)));
    }

    #[test]
    fn failed_in_place_authentication_preserves_replay_and_roaming_state() {
        let (mut tx, mut rx, cp, sp, ca, _) = established_pair();
        let roaming = SocketAddress::local_ipv4(43000);
        let mut output = [0; 128];
        let packet = tx.send_into(cp, b"authenticated", &mut output).unwrap();
        let original = packet.payload.to_vec();
        let mut forged = original.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            rx.receive_transport_in_place(roaming, &mut forged),
            Err(EngineError::Device(DeviceError::Crypto(
                crate::CryptoError::Decryption
            )))
        ));
        assert_eq!(rx.device().peer_endpoint(sp), Some(ca));
        let mut valid = original.clone();
        let received = rx
            .receive_transport_in_place(roaming, &mut valid)
            .unwrap()
            .unwrap();
        assert!(received.payload.starts_with(b"authenticated"));
        assert_eq!(rx.device().peer_endpoint(sp), Some(roaming));
        let mut replay = original;
        assert!(matches!(
            rx.receive_transport_in_place(ca, &mut replay),
            Err(EngineError::Device(DeviceError::Crypto(
                crate::CryptoError::Rejected
            )))
        ));
        assert_eq!(rx.device().peer_endpoint(sp), Some(roaming));
    }

    #[test]
    fn in_place_confirmation_promotes_keys_without_soliciting_keepalives() {
        let (mut tx, mut rx, cp, sp, ca, sa) = engine_pair();
        let mut init = tx
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([3; 32]),
            )
            .unwrap()
            .payload;
        // The transport-only API must reject handshakes without consuming them.
        assert!(matches!(
            rx.receive_transport_in_place(ca, &mut init),
            Err(EngineError::Decode(DecodeError::UnexpectedMessageType))
        ));
        let mut response = outgoing(
            rx.receive_datagram(
                ca,
                &mut init,
                Some(EphemeralPrivateKey::from_bytes([4; 32])),
            )
            .unwrap(),
        );
        let mut confirmation = outgoing(tx.receive_datagram(sa, &mut response, None).unwrap());
        assert!(rx.current_receiver(sp).is_none());
        assert!(
            rx.receive_transport_in_place(ca, &mut confirmation)
                .unwrap()
                .is_none()
        );
        assert!(rx.current_receiver(sp).is_some());
        assert!(rx.tick(KEEPALIVE_TIMEOUT).unwrap().is_empty());
        let mut output = [0; 32];
        let keepalive = rx.send_into(sp, &[], &mut output).unwrap();
        assert!(
            tx.receive_transport_in_place(sa, keepalive.payload)
                .unwrap()
                .is_none()
        );
        assert!(tx.tick(KEEPALIVE_TIMEOUT).unwrap().is_empty());
        let mut stale = tx.send(cp, b"expired").unwrap().payload;
        rx.tick(REJECT_AFTER).unwrap();
        assert!(matches!(
            rx.receive_transport_in_place(ca, &mut stale),
            Err(EngineError::UnknownReceiver(_))
        ));
    }

    #[test]
    fn lost_rekey_response_preserves_traffic_and_retries_with_fresh_keys() {
        let (mut client, mut server, cp, sp, ca, sa) = established_pair();
        let old_client = client.current_receiver(cp);
        let old_server = server.current_receiver(sp);
        assert!(matches!(
            client.tick(Duration::from_secs(120)).unwrap().as_slice(),
            [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == cp
        ));
        server.tick(Duration::from_secs(120)).unwrap();
        let mut init = client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([2; 12]),
                EphemeralPrivateKey::from_bytes([5; 32]),
            )
            .unwrap()
            .payload;
        // Delay the response beyond the retry rather than delivering it.
        let mut delayed_response = outgoing(
            server
                .receive_datagram(
                    ca,
                    &mut init,
                    Some(EphemeralPrivateKey::from_bytes([6; 32])),
                )
                .unwrap(),
        );
        let first_unconfirmed = server.pending_responder_receiver(sp).unwrap();
        assert_eq!(client.current_receiver(cp), old_client);
        assert_eq!(server.current_receiver(sp), old_server);
        for from_client in [true, false] {
            let (sender, receiver, peer, source) = if from_client {
                (&mut client, &mut server, cp, ca)
            } else {
                (&mut server, &mut client, sp, sa)
            };
            let mut packet = sender.send(peer, b"old keys still work").unwrap().payload;
            assert!(
                matches!(receiver.receive_datagram(source, &mut packet, None).unwrap().as_slice(),
                [WireGuardAction::Receive(packet)] if packet.payload.starts_with(b"old keys still work"))
            );
        }
        assert!(client.tick(Duration::from_secs(124)).unwrap().is_empty());
        assert!(matches!(
            client.tick(Duration::from_secs(125)).unwrap().as_slice(),
            [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == cp
        ));
        server.tick(Duration::from_secs(125)).unwrap();
        let mut retry = client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([3; 12]),
                EphemeralPrivateKey::from_bytes([7; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            server
                .receive_datagram(
                    ca,
                    &mut retry,
                    Some(EphemeralPrivateKey::from_bytes([8; 32])),
                )
                .unwrap(),
        );
        assert!(!server.sessions.contains_key(&first_unconfirmed));
        assert!(matches!(
            client.receive_datagram(sa, &mut delayed_response, None),
            Err(EngineError::UnknownHandshake(_))
        ));
        let mut confirmation = outgoing(client.receive_datagram(sa, &mut response, None).unwrap());
        server
            .receive_datagram(ca, &mut confirmation, None)
            .unwrap();
        assert_ne!(client.current_receiver(cp), old_client);
        assert_ne!(server.current_receiver(sp), old_server);
        assert_eq!(client.sessions.len(), 2);
        assert_eq!(server.sessions.len(), 2);
        for from_client in [true, false] {
            let (sender, receiver, peer, source) = if from_client {
                (&mut client, &mut server, cp, ca)
            } else {
                (&mut server, &mut client, sp, sa)
            };
            let mut packet = sender.send(peer, b"new keys work too").unwrap().payload;
            assert!(
                matches!(receiver.receive_datagram(source, &mut packet, None).unwrap().as_slice(),
                [WireGuardAction::Receive(packet)] if packet.payload.starts_with(b"new keys work too"))
            );
        }
    }

    #[test]
    fn lost_initial_confirmation_does_not_block_queued_traffic() {
        check_lost_confirmation(false, false);
    }

    #[test]
    fn lost_initial_confirmation_preserves_already_queued_traffic() {
        check_lost_confirmation(false, true);
    }

    #[test]
    fn late_confirmation_flushes_queued_traffic_without_redundant_handshake() {
        use rama_net::ip::{EcnCodepoint, Ipv4PacketHeader};
        let (mut client, mut server, cp, sp, ca, sa) = engine_pair();
        server
            .device
            .routes
            .insert("10.77.0.1/32".parse().unwrap(), sp);
        server.tick(Duration::ZERO).unwrap();
        let mut init = client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([3; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            server
                .receive_datagram(
                    ca,
                    &mut init,
                    Some(EphemeralPrivateKey::from_bytes([4; 32])),
                )
                .unwrap(),
        );
        let mut confirmation = outgoing(client.receive_datagram(sa, &mut response, None).unwrap());
        server.tick(Duration::from_secs(1)).unwrap();
        let mut buffer = [0; 64];
        let packet = Ipv4PacketHeader {
            source: "10.77.0.2".parse().unwrap(),
            destination: "10.77.0.1".parse().unwrap(),
            protocol: 17,
            ttl: 64,
            ecn: EcnCodepoint::NotEct,
        }
        .encode(b"waiting for confirmation", &mut buffer)
        .unwrap()
        .to_vec();
        assert!(server.send_ip_packet(&packet).unwrap().is_none());
        // The original confirmation arrives before a reverse handshake starts.
        server
            .receive_datagram(ca, &mut confirmation, None)
            .unwrap();
        let actions = server.tick(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            actions.as_slice(),
            [WireGuardMaintenance::Send(_)]
        ));
        let mut data = match actions.into_iter().next().unwrap() {
            WireGuardMaintenance::Send(datagram) => datagram.payload,
            WireGuardMaintenance::HandshakeRequired(_) => panic!("expected queued packet"),
        };
        assert!(
            matches!(client.receive_datagram(sa, &mut data, None).unwrap().as_slice(),
            [WireGuardAction::Receive(received)] if received.payload.starts_with(&packet))
        );
        assert!(server.tick(Duration::from_secs(5)).unwrap().is_empty());
    }

    #[test]
    fn lost_rekey_confirmation_does_not_block_queued_traffic_after_old_keys_expire() {
        check_lost_confirmation(true, false);
    }

    fn check_lost_confirmation(rekey: bool, queued_before: bool) {
        use rama_net::ip::{EcnCodepoint, Ipv4PacketHeader};
        let (mut client, mut server, cp, sp, ca, sa) = if rekey {
            established_pair()
        } else {
            engine_pair()
        };
        client
            .device
            .routes
            .insert("10.77.0.2/32".parse().unwrap(), cp);
        server
            .device
            .routes
            .insert("10.77.0.1/32".parse().unwrap(), sp);
        let created = if rekey { 120 } else { 0 };
        client.tick(Duration::from_secs(created)).unwrap();
        server.tick(Duration::from_secs(created)).unwrap();
        let mut buffer = [0; 64];
        let packet = Ipv4PacketHeader {
            source: "10.77.0.2".parse().unwrap(),
            destination: "10.77.0.1".parse().unwrap(),
            protocol: 17,
            ttl: 64,
            ecn: EcnCodepoint::NotEct,
        }
        .encode(b"queued during lost confirmation", &mut buffer)
        .unwrap()
        .to_vec();
        if queued_before {
            assert!(server.send_ip_packet(&packet).unwrap().is_none());
        }
        let mut init = client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([2; 12]),
                EphemeralPrivateKey::from_bytes([5; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            server
                .receive_datagram(
                    ca,
                    &mut init,
                    Some(EphemeralPrivateKey::from_bytes([6; 32])),
                )
                .unwrap(),
        );
        // Discard the empty confirmation. The initiator has the new keys,
        // but the responder must not send with them until they are confirmed.
        let _lost_confirmation =
            outgoing(client.receive_datagram(sa, &mut response, None).unwrap());
        let unconfirmed = server.pending_responder_receiver(sp).unwrap();
        let recovery = if rekey { 180 } else { 5 };
        client.tick(Duration::from_secs(recovery)).unwrap();
        let first_tick = server.tick(Duration::from_secs(recovery)).unwrap();
        assert!(server.current_receiver(sp).is_none());
        assert_eq!(server.pending_responder_receiver(sp), Some(unconfirmed));
        let actions = if queued_before {
            first_tick
        } else {
            assert!(first_tick.is_empty());
            assert!(server.send_ip_packet(&packet).unwrap().is_none());
            server.tick(Duration::from_secs(recovery)).unwrap()
        };
        assert!(
            matches!(actions.as_slice(),
                [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == sp),
            "unconfirmed receive keys must not block an outgoing handshake (rekey={rekey})"
        );
        // Recover with a handshake in the opposite direction, preserving
        // the queued packet until independently confirmed send keys exist.
        let mut init = server
            .start_handshake_auto(
                sp,
                Tai64n::from_bytes([3; 12]),
                EphemeralPrivateKey::from_bytes([7; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            client
                .receive_datagram(
                    sa,
                    &mut init,
                    Some(EphemeralPrivateKey::from_bytes([8; 32])),
                )
                .unwrap(),
        );
        let mut confirmation = outgoing(server.receive_datagram(ca, &mut response, None).unwrap());
        client
            .receive_datagram(sa, &mut confirmation, None)
            .unwrap();
        let actions = server.tick(Duration::from_secs(recovery)).unwrap();
        assert!(matches!(
            actions.as_slice(),
            [WireGuardMaintenance::Send(_)]
        ));
        let mut queued = match actions.into_iter().next().unwrap() {
            WireGuardMaintenance::Send(datagram) => datagram.payload,
            WireGuardMaintenance::HandshakeRequired(_) => panic!("expected queued packet"),
        };
        assert!(
            matches!(client.receive_ip_datagram(sa, &mut queued, None).unwrap().as_slice(),
                [WireGuardAction::Receive(received)] if received.payload == packet)
        );
        let mut reply = client
            .send(cp, b"recovered in both directions")
            .unwrap()
            .payload;
        assert!(
            matches!(server.receive_datagram(ca, &mut reply, None).unwrap().as_slice(),
                [WireGuardAction::Receive(received)] if received.payload.starts_with(b"recovered in both directions"))
        );
    }

    #[test]
    fn removing_peer_discards_all_protocol_state_and_rejects_old_keys() {
        let (mut client, mut server, cp, sp, _ca, sa) = established_pair();
        let mut old_packet = server.send(sp, b"old keys").unwrap().payload;
        client.tick(Duration::from_secs(6)).unwrap();
        client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([2; 12]),
                EphemeralPrivateKey::from_bytes([7; 32]),
            )
            .unwrap();
        client.queued_ip.insert(cp, vec![1, 2, 3]);
        assert!(!client.sessions.is_empty());
        assert!(!client.pending.is_empty());
        client.remove_peer(cp).unwrap();
        assert!(client.sessions.is_empty());
        assert!(client.peer_sessions.is_empty());
        assert!(client.next_sessions.is_empty());
        assert!(client.previous_sessions.is_empty());
        assert!(client.pending.is_empty());
        assert!(client.pending_created.is_empty());
        assert!(client.timings.is_empty());
        assert!(client.queued_ip.is_empty());
        assert_eq!(client.device().peer_ids().count(), 0);
        assert!(matches!(
            client.receive_datagram(sa, &mut old_packet, None),
            Err(EngineError::UnknownReceiver(_))
        ));
        let replacement = client
            .add_peer(&PeerConfig {
                public_key: server.device().public_key(),
                preshared_key: None,
                endpoint: Some(sa),
                allowed_ips: vec![],
            })
            .unwrap();
        assert_ne!(replacement, cp);
    }

    #[test]
    fn retries_are_rate_limited_bounded_and_release_pending_keys() {
        let (mut client, _, cp, _, _, _) = engine_pair();
        assert!(
            matches!(client.tick(Duration::ZERO).unwrap().as_slice(), [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == cp)
        );
        client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([3; 32]),
            )
            .unwrap();
        assert!(client.tick(Duration::from_secs(4)).unwrap().is_empty());
        assert!(matches!(
            client.start_handshake_auto(
                cp,
                Tai64n::from_bytes([2; 12]),
                EphemeralPrivateKey::from_bytes([4; 32])
            ),
            Err(EngineError::HandshakeRateLimited(_))
        ));
        assert!(matches!(
            client.tick(Duration::from_secs(5)).unwrap().as_slice(),
            [WireGuardMaintenance::HandshakeRequired(_)]
        ));
        client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([2; 12]),
                EphemeralPrivateKey::from_bytes([4; 32]),
            )
            .unwrap();
        assert_eq!(client.pending.len(), 1);
        assert!(client.tick(Duration::from_secs(90)).unwrap().is_empty());
        assert!(client.pending.is_empty());
        assert!(client.tick(Duration::from_secs(95)).unwrap().is_empty());
        assert!(matches!(
            client.tick(Duration::from_secs(94)),
            Err(EngineError::TimeWentBackwards)
        ));
    }

    #[test]
    fn handshake_confirmation_does_not_start_idle_keepalive_traffic() {
        let (mut client, mut server, _, _, _, _) = established_pair();
        // Stop before the independent 120-second rekey policy becomes due.
        for seconds in 0..120 {
            let now = Duration::from_secs(seconds);
            assert!(client.tick(now).unwrap().is_empty(), "client at {seconds}s");
            assert!(server.tick(now).unwrap().is_empty(), "server at {seconds}s");
        }
    }

    #[test]
    fn data_keepalive_does_not_trigger_a_keepalive_reply() {
        let (mut client, mut server, cp, _, ca, sa) = established_pair();
        let mut data = client
            .send(cp, b"needs an acknowledgement")
            .unwrap()
            .payload;
        assert!(matches!(
            server
                .receive_datagram(ca, &mut data, None)
                .unwrap()
                .as_slice(),
            [WireGuardAction::Receive(_)]
        ));
        assert!(server.tick(Duration::from_secs(9)).unwrap().is_empty());
        let actions = server.tick(Duration::from_secs(10)).unwrap();
        assert!(matches!(
            actions.as_slice(),
            [WireGuardMaintenance::Send(_)]
        ));
        let mut keepalive = match actions.into_iter().next().unwrap() {
            WireGuardMaintenance::Send(packet) => packet.payload,
            WireGuardMaintenance::HandshakeRequired(_) => panic!("expected keepalive"),
        };
        assert!(client.tick(Duration::from_secs(10)).unwrap().is_empty());
        assert!(
            client
                .receive_datagram(sa, &mut keepalive, None)
                .unwrap()
                .is_empty()
        );
        for seconds in 11..120 {
            let now = Duration::from_secs(seconds);
            assert!(client.tick(now).unwrap().is_empty(), "client at {seconds}s");
            assert!(server.tick(now).unwrap().is_empty(), "server at {seconds}s");
        }
    }

    #[test]
    fn persistent_keepalives_still_run_without_triggering_replies() {
        let (mut client, mut server, cp, _, ca, _) = established_pair();
        client.set_persistent_keepalive(cp, Some(Duration::from_secs(25)));
        for seconds in 0..76 {
            let now = Duration::from_secs(seconds);
            assert!(server.tick(now).unwrap().is_empty(), "server at {seconds}s");
            let actions = client.tick(now).unwrap();
            if seconds != 0 && seconds % 25 == 0 {
                assert!(matches!(
                    actions.as_slice(),
                    [WireGuardMaintenance::Send(_)]
                ));
                let mut keepalive = match actions.into_iter().next().unwrap() {
                    WireGuardMaintenance::Send(packet) => packet.payload,
                    WireGuardMaintenance::HandshakeRequired(_) => panic!("expected keepalive"),
                };
                assert!(
                    server
                        .receive_datagram(ca, &mut keepalive, None)
                        .unwrap()
                        .is_empty()
                );
            } else {
                assert!(actions.is_empty(), "client at {seconds}s");
            }
        }
    }

    #[test]
    fn keepalives_rekeying_and_all_receive_key_expiry_are_engine_policy() {
        let (mut client, mut server, cp, sp, ca, sa) = established_pair();
        let mut data = client
            .send(cp, b"needs an acknowledgement")
            .unwrap()
            .payload;
        server.receive_datagram(ca, &mut data, None).unwrap();
        assert!(server.tick(Duration::from_secs(9)).unwrap().is_empty());
        let mut keepalive = match server.tick(Duration::from_secs(10)).unwrap().pop().unwrap() {
            WireGuardMaintenance::Send(packet) => packet.payload,
            WireGuardMaintenance::HandshakeRequired(_) => panic!("expected keepalive"),
        };
        client.receive_datagram(sa, &mut keepalive, None).unwrap();
        assert!(
            client
                .tick(Duration::from_secs(120))
                .unwrap()
                .iter()
                .any(|a| matches!(a, WireGuardMaintenance::HandshakeRequired(peer) if *peer == cp))
        );
        // Install the rekey at t=120 while retaining the original receive keypair.
        server.tick(Duration::from_secs(120)).unwrap();
        let mut init = client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([2; 12]),
                EphemeralPrivateKey::from_bytes([5; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            server
                .receive_datagram(
                    ca,
                    &mut init,
                    Some(EphemeralPrivateKey::from_bytes([6; 32])),
                )
                .unwrap(),
        );
        let mut confirmation = outgoing(client.receive_datagram(sa, &mut response, None).unwrap());
        server
            .receive_datagram(ca, &mut confirmation, None)
            .unwrap();
        assert_eq!(server.sessions.len(), 2);
        server.tick(Duration::from_secs(180)).unwrap();
        assert_eq!(server.sessions.len(), 1);
        assert!(server.current_receiver(sp).is_some());
        server.tick(Duration::from_secs(300)).unwrap();
        assert!(server.sessions.is_empty());
        assert!(server.current_receiver(sp).is_none());
    }

    #[test]
    fn ip_queue_flushes_after_handshake_and_spoofed_sources_are_dropped() {
        use rama_net::ip::{EcnCodepoint, Ipv4PacketHeader};
        let (mut client, mut server, cp, sp, ca, sa) = engine_pair();
        client
            .device
            .routes
            .insert("10.77.0.2/32".parse().unwrap(), cp);
        server
            .device
            .routes
            .insert("10.77.0.1/32".parse().unwrap(), sp);
        let mut bytes = [0; 48];
        let mut header = Ipv4PacketHeader {
            source: "10.77.0.1".parse().unwrap(),
            destination: "10.77.0.2".parse().unwrap(),
            protocol: 17,
            ttl: 64,
            ecn: EcnCodepoint::NotEct,
        };
        let packet = header.encode(b"hello", &mut bytes).unwrap().to_vec();
        assert!(client.send_ip_packet(&packet).unwrap().is_none());
        client.tick(Duration::ZERO).unwrap();
        let mut init = client
            .start_handshake_auto(
                cp,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([3; 32]),
            )
            .unwrap()
            .payload;
        let mut response = outgoing(
            server
                .receive_datagram(
                    ca,
                    &mut init,
                    Some(EphemeralPrivateKey::from_bytes([4; 32])),
                )
                .unwrap(),
        );
        let mut confirmation = outgoing(client.receive_datagram(sa, &mut response, None).unwrap());
        server
            .receive_datagram(ca, &mut confirmation, None)
            .unwrap();
        let mut encrypted = match client.tick(Duration::ZERO).unwrap().pop().unwrap() {
            WireGuardMaintenance::Send(packet) => packet.payload,
            WireGuardMaintenance::HandshakeRequired(_) => panic!("expected queued IP packet"),
        };
        let received = server
            .receive_ip_datagram(ca, &mut encrypted, None)
            .unwrap();
        assert!(
            matches!(&received[..], [WireGuardAction::Receive(received)] if received.payload == packet)
        );
        header.source = "10.77.0.99".parse().unwrap();
        let spoofed = header.encode(b"hello", &mut bytes).unwrap();
        let mut encrypted = client.send_ip_packet(spoofed).unwrap().unwrap().payload;
        assert!(
            server
                .receive_ip_datagram(ca, &mut encrypted, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn longest_prefix_controls_peer_selection_and_source_ownership() {
        use rama_net::ip::{EcnCodepoint, Ipv4PacketHeader};
        let mut engine = WireGuardEngine::new(Device::<BuiltinCrypto>::new(
            StaticPrivateKey::from_bytes([1; 32]),
        ));
        let broad = engine
            .add_peer(&PeerConfig {
                public_key: PublicKey([2; 32]),
                preshared_key: None,
                endpoint: Some(SocketAddress::local_ipv4(1)),
                allowed_ips: vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()],
            })
            .unwrap();
        let narrow = engine
            .add_peer(&PeerConfig {
                public_key: PublicKey([3; 32]),
                preshared_key: None,
                endpoint: Some(SocketAddress::local_ipv4(2)),
                allowed_ips: vec![
                    "10.1.0.0/16".parse().unwrap(),
                    "fd00:1::/32".parse().unwrap(),
                ],
            })
            .unwrap();
        let mut bytes = [0; 48];
        let header = Ipv4PacketHeader {
            source: "10.1.2.3".parse().unwrap(),
            destination: "10.1.2.4".parse().unwrap(),
            protocol: 17,
            ttl: 64,
            ecn: EcnCodepoint::NotEct,
        };
        header.encode(b"hi", &mut bytes).unwrap();
        assert!(matches!(
            engine.validate_ip_packet(broad, &bytes),
            Err(EngineError::DisallowedSource(_))
        ));
        assert_eq!(engine.validate_ip_packet(narrow, &bytes).unwrap().len(), 22);
        assert!(engine.send_ip_packet(&bytes).unwrap().is_none());
        assert!(engine.queued_ip.contains_key(&narrow));
        assert!(!engine.queued_ip.contains_key(&broad));
        assert_eq!(
            engine.device.peer_for_ip("fd00:1::5".parse().unwrap()),
            Some(narrow)
        );
        assert_eq!(
            engine.device.peer_for_ip("fd00:2::5".parse().unwrap()),
            Some(broad)
        );
    }
}
