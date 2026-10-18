//! Runtime-neutral WireGuard protocol engine and routing.

use crate::{
    WireGuardCrypto,
    crypto::{CookieState, EphemeralPrivateKey},
    device::{Device, DeviceError, InitiatorHandshake, PeerConfig, PeerId, TransportSession},
    proto::{Cookie, DecodeError, HandshakeResponse, Message, Tai64n},
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
}

/// Stateful WireGuard handshake and transport engine.
pub struct WireGuardEngine<C> {
    device: Device<C>,
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
        Self {
            device,
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

    /// Returns the current device configuration.
    #[must_use]
    pub const fn device(&self) -> &Device<C> {
        &self.device
    }

    /// Returns mutable access to the device configuration.
    pub fn device_mut(&mut self) -> &mut Device<C> {
        &mut self.device
    }

    /// Adds a peer to the underlying device.
    pub fn add_peer(&mut self, config: &PeerConfig) -> Result<PeerId, DeviceError> {
        self.device.add_peer(config)
    }

    /// Removes configuration, routes, handshakes, all key generations, timers and queued IP data.
    pub fn remove_peer(&mut self, peer: PeerId) -> Result<(), DeviceError> {
        self.device.remove_peer(peer)?;
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
        let nonempty = !payload.is_empty();
        let payload = session.transport.encrypt_datagram(payload)?;
        let timers = self.timings.entry(peer).or_default();
        timers.last_sent = Some(self.now);
        timers.keepalive_due = None;
        if nonempty {
            timers.awaiting_reply.get_or_insert(self.now);
        }
        Ok(WireGuardDatagram {
            destination,
            payload,
        })
    }

    /// Processes a datagram without imposing a cookie challenge.
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
                self.install_responder_session(peer, session);
                Ok(vec![WireGuardAction::Send(WireGuardDatagram {
                    destination: source,
                    payload: response_bytes,
                })])
            }
            Message::HandshakeResponse(response) => self.receive_response(source, response),
            Message::CookieReply(reply) => {
                let receiver = reply.receiver.get();
                let handshake = self
                    .pending
                    .remove(&receiver)
                    .ok_or(EngineError::UnknownHandshake(receiver))?;
                match self.device.accept_cookie_reply(&handshake, reply) {
                    Ok(()) => {
                        // Keep the pending state available for callers that want to inspect it;
                        // a retry should normally start a fresh handshake with a new sender index.
                        self.pending.insert(receiver, handshake);
                        Ok(Vec::new())
                    }
                    Err(error) => {
                        self.pending.insert(receiver, handshake);
                        Err(error.into())
                    }
                }
            }
            Message::Transport(packet) => {
                let receiver = packet.receiver();
                let session = self
                    .sessions
                    .get_mut(&receiver)
                    .ok_or(EngineError::UnknownReceiver(receiver))?;
                if self.now.saturating_sub(session.created_at) >= REJECT_AFTER {
                    return Err(EngineError::SessionExpired(session.peer));
                }
                let payload = session.transport.decrypt_packet(&packet)?;
                let peer = session.peer;
                self.device.set_peer_endpoint(peer, source)?;
                let timers = self.timings.entry(peer).or_default();
                timers.awaiting_reply = None;
                timers
                    .keepalive_due
                    .get_or_insert(self.now.saturating_add(KEEPALIVE_TIMEOUT));
                if self.next_sessions.get(&peer) == Some(&receiver) {
                    self.next_sessions.remove(&peer);
                    self.promote_session(peer, receiver);
                }
                if payload.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(vec![WireGuardAction::Receive(TunnelPacket {
                    peer,
                    source,
                    payload,
                })])
            }
        }
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

    fn install_responder_session(&mut self, peer: PeerId, transport: TransportSession<C>) {
        let receiver = transport.local_receiver();
        if !self
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
        let peers: Vec<_> = self.device.peer_ids().collect();
        let mut actions = Vec::new();
        for peer in peers {
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
                && !unconfirmed
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
    fn keepalives_rekeying_and_all_receive_key_expiry_are_engine_policy() {
        let (mut client, mut server, cp, sp, ca, sa) = established_pair();
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
