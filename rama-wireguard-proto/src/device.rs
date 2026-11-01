//! Device configuration, IP routing, handshake primitives and protocol engine.
//!
//! This is deliberately independent of platform TUN/TAP APIs. It gives callers a typed starting
//! point for building a WireGuard device and leaves the actual packet interface to the surrounding
//! Rama application. Scheduling is supplied by the caller.

use ahash::{HashMap, HashMapExt as _};
use core::marker::PhantomData;
use std::vec::Vec;

use rama_net::{
    address::{SocketAddress, ip::ipnet::IpNet},
    ip::IpPrefixMap,
};

use zerocopy::IntoBytes;

use crate::{
    crypto::{
        CookieState, DecryptionKey, EncryptionKey, EphemeralPrivateKey, HandshakeState, HasMac,
        Key, PublicKey, StaticInitiatorConfig, StaticPeerConfig, WireGuardCrypto,
        decrypt_cookie_reply, decrypt_handshake_initiation, decrypt_handshake_response,
        encrypt_cookie_reply, encrypt_handshake_initiation_with_cookie,
        encrypt_handshake_response_with_cookie,
    },
    proto::{
        Cookie, CookieReply, DecodeError, HandshakeInitiation, HandshakeResponse, MAC_SIZE,
        MSG_TRANSPORT_DATA, Mac, Tai64n, TransportHeader, TransportPacket,
    },
};

/// A stable, never-reused identifier for a configured peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PeerId(usize);

/// A peer's public configuration.
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub preshared_key: Option<Key>,
    pub endpoint: Option<SocketAddress>,
    /// Prefixes routed to this peer and accepted as sources from it.
    pub allowed_ips: Vec<IpNet>,
}
impl Drop for PeerConfig {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.preshared_key);
    }
}

/// A small device configuration and handshake coordinator.
pub struct Device<C> {
    identity: StaticInitiatorConfig,
    peers: HashMap<PeerId, ConfiguredPeer>,
    next_peer: usize,
    routes: IpPrefixMap<PeerId>,
    _crypto: PhantomData<fn() -> C>,
}

// Keep routing ownership and cryptographic configuration in one peer record.
struct ConfiguredPeer {
    config: StaticPeerConfig,
    allowed_ips: Vec<IpNet>,
    cookie: Option<Cookie>,
    last_timestamp: Option<Tai64n>,
}

impl<C: WireGuardCrypto> Device<C> {
    /// Creates a device with a static private key.
    #[must_use]
    pub fn new(private_key: crate::StaticPrivateKey) -> Self {
        Self {
            identity: StaticInitiatorConfig::new_with_crypto::<C>(private_key),
            peers: HashMap::new(),
            next_peer: 0,
            routes: IpPrefixMap::new(),
            _crypto: PhantomData,
        }
    }

    /// Adds a peer with a unique public key and a never-reused identifier.
    pub fn add_peer(&mut self, config: &PeerConfig) -> Result<PeerId, DeviceError> {
        if self
            .peers
            .values()
            .any(|peer| peer.config.key == config.public_key)
        {
            return Err(DeviceError::DuplicatePeer);
        }
        let next = self
            .next_peer
            .checked_add(1)
            .ok_or(DeviceError::PeerSpaceExhausted)?;
        let id = PeerId(self.next_peer);
        self.next_peer = next;
        for prefix in &config.allowed_ips {
            self.routes.insert(*prefix, id);
        }
        self.peers.insert(
            id,
            ConfiguredPeer {
                config: StaticPeerConfig::new_with_crypto::<C>(
                    config.public_key,
                    config.preshared_key,
                    config.endpoint.map(SocketAddress::into_std),
                ),
                allowed_ips: config.allowed_ips.clone(),
                cookie: None,
                last_timestamp: None,
            },
        );
        Ok(id)
    }

    /// Removes peer configuration and its routes without disturbing transferred prefixes.
    pub fn remove_peer(&mut self, peer: PeerId) -> Result<(), DeviceError> {
        let removed = self.peers.remove(&peer).ok_or(DeviceError::UnknownPeer)?;
        for prefix in removed.allowed_ips {
            if let Some(owner) = self.routes.remove(prefix)
                && owner != peer
            {
                self.routes.insert(prefix, owner);
            }
        }
        Ok(())
    }

    /// Finds the peer owning the most specific prefix for an IP address.
    #[must_use]
    pub fn peer_for_ip(&self, address: core::net::IpAddr) -> Option<PeerId> {
        self.routes.longest_match(address).map(|(_, peer)| *peer)
    }

    /// Returns the number of currently configured peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns the local static public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.identity.public_key
    }

    /// Returns the configured endpoint for a peer, if one exists.
    #[must_use]
    pub fn peer_endpoint(&self, peer: PeerId) -> Option<SocketAddress> {
        self.peers
            .get(&peer)
            .map(|peer| &peer.config)
            .and_then(|peer| peer.endpoint.map(SocketAddress::from))
    }

    /// Updates the endpoint learned from an authenticated packet.
    pub fn set_peer_endpoint(
        &mut self,
        peer: PeerId,
        endpoint: SocketAddress,
    ) -> Result<(), DeviceError> {
        let peer = self
            .peers
            .get_mut(&peer)
            .map(|peer| &mut peer.config)
            .ok_or(DeviceError::UnknownPeer)?;
        peer.endpoint = Some(endpoint.into_std());
        Ok(())
    }

    /// Starts an initiator handshake with a configured peer.
    pub fn initiate_handshake(
        &self,
        peer: PeerId,
        sender: u32,
        timestamp: Tai64n,
        ephemeral: EphemeralPrivateKey,
    ) -> Result<InitiatorHandshake, DeviceError> {
        let peer_config = self.peers.get(&peer).ok_or(DeviceError::UnknownPeer)?;
        let mut state = HandshakeState::default();
        let message = encrypt_handshake_initiation_with_cookie::<C>(
            &mut state,
            &self.identity,
            &peer_config.config,
            &ephemeral,
            timestamp,
            sender,
            peer_config.cookie.as_ref(),
        )?;
        Ok(InitiatorHandshake {
            peer,
            sender,
            ephemeral,
            state,
            message,
        })
    }

    /// Completes an initiator handshake and returns the transport keys.
    pub fn complete_handshake(
        &self,
        handshake: &InitiatorHandshake,
        response: &mut HandshakeResponse,
    ) -> Result<TransportSession<C>, DeviceError> {
        let peer_config = self
            .peers
            .get(&handshake.peer)
            .map(|peer| &peer.config)
            .ok_or(DeviceError::UnknownPeer)?;
        if response.receiver.get() != handshake.sender {
            return Err(DeviceError::WrongReceiver);
        }
        response.verify_mac1::<C>(&self.identity.mac1_key)?;
        let mut state = handshake.state.clone();
        decrypt_handshake_response::<C>(
            response,
            &mut state,
            &self.identity,
            peer_config,
            &handshake.ephemeral,
        )?;
        let (encrypt, decrypt) = state.split::<C>(true);
        Ok(TransportSession {
            send_receiver: response.sender.get(),
            local_receiver: handshake.sender,
            encrypt,
            decrypt,
            _crypto: PhantomData,
        })
    }

    /// Creates a cookie reply for a valid handshake message.
    ///
    /// Load detection is intentionally left to the caller. The caller supplies the current
    /// cookie state, source address, and a fresh random nonce when it decides to challenge a peer.
    pub fn create_cookie_reply(
        &self,
        cookie_state: &CookieState,
        source: SocketAddress,
        message: &HandshakeInitiation,
        nonce: [u8; 24],
    ) -> Result<CookieReply, DeviceError> {
        message.verify_mac1::<C>(&self.identity.mac1_key)?;
        let cookie = cookie_state.new_cookie::<C>(source.into_std());
        Ok(encrypt_cookie_reply::<C>(
            &self.identity.cookie_key,
            message.sender.get(),
            &message.mac1,
            cookie,
            nonce,
        ))
    }

    /// Accepts a cookie reply for an outstanding initiation and caches the cookie for that peer.
    pub fn accept_cookie_reply(
        &mut self,
        handshake: &InitiatorHandshake,
        reply: &CookieReply,
    ) -> Result<(), DeviceError> {
        if reply.receiver.get() != handshake.sender {
            return Err(DeviceError::WrongReceiver);
        }
        self.accept_cookie_for_peer(handshake.peer, &handshake.message.mac1, reply)
    }

    fn accept_cookie_for_peer(
        &mut self,
        peer: PeerId,
        mac1: &Mac,
        reply: &CookieReply,
    ) -> Result<(), DeviceError> {
        let peer = self.peers.get_mut(&peer).ok_or(DeviceError::UnknownPeer)?;
        let cookie = decrypt_cookie_reply::<C>(&peer.config.cookie_key, mac1, reply)?;
        peer.cookie = Some(cookie);
        Ok(())
    }

    /// Accepts an incoming handshake initiation for the matching configured peer.
    pub fn accept_handshake(
        &mut self,
        initiation: &mut HandshakeInitiation,
        sender: u32,
        ephemeral: &EphemeralPrivateKey,
    ) -> Result<(HandshakeResponse, TransportSession<C>), DeviceError> {
        self.accept_handshake_with_cookie(initiation, sender, ephemeral, None)
    }

    /// Accepts an incoming handshake initiation, optionally requiring a source-bound cookie.
    pub fn accept_handshake_with_cookie(
        &mut self,
        initiation: &mut HandshakeInitiation,
        sender: u32,
        ephemeral: &EphemeralPrivateKey,
        cookie: Option<&Cookie>,
    ) -> Result<(HandshakeResponse, TransportSession<C>), DeviceError> {
        let (_, response, session) =
            self.accept_handshake_with_cookie_for_peer(initiation, sender, ephemeral, cookie)?;
        Ok((response, session))
    }

    /// Accepts an incoming handshake and also returns the matching peer.
    ///
    /// This is useful to stateful endpoint implementations that need to associate the newly
    /// created transport session with the configured peer.
    pub fn accept_handshake_with_cookie_for_peer(
        &mut self,
        initiation: &mut HandshakeInitiation,
        sender: u32,
        ephemeral: &EphemeralPrivateKey,
        cookie: Option<&Cookie>,
    ) -> Result<(PeerId, HandshakeResponse, TransportSession<C>), DeviceError> {
        let mut state = HandshakeState::default();
        initiation.verify_mac1::<C>(&self.identity.mac1_key)?;
        if let Some(cookie) = cookie {
            initiation.verify_mac2::<C>(cookie)?;
        }
        let decrypted = decrypt_handshake_initiation::<C>(initiation, &mut state, &self.identity)?;
        let peer = self
            .peers
            .iter()
            .find_map(|(id, peer)| (peer.config.key == decrypted.static_key).then_some(*id))
            .ok_or(DeviceError::UnknownPeer)?;
        let peer_config = self.peers.get_mut(&peer).ok_or(DeviceError::UnknownPeer)?;
        if peer_config
            .last_timestamp
            .is_some_and(|last| decrypted.timestamp <= last)
        {
            return Err(DeviceError::TimestampReplay);
        }
        let response = encrypt_handshake_response_with_cookie::<C>(
            &mut state,
            &decrypted,
            ephemeral,
            &peer_config.config,
            sender,
            peer_config.cookie.as_ref(),
        )?;
        peer_config.last_timestamp = Some(decrypted.timestamp);
        let (encrypt, decrypt) = state.split::<C>(false);
        let session = TransportSession {
            send_receiver: initiation.sender.get(),
            local_receiver: response.sender.get(),
            encrypt,
            decrypt,
            _crypto: PhantomData,
        };
        Ok((peer, response, session))
    }
}

/// State retained between an initiation and its response.
pub struct InitiatorHandshake {
    pub peer: PeerId,
    pub sender: u32,
    pub ephemeral: EphemeralPrivateKey,
    pub state: HandshakeState,
    pub message: HandshakeInitiation,
}

/// Established transport state for one peer session.
pub struct TransportSession<C> {
    send_receiver: u32,
    local_receiver: u32,
    encrypt: EncryptionKey,
    decrypt: DecryptionKey,
    _crypto: PhantomData<fn() -> C>,
}

impl<C: WireGuardCrypto> TransportSession<C> {
    /// Encrypts and frames one transport datagram. Payloads are padded to a 16-byte boundary.
    pub fn encrypt_datagram(&mut self, payload: &[u8]) -> Result<Vec<u8>, DeviceError> {
        let mut datagram = vec![0; transport_datagram_len(payload.len())];
        self.encrypt_datagram_into(payload, &mut datagram)?;
        Ok(datagram)
    }

    fn encrypt_datagram_into<'a>(
        &mut self,
        payload: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], DeviceError> {
        let padded_len = (payload.len() + 15) & !15;
        let datagram = buffer
            .get_mut(..transport_datagram_len(payload.len()))
            .ok_or(DeviceError::Decode(DecodeError::InvalidTransportLength))?;
        datagram[16..16 + payload.len()].copy_from_slice(payload);
        // The caller may be reusing storage containing an earlier packet.
        datagram[16 + payload.len()..16 + padded_len].fill(0);
        let tag = self
            .encrypt
            .encrypt::<C>(&mut datagram[16..16 + padded_len])?;
        datagram[16 + padded_len..].copy_from_slice(&tag.0);
        let header = TransportHeader {
            message_type: zerocopy::little_endian::U32::new(MSG_TRANSPORT_DATA),
            receiver: zerocopy::little_endian::U32::new(self.send_receiver),
            counter: zerocopy::little_endian::U64::new(self.encrypt.counter() - 1),
        };
        datagram[..16].copy_from_slice(header.as_bytes());
        Ok(datagram)
    }

    /// Returns the next outgoing transport counter.
    #[must_use]
    pub fn send_counter(&self) -> u64 {
        self.encrypt.counter()
    }

    /// Decrypts one transport datagram and returns its padded plaintext.
    ///
    /// WireGuard transport packets do not carry an application payload length. Callers should
    /// parse the returned network-layer packet or otherwise apply their own framing instead of
    /// stripping trailing zero bytes here.
    pub fn decrypt_datagram(&mut self, datagram: &mut [u8]) -> Result<Vec<u8>, DeviceError> {
        let packet = TransportPacket::decode(datagram).map_err(DeviceError::Decode)?;
        self.decrypt_packet(&packet)
    }

    /// Authenticates and decrypts a transport datagram in its original storage.
    /// Returns padded plaintext borrowing the input. On error, input bytes may
    /// have changed; unauthenticated data must not be used. Failed authentication
    /// does not consume the replay counter.
    pub fn decrypt_datagram_in_place<'a>(
        &mut self,
        datagram: &'a mut [u8],
    ) -> Result<&'a mut [u8], DeviceError> {
        let packet = TransportPacket::decode(datagram).map_err(DeviceError::Decode)?;
        self.decrypt_packet_in_place(packet)
    }

    fn decrypt_packet_in_place<'a>(
        &mut self,
        packet: TransportPacket<'a>,
    ) -> Result<&'a mut [u8], DeviceError> {
        if packet.receiver() != self.local_receiver {
            return Err(DeviceError::WrongReceiver);
        }
        let TransportPacket {
            header,
            payload,
            tag,
        } = packet;
        self.decrypt
            .decrypt_detached::<C>(header.counter.get(), payload, tag)?;
        Ok(payload)
    }

    /// Decrypts an already-decoded transport packet.
    pub fn decrypt_packet(&mut self, packet: &TransportPacket<'_>) -> Result<Vec<u8>, DeviceError> {
        if packet.receiver() != self.local_receiver {
            return Err(DeviceError::WrongReceiver);
        }
        let mut body = packet.payload.to_vec();
        self.decrypt
            .decrypt_detached::<C>(packet.counter(), &mut body, packet.tag)?;
        Ok(body)
    }

    /// Returns the receiver identifier used in outgoing packets.
    #[must_use]
    pub const fn receiver(&self) -> u32 {
        self.send_receiver
    }

    /// Returns the local receiver identifier used to look up incoming packets.
    #[must_use]
    pub const fn local_receiver(&self) -> u32 {
        self.local_receiver
    }
}

fn transport_datagram_len(payload_len: usize) -> usize {
    16 + ((payload_len + 15) & !15) + MAC_SIZE
}

/// Errors returned by device-level operations.
#[derive(Debug)]
pub enum DeviceError {
    DuplicatePeer,
    PeerSpaceExhausted,
    UnknownPeer,
    WrongReceiver,
    TimestampReplay,
    Decode(DecodeError),
    Crypto(crate::CryptoError),
}

impl core::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicatePeer => f.write_str("peer public key is already registered"),
            Self::PeerSpaceExhausted => f.write_str("peer identifier space exhausted"),
            Self::UnknownPeer => f.write_str("unknown WireGuard peer"),
            Self::WrongReceiver => f.write_str("packet receiver does not match the session"),
            Self::TimestampReplay => {
                f.write_str("handshake timestamp is not newer than the last accepted timestamp")
            }
            Self::Decode(error) => error.fmt(f),
            Self::Crypto(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crate::CryptoError> for DeviceError {
    fn from(error: crate::CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{BuiltinCrypto, CookieState},
        proto::KEY_SIZE,
    };

    #[test]
    fn removing_routes_preserves_transferred_prefixes_and_other_peers() {
        let mut device =
            Device::<BuiltinCrypto>::new(crate::StaticPrivateKey::from_bytes([51; 32]));
        let first_key =
            BuiltinCrypto::x25519_pubkey(&crate::StaticPrivateKey::from_bytes([52; 32]));
        let second_key =
            BuiltinCrypto::x25519_pubkey(&crate::StaticPrivateKey::from_bytes([53; 32]));
        let first = device
            .add_peer(&PeerConfig {
                public_key: first_key,
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec![
                    "10.0.0.0/24".parse().unwrap(),
                    "10.0.0.2/32".parse().unwrap(),
                    "fd00::/64".parse().unwrap(),
                ],
            })
            .unwrap();
        let second = device
            .add_peer(&PeerConfig {
                public_key: second_key,
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec![
                    "10.0.0.2/32".parse().unwrap(),
                    "fd00::2/128".parse().unwrap(),
                ],
            })
            .unwrap();
        device.remove_peer(first).unwrap();
        assert_eq!(
            device.peer_for_ip("10.0.0.2".parse().unwrap()),
            Some(second)
        );
        assert_eq!(device.peer_for_ip("fd00::2".parse().unwrap()), Some(second));
        assert!(device.peer_for_ip("10.0.0.3".parse().unwrap()).is_none());
        assert!(device.peer_for_ip("fd00::3".parse().unwrap()).is_none());
        device.remove_peer(second).unwrap();
        assert!(device.routes.is_empty());
        let replacement = device
            .add_peer(&PeerConfig {
                public_key: first_key,
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec![],
            })
            .unwrap();
        assert_ne!(replacement, first);
        assert_ne!(replacement, second);
    }

    #[test]
    fn device_accepts_and_round_trips_transport_data() {
        let mut client =
            Device::<BuiltinCrypto>::new(crate::StaticPrivateKey::from_bytes([1; KEY_SIZE]));
        let mut server =
            Device::<BuiltinCrypto>::new(crate::StaticPrivateKey::from_bytes([2; KEY_SIZE]));
        let client_config = PeerConfig {
            public_key: server.public_key(),
            preshared_key: Some([3; KEY_SIZE]),
            endpoint: None,
            allowed_ips: Vec::new(),
        };
        let server_config = PeerConfig {
            public_key: client.public_key(),
            preshared_key: Some([3; KEY_SIZE]),
            endpoint: None,
            allowed_ips: Vec::new(),
        };
        let client_peer = client.add_peer(&client_config).unwrap();
        let server_peer = server.add_peer(&server_config).unwrap();
        assert_eq!(client_peer, PeerId(0));
        assert_eq!(server_peer, PeerId(0));

        let mut initiation = client
            .initiate_handshake(
                client_peer,
                10,
                Tai64n::from_bytes([4; 12]),
                EphemeralPrivateKey::from_bytes([5; KEY_SIZE]),
            )
            .unwrap();
        let (mut response, mut server_session) = server
            .accept_handshake(
                &mut initiation.message,
                20,
                &EphemeralPrivateKey::from_bytes([6; KEY_SIZE]),
            )
            .unwrap();
        let mut client_session = client
            .complete_handshake(&initiation, &mut response)
            .unwrap();

        let mut packet = client_session.encrypt_datagram(b"hello").unwrap();
        let plaintext = server_session.decrypt_datagram(&mut packet).unwrap();
        assert_eq!(&plaintext[..5], b"hello");
        assert!(plaintext[5..].iter().all(|byte| *byte == 0));

        let mut packet = client_session.encrypt_datagram(b"in place").unwrap();
        let plaintext_start = packet[16..].as_ptr();
        let plaintext = server_session
            .decrypt_datagram_in_place(&mut packet)
            .unwrap();
        assert_eq!(plaintext.as_ptr(), plaintext_start);
        assert_eq!(&plaintext[..8], b"in place");
        assert!(plaintext[8..].iter().all(|byte| *byte == 0));

        let mut replay = client
            .initiate_handshake(
                client_peer,
                11,
                Tai64n::from_bytes([4; 12]),
                EphemeralPrivateKey::from_bytes([7; KEY_SIZE]),
            )
            .unwrap();
        assert!(matches!(
            server.accept_handshake(
                &mut replay.message,
                21,
                &EphemeralPrivateKey::from_bytes([8; KEY_SIZE]),
            ),
            Err(DeviceError::TimestampReplay)
        ));
    }

    #[test]
    fn cookie_reply_is_cached_and_applied_to_next_handshake() {
        let mut client =
            Device::<BuiltinCrypto>::new(crate::StaticPrivateKey::from_bytes([1; KEY_SIZE]));
        let mut server =
            Device::<BuiltinCrypto>::new(crate::StaticPrivateKey::from_bytes([2; KEY_SIZE]));
        let server_addr = SocketAddress::local_ipv4(51820);
        let client_peer = client
            .add_peer(&PeerConfig {
                public_key: server.public_key(),
                preshared_key: Some([3; KEY_SIZE]),
                endpoint: Some(server_addr),
                allowed_ips: Vec::new(),
            })
            .unwrap();
        let _server_peer = server
            .add_peer(&PeerConfig {
                public_key: client.public_key(),
                preshared_key: Some([3; KEY_SIZE]),
                endpoint: None,
                allowed_ips: Vec::new(),
            })
            .unwrap();

        let initial = client
            .initiate_handshake(
                client_peer,
                10,
                Tai64n::from_bytes([4; 12]),
                EphemeralPrivateKey::from_bytes([5; KEY_SIZE]),
            )
            .unwrap();
        let cookie_state = CookieState::new([9; KEY_SIZE]);
        let reply = server
            .create_cookie_reply(&cookie_state, server_addr, &initial.message, [7; 24])
            .unwrap();
        client.accept_cookie_reply(&initial, &reply).unwrap();

        let mut retried = client
            .initiate_handshake(
                client_peer,
                11,
                Tai64n::from_bytes([4; 12]),
                EphemeralPrivateKey::from_bytes([6; KEY_SIZE]),
            )
            .unwrap();
        let cookie = cookie_state.new_cookie::<BuiltinCrypto>(server_addr.into_std());
        retried
            .message
            .verify_mac2::<BuiltinCrypto>(&cookie)
            .unwrap();
        let (mut response, _session) = server
            .accept_handshake_with_cookie(
                &mut retried.message,
                20,
                &EphemeralPrivateKey::from_bytes([8; KEY_SIZE]),
                Some(&cookie),
            )
            .unwrap();
        // A cookie issued by this responder authenticates incoming initiations,
        // not its outgoing response. It has not received a cookie from the client.
        assert_eq!(response.mac2, [0; MAC_SIZE]);
        client.complete_handshake(&retried, &mut response).unwrap();
    }
}
