//! WireGuard's fixed wire layouts and packet framing.

use core::{fmt, mem::size_of};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, little_endian};

/// Handshake initiation message type.
pub const MSG_HANDSHAKE_INITIATION: u32 = 1;
/// Handshake response message type.
pub const MSG_HANDSHAKE_RESPONSE: u32 = 2;
/// Cookie reply message type.
pub const MSG_COOKIE_REPLY: u32 = 3;
/// Transport data message type.
pub const MSG_TRANSPORT_DATA: u32 = 4;

/// The length of a WireGuard MAC or AEAD tag.
pub const MAC_SIZE: usize = 16;
/// The length of a WireGuard key or public key.
pub const KEY_SIZE: usize = 32;
/// The length of a WireGuard handshake timestamp.
pub const TIMESTAMP_SIZE: usize = 12;

pub type Mac = [u8; MAC_SIZE];

/// A TAI64N timestamp used for WireGuard handshake freshness.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
#[repr(transparent)]
pub struct Tai64n(pub [u8; TIMESTAMP_SIZE]);

impl Tai64n {
    /// Constructs a timestamp from its wire representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TIMESTAMP_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the wire representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TIMESTAMP_SIZE] {
        &self.0
    }

    /// Encodes a Unix duration as a TAI64N timestamp.
    #[must_use]
    pub fn from_unix_duration(duration: core::time::Duration) -> Self {
        let seconds = 0x4000_0000_0000_000au64.saturating_add(duration.as_secs());
        let mut bytes = [0; TIMESTAMP_SIZE];
        bytes[..8].copy_from_slice(&seconds.to_be_bytes());
        bytes[8..].copy_from_slice(&duration.subsec_nanos().to_be_bytes());
        Self(bytes)
    }
}

/// An AEAD authentication tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct Tag(pub [u8; MAC_SIZE]);

/// A cookie authenticated by a MAC.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct Cookie(pub Mac);

/// An encrypted zero-length handshake payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedEmpty {
    pub msg: [u8; 0],
    pub tag: Tag,
}

/// An encrypted TAI64N timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedTimestamp {
    pub msg: [u8; TIMESTAMP_SIZE],
    pub tag: Tag,
}

/// An encrypted static public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedPublicKey {
    pub msg: [u8; KEY_SIZE],
    pub tag: Tag,
}

/// An encrypted cookie reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedCookie {
    pub msg: Cookie,
    pub tag: Tag,
}

/// WireGuard handshake initiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(4))]
pub struct HandshakeInitiation {
    /// Must be [`MSG_HANDSHAKE_INITIATION`].
    pub message_type: little_endian::U32,
    /// Identifier for this handshake session.
    pub sender: little_endian::U32,
    /// Initiator ephemeral X25519 public key.
    pub ephemeral_key: [u8; KEY_SIZE],
    /// Initiator static public key encrypted under the Noise handshake.
    pub static_key: EncryptedPublicKey,
    /// Current TAI64N timestamp encrypted under the Noise handshake.
    pub timestamp: EncryptedTimestamp,
    /// Fast MAC keyed by the responder's static public key.
    pub mac1: Mac,
    /// Cookie MAC used during responder overload.
    pub mac2: Mac,
}

/// WireGuard handshake response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(4))]
pub struct HandshakeResponse {
    /// Must be [`MSG_HANDSHAKE_RESPONSE`].
    pub message_type: little_endian::U32,
    /// Identifier for this response session.
    pub sender: little_endian::U32,
    /// The initiation sender identifier being answered.
    pub receiver: little_endian::U32,
    /// Responder ephemeral X25519 public key.
    pub ephemeral_key: [u8; KEY_SIZE],
    /// Encrypted empty payload used to authenticate the response.
    pub empty: EncryptedEmpty,
    /// Fast MAC keyed by the initiator's static public key.
    pub mac1: Mac,
    /// Cookie MAC used during initiator overload.
    pub mac2: Mac,
}

/// WireGuard cookie reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(4))]
pub struct CookieReply {
    /// Must be [`MSG_COOKIE_REPLY`].
    pub message_type: little_endian::U32,
    /// Identifier from the handshake message being challenged.
    pub receiver: little_endian::U32,
    /// Random XChaCha20 nonce.
    pub nonce: [u8; 24],
    /// Cookie encrypted for the recipient.
    pub cookie: EncryptedCookie,
}

/// WireGuard transport-data header.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(8))]
pub struct TransportHeader {
    /// Must be [`MSG_TRANSPORT_DATA`].
    pub message_type: little_endian::U32,
    /// Receiver identifier from the completed handshake.
    pub receiver: little_endian::U32,
    /// Monotonically increasing transport nonce.
    pub counter: little_endian::U64,
}

/// A decoded transport packet borrowing the payload and tag from the input buffer.
pub struct TransportPacket<'a> {
    pub header: TransportHeader,
    pub payload: &'a mut [u8],
    pub tag: &'a mut [u8; MAC_SIZE],
}

impl<'a> TransportPacket<'a> {
    /// Splits a transport packet into its copied header and mutable ciphertext/tag.
    pub fn decode(buffer: &'a mut [u8]) -> Result<Self, DecodeError> {
        if buffer.len() < size_of::<TransportHeader>() + MAC_SIZE {
            return Err(DecodeError::InvalidTransportLength);
        }

        let (header, body) = buffer.split_at_mut(size_of::<TransportHeader>());
        let message_type = header[0..4]
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_error| DecodeError::InvalidTransportLength)?;
        let receiver = header[4..8]
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_error| DecodeError::InvalidTransportLength)?;
        let counter = header[8..16]
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_error| DecodeError::InvalidTransportLength)?;
        let header = TransportHeader {
            message_type: little_endian::U32::new(message_type),
            receiver: little_endian::U32::new(receiver),
            counter: little_endian::U64::new(counter),
        };
        if header.message_type.get() != MSG_TRANSPORT_DATA {
            return Err(DecodeError::UnexpectedMessageType);
        }

        let (payload, tag) = body.split_at_mut(body.len() - MAC_SIZE);
        let tag = <&mut [u8; MAC_SIZE]>::try_from(tag)
            .map_err(|_error| DecodeError::InvalidTransportLength)?;
        Ok(Self {
            header,
            payload,
            tag,
        })
    }

    /// Returns the packet's counter as a host-endian integer.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.header.counter.get()
    }

    /// Returns the packet's receiver identifier.
    #[must_use]
    pub fn receiver(&self) -> u32 {
        self.header.receiver.get()
    }
}

/// A message decoded from a mutable datagram buffer.
pub enum Message<'a> {
    HandshakeInitiation(&'a mut HandshakeInitiation),
    HandshakeResponse(&'a mut HandshakeResponse),
    CookieReply(&'a mut CookieReply),
    Transport(TransportPacket<'a>),
}

impl<'a> Message<'a> {
    /// Decodes a complete WireGuard datagram.
    pub fn decode(buffer: &'a mut [u8]) -> Result<Self, DecodeError> {
        let message_type = buffer
            .get(..4)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_error| DecodeError::Truncated)?;

        match message_type {
            MSG_HANDSHAKE_INITIATION => HandshakeInitiation::mut_from_bytes(buffer)
                .map(Self::HandshakeInitiation)
                .map_err(|_error| DecodeError::InvalidHandshakeInitiation),
            MSG_HANDSHAKE_RESPONSE => HandshakeResponse::mut_from_bytes(buffer)
                .map(Self::HandshakeResponse)
                .map_err(|_error| DecodeError::InvalidHandshakeResponse),
            MSG_COOKIE_REPLY => CookieReply::mut_from_bytes(buffer)
                .map(Self::CookieReply)
                .map_err(|_error| DecodeError::InvalidCookieReply),
            MSG_TRANSPORT_DATA => TransportPacket::decode(buffer).map(Self::Transport),
            _ => Err(DecodeError::UnexpectedMessageType),
        }
    }
}

/// Errors returned by the packet decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated,
    UnexpectedMessageType,
    InvalidHandshakeInitiation,
    InvalidHandshakeResponse,
    InvalidCookieReply,
    InvalidTransportLength,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated WireGuard message",
            Self::UnexpectedMessageType => "unexpected WireGuard message type",
            Self::InvalidHandshakeInitiation => "invalid WireGuard handshake initiation",
            Self::InvalidHandshakeResponse => "invalid WireGuard handshake response",
            Self::InvalidCookieReply => "invalid WireGuard cookie reply",
            Self::InvalidTransportLength => "invalid WireGuard transport length",
        })
    }
}

const _: () = assert!(size_of::<HandshakeInitiation>() == 148);
const _: () = assert!(size_of::<HandshakeResponse>() == 92);
const _: () = assert!(size_of::<CookieReply>() == 64);
const _: () = assert!(size_of::<TransportHeader>() == 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_sizes_match_protocol() {
        assert_eq!(size_of::<HandshakeInitiation>(), 148);
        assert_eq!(size_of::<HandshakeResponse>(), 92);
        assert_eq!(size_of::<CookieReply>(), 64);
        assert_eq!(size_of::<TransportHeader>(), 16);
    }

    #[test]
    fn transport_packet_rejects_bad_lengths() {
        let mut packet = [0; 31];
        packet[..4].copy_from_slice(&MSG_TRANSPORT_DATA.to_le_bytes());
        assert!(matches!(
            Message::decode(&mut packet),
            Err(DecodeError::InvalidTransportLength)
        ));
    }

    #[test]
    fn transport_accepts_padding_capped_at_a_non_aligned_mtu() {
        let mut packet = vec![0; 1500 + 32];
        packet[..4].copy_from_slice(&MSG_TRANSPORT_DATA.to_le_bytes());
        let packet = TransportPacket::decode(&mut packet).unwrap();
        assert_eq!(packet.payload.len(), 1500);
    }

    #[test]
    fn tai64n_encodes_unix_duration() {
        let timestamp = Tai64n::from_unix_duration(core::time::Duration::new(7, 11));
        assert_eq!(
            timestamp.as_bytes(),
            &[0x40, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 11]
        );
    }
}
