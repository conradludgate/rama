//! Borrowed IP packet framing and basic header encoders.

use super::EcnCodepoint;
use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// A validated IPv4 or IPv6 packet, borrowing its wire bytes.
///
/// Parsing checks version and declared lengths and excludes trailing bytes such
/// as tunnel padding. IPv4 options and IPv6 extension headers remain opaque.
/// Header checksums, transport checksums, reassembly and IPv6 jumbograms are not
/// handled by this framing API.
#[derive(Clone, Copy, Debug)]
pub struct IpPacket<'a> {
    bytes: &'a [u8],
    header_len: usize,
}

impl<'a> IpPacket<'a> {
    /// Parses one IP packet and ignores bytes beyond its declared length.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IpPacketError> {
        let first = *bytes.first().ok_or(IpPacketError::Truncated)?;
        let (header_len, total) = match first >> 4 {
            4 => {
                let header = usize::from(first & 15) * 4;
                if header < 20 {
                    return Err(IpPacketError::InvalidLength);
                }
                if bytes.len() < header {
                    return Err(IpPacketError::Truncated);
                }
                (
                    header,
                    usize::from(u16::from_be_bytes([bytes[2], bytes[3]])),
                )
            }
            6 => {
                if bytes.len() < 40 {
                    return Err(IpPacketError::Truncated);
                }
                (
                    40,
                    40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
                )
            }
            _ => return Err(IpPacketError::UnsupportedVersion),
        };
        if total < header_len {
            return Err(IpPacketError::InvalidLength);
        }
        let bytes = bytes.get(..total).ok_or(IpPacketError::Truncated)?;
        Ok(Self { bytes, header_len })
    }

    /// Returns the complete packet without tunnel padding.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the bytes after the base IPv6 header or the IPv4 header/options.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    /// Returns 4 or 6.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.bytes[0] >> 4
    }

    /// Returns the source address.
    #[must_use]
    pub fn source(&self) -> IpAddr {
        self.address(true)
    }

    /// Returns the destination address.
    #[must_use]
    pub fn destination(&self) -> IpAddr {
        self.address(false)
    }

    fn address(&self, source: bool) -> IpAddr {
        if self.version() == 4 {
            let offset = if source { 12 } else { 16 };
            IpAddr::V4(Ipv4Addr::new(
                self.bytes[offset],
                self.bytes[offset + 1],
                self.bytes[offset + 2],
                self.bytes[offset + 3],
            ))
        } else {
            let offset = if source { 8 } else { 24 };
            IpAddr::V6(Ipv6Addr::from(core::array::from_fn::<_, 16, _>(|i| {
                self.bytes[offset + i]
            })))
        }
    }

    /// Returns the IPv4 protocol or the IPv6 base header's next-header value.
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.bytes[if self.version() == 4 { 9 } else { 6 }]
    }

    /// Returns the ECN bits without assigning protocol behavior.
    #[must_use]
    pub fn ecn(&self) -> EcnCodepoint {
        EcnCodepoint::from_bits(if self.version() == 4 {
            self.bytes[1]
        } else {
            self.bytes[1] >> 4
        })
    }
}

/// Basic IPv4 header parameters. Encoding uses no options or fragmentation.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4PacketHeader {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub ecn: EcnCodepoint,
}

impl Ipv4PacketHeader {
    /// Encodes a header and payload, including the IPv4 header checksum.
    pub fn encode<'a>(
        &self,
        payload: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a mut [u8], IpPacketError> {
        let length = payload
            .len()
            .checked_add(20)
            .filter(|&n| n <= usize::from(u16::MAX))
            .ok_or(IpPacketError::InvalidLength)?;
        let output = output
            .get_mut(..length)
            .ok_or(IpPacketError::BufferTooSmall)?;
        output[..20].fill(0);
        output[0] = 0x45;
        output[1] = self.ecn.bits();
        output[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        output[8] = self.ttl;
        output[9] = self.protocol;
        output[12..16].copy_from_slice(&self.source.octets());
        output[16..20].copy_from_slice(&self.destination.octets());
        let sum: u32 = output[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
            .sum();
        let sum = (sum & 0xffff) + (sum >> 16);
        let checksum = !((sum & 0xffff) + (sum >> 16)) as u16;
        output[10..12].copy_from_slice(&checksum.to_be_bytes());
        output[20..].copy_from_slice(payload);
        Ok(output)
    }
}

/// Basic IPv6 header parameters. Flow label and DSCP default to zero.
#[derive(Clone, Copy, Debug)]
pub struct Ipv6PacketHeader {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub ecn: EcnCodepoint,
}

impl Ipv6PacketHeader {
    /// Encodes a base header and payload, which may begin with extension headers.
    pub fn encode<'a>(
        &self,
        payload: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a mut [u8], IpPacketError> {
        let length: u16 = payload
            .len()
            .try_into()
            .map_err(|_error| IpPacketError::InvalidLength)?;
        let output = output
            .get_mut(..40 + usize::from(length))
            .ok_or(IpPacketError::BufferTooSmall)?;
        output[..40].fill(0);
        output[0] = 0x60;
        output[1] = self.ecn.bits() << 4;
        output[4..6].copy_from_slice(&length.to_be_bytes());
        output[6] = self.next_header;
        output[7] = self.hop_limit;
        output[8..24].copy_from_slice(&self.source.octets());
        output[24..40].copy_from_slice(&self.destination.octets());
        output[40..].copy_from_slice(payload);
        Ok(output)
    }
}

/// IP framing or encoding failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpPacketError {
    Truncated,
    UnsupportedVersion,
    InvalidLength,
    BufferTooSmall,
}
impl fmt::Display for IpPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IP packet: {self:?}")
    }
}
impl core::error::Error for IpPacketError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_encoding_checksum_and_padding() {
        let mut buffer = [0xff; 64];
        let h = Ipv4PacketHeader {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            protocol: 17,
            ttl: 64,
            ecn: EcnCodepoint::Ce,
        };
        assert_eq!(h.encode(b"abc", &mut buffer).unwrap().len(), 23);
        // Independent one's-complement validation of the encoded header.
        let sum: u32 = buffer[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
            .sum();
        assert_eq!((sum & 65535) + (sum >> 16), 65535);
        let packet = IpPacket::parse(&buffer).unwrap();
        assert_eq!(packet.source(), IpAddr::V4(h.source));
        assert_eq!(packet.destination(), IpAddr::V4(h.destination));
        assert_eq!(packet.payload(), b"abc");
        assert_eq!(packet.ecn(), EcnCodepoint::Ce);
        assert_eq!(packet.protocol(), 17);
        assert_eq!(
            h.encode(b"", &mut [0; 19]),
            Err(IpPacketError::BufferTooSmall)
        );
    }

    #[test]
    fn ipv6_and_invalid_lengths() {
        let mut buffer = [0; 64];
        let h = Ipv6PacketHeader {
            source: Ipv6Addr::LOCALHOST,
            destination: "2001:db8::1".parse().unwrap(),
            next_header: 58,
            hop_limit: 64,
            ecn: EcnCodepoint::Ect1,
        };
        h.encode(b"hello", &mut buffer).unwrap();
        let packet = IpPacket::parse(&buffer).unwrap();
        assert_eq!(packet.source(), IpAddr::V6(h.source));
        assert_eq!(packet.destination(), IpAddr::V6(h.destination));
        assert_eq!(packet.payload(), b"hello");
        assert_eq!(packet.ecn(), EcnCodepoint::Ect1);
        assert!(matches!(
            IpPacket::parse(&buffer[..44]),
            Err(IpPacketError::Truncated)
        ));
        assert!(matches!(
            IpPacket::parse(&[]),
            Err(IpPacketError::Truncated)
        ));
        buffer[0] = 0x44;
        assert!(matches!(
            IpPacket::parse(&buffer),
            Err(IpPacketError::InvalidLength)
        ));
        buffer[0] = 0x45;
        buffer[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert!(matches!(
            IpPacket::parse(&buffer),
            Err(IpPacketError::InvalidLength)
        ));
    }
}
