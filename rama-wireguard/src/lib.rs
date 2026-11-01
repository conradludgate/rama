//! WireGuard endpoints and I/O adapters for Rama.
//!
//! [`rama_wireguard_proto`] owns wire formats, cryptography, peer configuration, IP
//! routing and the deterministic engine. Its common types and modules are re-exported here.
//! [`transport`] and [`service`] provide manually driven Rama UDP adapters. With
//! `runtime`, `endpoint` provides one socket driver and typed packet/peer endpoints.
//! The `linux_tun` example connects a packet endpoint to an OS interface.
//!
//! The built-in provider requires `rama-crypto/rustcrypto`. Custom providers can
//! implement [`WireGuardCrypto`]. The protocol work is initially based on
//! [`rustyguard`](https://github.com/conradludgate/rustyguard).

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub use rama_wireguard_proto::{crypto, device, proto};
pub mod service;
pub mod transport;

#[cfg(feature = "runtime")]
mod admission;
#[cfg(feature = "runtime")]
pub use admission::HandshakeAdmissionConfig;
#[cfg(feature = "runtime")]
pub mod endpoint;
#[cfg(feature = "runtime")]
pub use endpoint::{
    DriverError, Endpoint, EndpointConfig, EndpointDriver, EndpointError, PacketEndpoint,
    PacketMode, Peer, PeerEndpoint, PeerError, PeerMode, PeerPacket, ReceiveMode,
};

pub use crypto::{
    BuiltinCrypto, CookieState, CryptoError, EphemeralPrivateKey, Key, PublicKey, StaticPrivateKey,
    WireGuardCrypto,
};
pub use device::{
    Device, DeviceError, EngineError, HandshakePolicy, PeerConfig, PeerId, SendIntoError,
    TunnelPacket, TunnelPacketRef, WireGuardAction, WireGuardDatagram, WireGuardDatagramRef,
    WireGuardEngine, WireGuardMaintenance,
};
pub use proto::Tai64n;
pub use service::{ServiceError, TunnelServiceError, WireGuardService, WireGuardTunnelService};
pub use transport::DatagramTransport;
