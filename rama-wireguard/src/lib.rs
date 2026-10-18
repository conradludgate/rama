//! WireGuard protocol re-exports and manually driven Rama UDP adapters.
//! `rama-wireguard-proto` owns protocol state; [`transport`] and [`service`] execute UDP I/O.
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

pub use crypto::{
    BuiltinCrypto, CookieState, CryptoError, EphemeralPrivateKey, Key, PublicKey, StaticPrivateKey,
    WireGuardCrypto,
};
pub use device::{
    Device, DeviceError, EngineError, HandshakePolicy, PeerConfig, PeerId, TunnelPacket,
    WireGuardAction, WireGuardDatagram, WireGuardEngine, WireGuardMaintenance,
};
pub use proto::Tai64n;
pub use service::{ServiceError, TunnelServiceError, WireGuardService, WireGuardTunnelService};
pub use transport::DatagramTransport;
