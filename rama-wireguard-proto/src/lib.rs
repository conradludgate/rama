//! Deterministic WireGuard protocol implementation for Rama.
//!
//! [`proto`] contains wire layouts, [`crypto`] provides Noise IKpsk2 and transport
//! keys, and [`device`] owns peer configuration, IP routing and protocol scheduling.
//! The engine accepts packets, monotonic time, handshake timestamps and ephemeral
//! keys explicitly. It performs no socket I/O and reads no clock; cryptographic
//! randomness is supplied by the caller.
//!
//! For the UDP driver, typed endpoints and Linux TUN adapter, use `rama-wireguard`.
//! This crate currently uses `std` and requires `rama-crypto/rustcrypto`.
//! The protocol work is initially based on
//! [`rustyguard`](https://github.com/conradludgate/rustyguard).

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub mod crypto;
pub mod device;
pub mod proto;

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
