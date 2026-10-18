//! WireGuard protocol primitives and configured device state.
//! Device coordinates handshakes, transport sessions and allowed-IP routing without socket I/O.
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
pub use device::{Device, DeviceError, PeerConfig, PeerId};
pub use proto::Tai64n;
