//! WireGuard wire formats, Noise IKpsk2, transport encryption and replay protection.
//! Cryptographic randomness is supplied by the caller. The built-in provider uses RustCrypto.
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub mod crypto;
pub mod proto;

pub use crypto::{
    BuiltinCrypto, CookieState, CryptoError, EphemeralPrivateKey, Key, PublicKey, StaticPrivateKey,
    WireGuardCrypto,
};
pub use proto::Tai64n;
