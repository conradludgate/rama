//! WireGuard cryptographic provider and owned keys.
mod provider;
pub use provider::{BuiltinCrypto, CryptoError, Key, PublicKey, StaticPrivateKey, WireGuardCrypto};
