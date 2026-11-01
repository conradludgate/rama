//! Deterministic WireGuard protocol building blocks for Rama.
//!
//! Initially based on <https://github.com/conradludgate/rustyguard>.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub mod proto;
pub use proto::Tai64n;
