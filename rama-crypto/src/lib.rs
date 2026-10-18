//! Crypto primitives and dependencies used by rama.
//!
//! This includes but is not limited to:
//! - Certificates
//! - Javascript object signing and encryption (JOSE): JWS, JWK, JWE...
//! - Public and private keys
//! - Signing
//!
//! Enable `rustcrypto` for pure Rust primitives exported by `dep::rustcrypto`.
//! These exports include SHA-2, HMAC, HKDF, BLAKE2, ChaCha20Poly1305,
//! XChaCha20Poly1305, X25519 and zeroization utilities. This feature can be used
//! alongside the other crypto backends; it does not change their selection.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

mod asn1;

pub mod cert;

#[cfg(feature = "aws-lc")]
#[cfg_attr(docsrs, doc(cfg(feature = "aws-lc")))]
pub mod jose;

pub mod hmac;

pub mod pem;

pub mod pki_types {
    //! Pki types used by rama. Currently this is a re-export of the [`rustls-pki-types`][rustls_pki_types] crate.
    //!
    //! [`rustls_pki_types`]: https://docs.rs/rustls-pki-types

    #[doc(inline)]
    pub use rustls_pki_types::*;
}

#[cfg(feature = "native-certs")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-certs")))]
pub mod native_certs;

pub mod ocsp;

pub mod crl;

pub mod dep {
    //! Dependencies for rama crypto modules.
    //!
    //! Exported for your convenience

    /// Pure Rust cryptographic primitives used by Rama.
    ///
    /// Enable `rustcrypto` to use these crates directly alongside Rama's helpers.
    /// The hash, MAC and KDF crates share the same `digest` traits. BLAKE2 requires
    /// [`hmac::SimpleHmac`] and [`hkdf::SimpleHkdf`] rather than their eager variants.
    #[cfg(feature = "rustcrypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
    pub mod rustcrypto {
        #[doc(inline)]
        pub use blake2::digest;
        #[doc(inline)]
        pub use chacha20poly1305::aead;
        #[doc(inline)]
        pub use {blake2, chacha20poly1305, hkdf, hmac, sha2, x25519_dalek, zeroize};
    }

    #[cfg(feature = "aws-lc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "aws-lc")))]
    pub mod aws_lc_rs {
        //! Re-export of the [`aws-lc-rs`] crate.
        //!
        //! [`aws-lc-rs`]: https://docs.rs/aws-lc-rs

        #[doc(inline)]
        pub use aws_lc_rs::*;
    }

    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub mod ring {
        //! Re-export of the [`ring`] crate.
        //!
        //! [`ring`]: https://docs.rs/ring

        #[doc(inline)]
        pub use ring::*;
    }

    #[cfg(feature = "boring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
    pub mod boring {
        //! Re-export of the [`rama-boring`] crate.
        //!
        //! [`rama-boring`]: https://docs.rs/rama-boring

        #[doc(inline)]
        pub use rama_boring::*;
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "aws-lc", feature = "ring"))))]
    pub mod rcgen {
        //! Re-export of the [`rcgen`] crate.
        //!
        //! [`rcgen`]: https://docs.rs/rcgen

        #[doc(inline)]
        pub use rcgen::*;
    }

    pub mod x509_parser {
        //! Re-export of the [`x509_parser`] crate.
        //!
        //! [`x509_parser`]: https://docs.rs/x509_parser

        #[doc(inline)]
        pub use x509_parser::*;
    }
}

#[cfg(all(feature = "inspect", feature = "boring"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "inspect", feature = "boring"))))]
pub mod inspect;
