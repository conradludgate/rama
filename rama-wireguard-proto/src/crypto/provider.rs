//! WireGuard's provider-neutral cryptographic contract and built-in backend.

use rama_crypto::dep::rustcrypto::{
    blake2::{Blake2s256, Blake2sMac, Digest as _, digest::consts::U16},
    chacha20poly1305::{AeadInOut as _, ChaCha20Poly1305, KeyInit as _, XChaCha20Poly1305},
    hkdf::SimpleHkdf,
    hmac::Mac as _,
    x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A WireGuard symmetric key.
pub type Key = [u8; 32];

/// Errors returned by WireGuard cryptographic operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    KeyExchange,
    Decryption,
    Rejected,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::KeyExchange => "WireGuard key exchange failed",
            Self::Decryption => "WireGuard authentication failed",
            Self::Rejected => "WireGuard message rejected",
        })
    }
}
impl std::error::Error for CryptoError {}

/// Cryptographic operations required by WireGuard.
pub trait WireGuardCrypto {
    fn blake2s_hash(left: &[u8], right: &[u8]) -> Key;
    fn blake2s_mac(key: &[u8], message: &[u8]) -> [u8; 16];
    /// Noise HKDF with empty info: updates the chaining key, then returns up to
    /// two additional blocks (WireGuard uses one, two or three blocks in total).
    ///
    /// # Panics
    ///
    /// Panics if `N > 2`.
    fn hkdf_blake2s<const N: usize>(key: &mut Key, message: &[u8], output: &mut [Key; N]);

    fn x25519(secret: &StaticPrivateKey, public: &PublicKey) -> Result<Key, CryptoError>;
    fn x25519_pubkey(secret: &StaticPrivateKey) -> PublicKey;

    fn chacha20poly1305_encrypt(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    );
    fn chacha20poly1305_decrypt(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError>;

    fn xchacha20poly1305_encrypt(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    );
    fn xchacha20poly1305_decrypt(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError>;
}

/// A static private X25519 key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StaticPrivateKey(pub [u8; 32]);

impl StaticPrivateKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// An X25519 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey(pub [u8; 32]);

/// The RustCrypto WireGuard backend shipped by Rama.
pub struct BuiltinCrypto;

impl WireGuardCrypto for BuiltinCrypto {
    fn blake2s_hash(left: &[u8], right: &[u8]) -> Key {
        Blake2s256::new()
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    }

    #[expect(clippy::expect_used, reason = "WireGuard MAC keys are 16 or 32 bytes")]
    fn blake2s_mac(key: &[u8], message: &[u8]) -> [u8; 16] {
        // Keyed BLAKE2s-128, not HMAC or a truncated BLAKE2s-256 digest.
        let key = if key.is_empty() { None } else { Some(key) };
        Blake2sMac::<U16>::new_with_salt_and_personal(key, &[], &[])
            .expect("WireGuard MAC keys are at most 32 bytes")
            .chain_update(message)
            .finalize()
            .into_bytes()
            .into()
    }

    #[expect(
        clippy::expect_used,
        reason = "Noise requests at most three HKDF blocks"
    )]
    fn hkdf_blake2s<const N: usize>(key: &mut Key, message: &[u8], output: &mut [Key; N]) {
        assert!(N <= 2, "WireGuard Noise HKDF supports at most three blocks");
        // A fixed buffer covers all WireGuard derivations without allocating.
        let mut blocks = Zeroizing::new([[0; 32]; 3]);
        SimpleHkdf::<Blake2s256>::new(Some(key), message)
            .expand(&[], blocks[..=N].as_flattened_mut())
            .expect("three blocks fit the HKDF output limit");
        *key = blocks[0];
        output.copy_from_slice(&blocks[1..=N]);
    }

    fn x25519(secret: &StaticPrivateKey, public: &PublicKey) -> Result<Key, CryptoError> {
        let shared = StaticSecret::from(secret.0).diffie_hellman(&X25519PublicKey::from(public.0));
        if !shared.was_contributory() {
            return Err(CryptoError::KeyExchange);
        }
        Ok(shared.to_bytes())
    }

    fn x25519_pubkey(secret: &StaticPrivateKey) -> PublicKey {
        PublicKey(X25519PublicKey::from(&StaticSecret::from(secret.0)).to_bytes())
    }

    #[expect(
        clippy::expect_used,
        reason = "WireGuard packet lengths fit the AEAD limits"
    )]
    fn chacha20poly1305_encrypt(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        let encrypted_tag = ChaCha20Poly1305::new(key.into())
            .encrypt_inout_detached(nonce.into(), aad, payload.into())
            .expect("WireGuard packet lengths fit the AEAD limits");
        tag.copy_from_slice(&encrypted_tag);
    }

    fn chacha20poly1305_decrypt(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        ChaCha20Poly1305::new(key.into())
            .decrypt_inout_detached(nonce.into(), aad, payload.into(), tag.into())
            .map_err(|_error| CryptoError::Decryption)
    }

    #[expect(
        clippy::expect_used,
        reason = "WireGuard packet lengths fit the AEAD limits"
    )]
    fn xchacha20poly1305_encrypt(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        let encrypted_tag = XChaCha20Poly1305::new(key.into())
            .encrypt_inout_detached(nonce.into(), aad, payload.into())
            .expect("WireGuard packet lengths fit the AEAD limits");
        tag.copy_from_slice(&encrypted_tag);
    }

    fn xchacha20poly1305_decrypt(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        XChaCha20Poly1305::new(key.into())
            .decrypt_inout_detached(nonce.into(), aad, payload.into(), tag.into())
            .map_err(|_error| CryptoError::Decryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), 2 * N);
        core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn independent_blake2s_vectors() {
        // Generated independently with Python's hashlib.blake2s and hmac modules.
        assert_eq!(
            BuiltinCrypto::blake2s_hash(b"a", b"bc"),
            hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
        assert_eq!(
            BuiltinCrypto::blake2s_mac(b"", b"abc"),
            hex("aa4938119b1dc7b87cbad0ffd200d0ae")
        );
        let key: Key = core::array::from_fn(|i| i as u8);
        assert_eq!(
            BuiltinCrypto::blake2s_mac(&key, b"abc"),
            hex("61ba5f165c194692e09d12520cc4c74a")
        );
    }

    #[test]
    fn noise_hkdf_output_prefixes() {
        // Generated independently using Python HMAC-BLAKE2s, covering all Noise output lengths.
        let expected = [
            hex("c67e0b211ebf48c12c6d41da8fcee207d4c325a8c30f054d97401b14ed212f9f"),
            hex("923b032867c597d1df124053325e553b104bf3b76180a46e0c21b44001ec50f6"),
            hex("73e5eae9c5d230ea6becb29ab8a49f627aff1eb27586b938a71ae090d4c7a184"),
        ];
        fn check<const N: usize>(expected: &[Key; 3]) {
            let mut chain = core::array::from_fn(|i| i as u8);
            let mut output = [[0; 32]; N];
            BuiltinCrypto::hkdf_blake2s(&mut chain, b"abc", &mut output);
            assert_eq!(chain, expected[0]);
            assert_eq!(output, expected[1..=N]);
        }
        check::<0>(&expected);
        check::<1>(&expected);
        check::<2>(&expected);
    }

    #[test]
    #[should_panic(expected = "at most three blocks")]
    fn rejects_excessive_noise_hkdf_output() {
        BuiltinCrypto::hkdf_blake2s(&mut [0; 32], b"", &mut [[0; 32]; 3]);
    }

    #[test]
    fn x25519_rfc7748_vector_and_low_order_rejection() {
        // RFC 7748, section 6.1.
        let secret = StaticPrivateKey::from_bytes(hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        assert_eq!(
            BuiltinCrypto::x25519_pubkey(&secret).0,
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",)
        );
        let public = PublicKey(hex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        assert_eq!(
            BuiltinCrypto::x25519(&secret, &public).unwrap(),
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",)
        );
        for low_order in [0, 1] {
            let mut point = [0; 32];
            point[0] = low_order;
            assert_eq!(
                BuiltinCrypto::x25519(&secret, &PublicKey(point)),
                Err(CryptoError::KeyExchange)
            );
        }
    }

    #[test]
    fn aead_known_answer_vectors() {
        // RFC 8439 section 2.8.2 and draft-irtf-cfrg-xchacha-03 appendix A.3.1.
        let key = core::array::from_fn(|i| 0x80 + i as u8);
        let aad = hex::<12>("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut payload = *plaintext;
        let mut tag = [0; 16];
        let nonce = hex::<12>("070000004041424344454647");
        BuiltinCrypto::chacha20poly1305_encrypt(&key, &nonce, &aad, &mut payload, &mut tag);
        assert_eq!(
            payload,
            hex(concat!(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63d",
                "bea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692dd",
                "bd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def",
                "08e4b7a9de576d26586cec64b6116",
            ))
        );
        assert_eq!(tag, hex("1ae10b594f09e26a7e902ecbd0600691"));
        BuiltinCrypto::chacha20poly1305_decrypt(&key, &nonce, &aad, &mut payload, &tag).unwrap();
        assert_eq!(&payload, plaintext);

        let nonce = core::array::from_fn(|i| 0x40 + i as u8);
        BuiltinCrypto::xchacha20poly1305_encrypt(&key, &nonce, &aad, &mut payload, &mut tag);
        assert_eq!(
            payload,
            hex(concat!(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb7",
                "31c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522",
                "f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f",
                "9664c97637da9768812f615c68b13b52e",
            ))
        );
        assert_eq!(tag, hex("c0875924c1c7987947deafd8780acf49"));
        BuiltinCrypto::xchacha20poly1305_decrypt(&key, &nonce, &aad, &mut payload, &tag).unwrap();
        assert_eq!(&payload, plaintext);
    }

    #[test]
    fn aead_rejects_modified_inputs_and_handles_empty_payloads() {
        // Both nonce sizes are exercised, including the empty handshake payload.
        for length in [0, 32] {
            for extended in [false, true] {
                let key = [1; 32];
                let nonce = [2; 24];
                let aad = [3; 8];
                let mut payload = vec![4; length];
                let mut tag = [0; 16];
                if extended {
                    BuiltinCrypto::xchacha20poly1305_encrypt(
                        &key,
                        &nonce,
                        &aad,
                        &mut payload,
                        &mut tag,
                    );
                } else {
                    BuiltinCrypto::chacha20poly1305_encrypt(
                        &key,
                        nonce[..12].try_into().unwrap(),
                        &aad,
                        &mut payload,
                        &mut tag,
                    );
                }
                for modified in 0..5 {
                    let mut key = key;
                    let mut nonce = nonce;
                    let mut aad = aad;
                    let mut payload = payload.clone();
                    let mut tag = tag;
                    match modified {
                        0 => key[0] ^= 1,
                        1 => nonce[0] ^= 1,
                        2 => aad[0] ^= 1,
                        3 => tag[0] ^= 1,
                        _ if payload.is_empty() => continue,
                        _ => payload[0] ^= 1,
                    }
                    let result = if extended {
                        BuiltinCrypto::xchacha20poly1305_decrypt(
                            &key,
                            &nonce,
                            &aad,
                            &mut payload,
                            &tag,
                        )
                    } else {
                        BuiltinCrypto::chacha20poly1305_decrypt(
                            &key,
                            nonce[..12].try_into().unwrap(),
                            &aad,
                            &mut payload,
                            &tag,
                        )
                    };
                    assert_eq!(result, Err(CryptoError::Decryption));
                }
            }
        }
    }

    #[test]
    fn noise_constants_match_the_specification() {
        let construction =
            BuiltinCrypto::blake2s_hash(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", b"");
        let identifier =
            BuiltinCrypto::blake2s_hash(&construction, b"WireGuard v1 zx2c4 Jason@zx2c4.com");
        assert_eq!(
            construction,
            [
                96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235,
                66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
            ]
        );
        assert_eq!(
            identifier,
            [
                34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108,
                102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
            ]
        );
    }
}
