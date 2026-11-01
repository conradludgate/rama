//! Check the public exports as a downstream user, without another crypto backend.
#![cfg(feature = "rustcrypto")]

use rama_crypto::dep::rustcrypto::{
    blake2::Blake2s256,
    chacha20poly1305::{AeadInOut as _, ChaCha20Poly1305, KeyInit as _},
    digest::Digest as _,
    hkdf::SimpleHkdf,
    x25519_dalek::{PublicKey, StaticSecret},
    zeroize::Zeroizing,
};

#[test]
fn exported_primitives_support_key_agreement_and_authenticated_messages() {
    let alice = StaticSecret::from([7; 32]);
    let bob = StaticSecret::from([9; 32]);
    let shared = alice.diffie_hellman(&PublicKey::from(&bob));
    assert_eq!(
        shared.as_bytes(),
        bob.diffie_hellman(&PublicKey::from(&alice)).as_bytes()
    );
    assert!(shared.was_contributory());

    let mut key = Zeroizing::new([0; 32]);
    SimpleHkdf::<Blake2s256>::new(None, shared.as_bytes())
        .expand(b"export test", &mut *key)
        .unwrap();
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let nonce = [0; 12];
    let mut message = *b"hello";
    let tag = cipher
        .encrypt_inout_detached((&nonce).into(), b"metadata", message.as_mut_slice().into())
        .unwrap();
    assert_ne!(&message, b"hello");
    cipher
        .decrypt_inout_detached(
            (&nonce).into(),
            b"metadata",
            message.as_mut_slice().into(),
            &tag,
        )
        .unwrap();
    assert_eq!(&message, b"hello");
    assert_eq!(Blake2s256::digest(message).len(), 32);
}
