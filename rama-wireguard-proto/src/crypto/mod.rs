//! WireGuard cryptographic provider and owned keys.
mod provider;
pub use provider::{BuiltinCrypto, CryptoError, Key, PublicKey, StaticPrivateKey, WireGuardCrypto};

use crate::proto::{MAC_SIZE, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// WireGuard's maximum accepted transport counter, excluding the nonce exhaustion margin.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// Symmetric transport key used for outgoing packets.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    key: Key,
    counter: u64,
}

impl EncryptionKey {
    #[must_use]
    pub const fn new(key: Key) -> Self {
        Self { key, counter: 0 }
    }

    pub fn encrypt<C: WireGuardCrypto>(&mut self, payload: &mut [u8]) -> Result<Tag, CryptoError> {
        if self.counter >= REJECT_AFTER_MESSAGES {
            return Err(CryptoError::Rejected);
        }
        let nonce = nonce(self.counter);
        self.counter = self.counter.saturating_add(1);
        let mut tag = [0; MAC_SIZE];
        C::chacha20poly1305_encrypt(&self.key, &nonce, &[], payload, &mut tag);
        Ok(Tag(tag))
    }

    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }
}

/// Symmetric transport key used for incoming packets, with an RFC 6479 replay window.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptionKey {
    key: Key,
    #[zeroize(skip)]
    replay: ReplayWindow,
}

impl DecryptionKey {
    #[must_use]
    pub const fn new(key: Key) -> Self {
        Self {
            key,
            replay: ReplayWindow::new(),
        }
    }

    pub fn decrypt<'a, C: WireGuardCrypto>(
        &mut self,
        counter: u64,
        payload_and_tag: &'a mut [u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let (payload, tag) = payload_and_tag.split_at_mut(
            payload_and_tag
                .len()
                .checked_sub(MAC_SIZE)
                .ok_or(CryptoError::Decryption)?,
        );
        let tag: &[u8; MAC_SIZE] = (&*tag)
            .try_into()
            .map_err(|_error| CryptoError::Decryption)?;
        self.decrypt_detached::<C>(counter, payload, tag)?;
        Ok(payload)
    }

    pub(crate) fn decrypt_detached<C: WireGuardCrypto>(
        &mut self,
        counter: u64,
        payload: &mut [u8],
        tag: &[u8; MAC_SIZE],
    ) -> Result<(), CryptoError> {
        if counter >= REJECT_AFTER_MESSAGES || !self.replay.would_accept(counter) {
            return Err(CryptoError::Rejected);
        }
        C::chacha20poly1305_decrypt(&self.key, &nonce(counter), &[], payload, tag)?;
        self.replay.mark_seen(counter);
        Ok(())
    }
}

#[derive(Default)]
struct ReplayWindow {
    bitmap: [usize; 2048 / (core::mem::size_of::<usize>() * 8)],
    last: u64,
}

impl ReplayWindow {
    const fn new() -> Self {
        Self {
            bitmap: [0; 2048 / (core::mem::size_of::<usize>() * 8)],
            last: 0,
        }
    }

    fn would_accept(&self, counter: u64) -> bool {
        let word_bits = (core::mem::size_of::<usize>() * 8) as u64;
        if counter > self.last {
            return true;
        }
        let distance = self.last - counter;
        if distance >= 2048 - word_bits {
            return false;
        }
        let index = (counter / word_bits) as usize;
        let bit = (counter % word_bits) as usize;
        (self.bitmap[index % self.bitmap.len()] & (1usize << bit)) == 0
    }

    fn mark_seen(&mut self, counter: u64) {
        let word_bits = (core::mem::size_of::<usize>() * 8) as u64;
        let index = (counter / word_bits) as usize;
        let bit = (counter % word_bits) as usize;
        if counter > self.last {
            let next = (self.last / word_bits + 1) as usize;
            if index > next && index - next > self.bitmap.len() {
                self.bitmap.fill(0);
            } else {
                for i in next..=index {
                    self.bitmap[i % self.bitmap.len()] = 0;
                }
            }
            self.last = counter;
        }
        self.bitmap[index % self.bitmap.len()] |= 1usize << bit;
    }
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_counter_limits_reject_before_nonce_reuse_or_decryption() {
        let mut encryption = EncryptionKey::new([1; 32]);
        encryption.counter = REJECT_AFTER_MESSAGES - 1;
        encryption.encrypt::<BuiltinCrypto>(&mut []).unwrap();
        assert_eq!(encryption.counter(), REJECT_AFTER_MESSAGES);
        assert!(matches!(
            encryption.encrypt::<BuiltinCrypto>(&mut []),
            Err(CryptoError::Rejected)
        ));
        let mut decryption = DecryptionKey::new([1; 32]);
        for counter in [REJECT_AFTER_MESSAGES, u64::MAX] {
            assert!(matches!(
                decryption.decrypt::<BuiltinCrypto>(counter, &mut [0; 16]),
                Err(CryptoError::Rejected)
            ));
        }
    }
    #[test]
    fn replay_window_only_marks_authenticated_packets() {
        let mut replay = ReplayWindow::new();
        assert!(replay.would_accept(10));
        assert!(replay.would_accept(10_000));
        replay.mark_seen(10);
        assert!(!replay.would_accept(10));
        assert!(replay.would_accept(11));
    }
}
