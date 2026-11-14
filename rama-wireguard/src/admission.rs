//! Interface-wide admission before responder randomness and Noise operations.
use crate::{
    CookieState, PublicKey, WireGuardCrypto, WireGuardDatagram,
    crypto::{HasMac as _, encrypt_cookie_reply},
    proto::Message,
};
use ahash::{HashMap, HashMapExt as _};
use rama_net::address::SocketAddress;
use std::{
    io,
    net::IpAddr,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use zerocopy::IntoBytes as _;

const SECOND: u128 = 1_000_000_000;
const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

/// Interface-wide handshake admission. Limits are shared by all registered peers.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeAdmissionConfig {
    /// Handshakes admitted without cookies per one-second window. Zero always requires cookies.
    pub handshake_threshold: u32,
    /// Cookie-valid handshakes per second per IPv4 address or IPv6 /64 while under load.
    pub source_rate: NonZeroU32,
    /// Maximum burst from one cookie-valid source while under load.
    pub source_burst: NonZeroU32,
    /// Maximum number of tracked sources. New sources are refused when the table is full.
    pub max_sources: NonZeroUsize,
}
impl Default for HandshakeAdmissionConfig {
    fn default() -> Self {
        Self {
            handshake_threshold: 100,
            source_rate: const { NonZeroU32::new(20).unwrap() },
            source_burst: const { NonZeroU32::new(5).unwrap() },
            max_sources: const { NonZeroUsize::new(4096).unwrap() },
        }
    }
}

pub(crate) struct HandshakeAdmission {
    config: HandshakeAdmissionConfig,
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],
    secret: Option<(CookieState, Duration)>,
    window_start: Duration,
    count: u32,
    sources: HashMap<Source, Bucket>,
    last_gc: Duration,
}
pub(crate) enum Decision {
    Accept(Accepted),
    Reply(WireGuardDatagram),
    Drop,
}
/// Only admission can construct this evidence. Peer authentication and inner IP
/// authorization remain the engine's responsibility.
pub(crate) struct Accepted {
    initiation: bool,
}
impl Accepted {
    pub(crate) fn ephemeral(
        self,
        generate: impl FnOnce() -> io::Result<crate::EphemeralPrivateKey>,
    ) -> io::Result<Option<crate::EphemeralPrivateKey>> {
        self.initiation.then(generate).transpose()
    }
}

impl HandshakeAdmission {
    pub(crate) fn new<C: WireGuardCrypto>(
        public_key: PublicKey,
        config: HandshakeAdmissionConfig,
    ) -> Self {
        Self {
            config,
            mac1_key: C::blake2s_hash(b"mac1----", &public_key.0),
            cookie_key: C::blake2s_hash(b"cookie--", &public_key.0),
            secret: None,
            window_start: Duration::ZERO,
            count: 0,
            sources: HashMap::new(),
            last_gc: Duration::ZERO,
        }
    }

    pub(crate) fn configure(&mut self, config: HandshakeAdmissionConfig) {
        self.config = config;
        self.count = 0;
        self.sources.clear();
    }

    pub(crate) fn check<C: WireGuardCrypto>(
        &mut self,
        source: SocketAddress,
        bytes: &mut [u8],
        now: Duration,
        mut random: impl FnMut(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<Decision> {
        let Some(header) = bytes.first_chunk::<4>() else {
            return Ok(Decision::Drop);
        };
        let kind = u32::from_le_bytes(*header);
        // Transport and cookie packets have no handshake admission budget. The
        // engine still validates their framing, authentication and replay state.
        if kind != 1 && kind != 2 {
            return Ok(Decision::Accept(Accepted { initiation: false }));
        }
        let Ok(message) = Message::decode(bytes) else {
            return Ok(Decision::Drop);
        };
        let (sender, mac1, valid_mac1) = match &message {
            Message::HandshakeInitiation(m) => (
                m.sender.get(),
                m.mac1,
                m.verify_mac1::<C>(&self.mac1_key).is_ok(),
            ),
            Message::HandshakeResponse(m) => (
                m.sender.get(),
                m.mac1,
                m.verify_mac1::<C>(&self.mac1_key).is_ok(),
            ),
            _ => return Ok(Decision::Drop),
        };
        if !valid_mac1 {
            return Ok(Decision::Drop);
        }
        if now.saturating_sub(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.count = 0;
        }
        let under_load = self.count >= self.config.handshake_threshold;
        self.count = self.count.saturating_add(1);
        if !under_load {
            return Ok(Decision::Accept(Accepted {
                initiation: kind == 1,
            }));
        }

        // No entropy is needed for invalid MAC1s or traffic below the threshold.
        if self
            .secret
            .as_ref()
            .is_none_or(|(_, created)| now.saturating_sub(*created) >= COOKIE_LIFETIME)
        {
            let mut key = [0; 32];
            random(&mut key)?;
            self.secret = Some((CookieState::new(key), now));
        }
        let Some((secret, _)) = &self.secret else {
            return Ok(Decision::Drop);
        };
        let cookie = secret.new_cookie::<C>(source.into_std());
        let valid_cookie = match message {
            Message::HandshakeInitiation(m) => m.verify_mac2::<C>(&cookie).is_ok(),
            Message::HandshakeResponse(m) => m.verify_mac2::<C>(&cookie).is_ok(),
            _ => false,
        };
        if !valid_cookie {
            let mut nonce = [0; 24];
            random(&mut nonce)?;
            let reply = encrypt_cookie_reply::<C>(&self.cookie_key, sender, &mac1, cookie, nonce);
            return Ok(Decision::Reply(WireGuardDatagram {
                destination: source,
                payload: reply.as_bytes().to_vec(),
            }));
        }
        if !self.allow_source(source.into_std().ip(), now) {
            return Ok(Decision::Drop);
        }
        Ok(Decision::Accept(Accepted {
            initiation: kind == 1,
        }))
    }

    fn allow_source(&mut self, ip: IpAddr, now: Duration) -> bool {
        let cap = u128::from(self.config.source_burst.get()) * SECOND;
        let rate = u128::from(self.config.source_rate.get());
        // An evicted source must already have earned a full bucket, so eviction
        // cannot restore burst credit early even with a slow configured rate.
        let idle_ns = cap.div_ceil(rate).max(SECOND);
        if now.saturating_sub(self.last_gc) >= Duration::from_secs(1) {
            self.sources
                .retain(|_, b| now.saturating_sub(b.last).as_nanos() < idle_ns);
            self.last_gc = now;
        }
        let source = Source::from(ip);
        if let Some(bucket) = self.sources.get_mut(&source) {
            return bucket.take(now, rate, cap);
        }
        if self.sources.len() >= self.config.max_sources.get() {
            return false;
        }
        self.sources.insert(
            source,
            Bucket {
                credit: cap - SECOND,
                last: now,
            },
        );
        true
    }
}

#[derive(Hash, PartialEq, Eq)]
enum Source {
    V4(std::net::Ipv4Addr),
    V6(u64),
}
impl From<IpAddr> for Source {
    fn from(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(ip) => Self::V4(ip),
            IpAddr::V6(ip) => Self::V6((ip.to_bits() >> 64) as u64),
        }
    }
}
struct Bucket {
    credit: u128,
    last: Duration,
}
impl Bucket {
    fn take(&mut self, now: Duration, rate: u128, cap: u128) -> bool {
        self.credit = self
            .credit
            .saturating_add(
                now.saturating_sub(self.last)
                    .as_nanos()
                    .saturating_mul(rate),
            )
            .min(cap);
        self.last = self.last.max(now);
        if self.credit < SECOND {
            return false;
        }
        self.credit -= SECOND;
        true
    }
}

#[cfg(test)]
mod tests;
