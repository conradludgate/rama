use super::*;
use crate::{
    BuiltinCrypto,
    crypto::decrypt_cookie_reply,
    proto::{HandshakeInitiation, Mac},
};
use rand::{Rng as _, SeedableRng as _};

fn fixture(
    threshold: u32,
) -> (
    HandshakeAdmission,
    Vec<u8>,
    impl FnMut(&mut [u8]) -> io::Result<()>,
) {
    let public_key = PublicKey([7; 32]);
    let admission = HandshakeAdmission::new::<BuiltinCrypto>(
        public_key,
        HandshakeAdmissionConfig {
            handshake_threshold: threshold,
            ..Default::default()
        },
    );
    let mut bytes = vec![0; size_of::<HandshakeInitiation>()];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&10u32.to_le_bytes());
    let Message::HandshakeInitiation(message) = Message::decode(&mut bytes).unwrap() else {
        panic!("initiation")
    };
    message.mac1 = message.compute_mac1::<BuiltinCrypto>(&admission.mac1_key);
    let mut rng = rand::rngs::StdRng::from_seed([42; 32]);
    (admission, bytes, move |bytes| {
        rng.fill_bytes(bytes);
        Ok(())
    })
}
fn mac1(bytes: &mut [u8]) -> Mac {
    let Message::HandshakeInitiation(message) = Message::decode(bytes).unwrap() else {
        panic!("initiation")
    };
    message.mac1
}
fn attach_cookie(bytes: &mut [u8], cookie: &crate::proto::Cookie) {
    let Message::HandshakeInitiation(message) = Message::decode(bytes).unwrap() else {
        panic!("initiation")
    };
    message.mac2 = message.compute_mac2::<BuiltinCrypto>(cookie);
}

#[test]
fn malformed_and_invalid_mac1_traffic_needs_no_randomness_or_source_state() {
    let (mut admission, mut bytes, _) = fixture(0);
    bytes[20] ^= 1;
    let mut random = |_: &mut [u8]| Err(io::Error::other("must not request entropy"));
    for bytes in [&mut [] as &mut [u8], &mut [1, 0, 0, 0][..], &mut bytes[..]] {
        assert!(matches!(
            admission
                .check::<BuiltinCrypto>(
                    SocketAddress::local_ipv4(1),
                    bytes,
                    Duration::ZERO,
                    &mut random
                )
                .unwrap(),
            Decision::Drop
        ));
    }
    assert!(admission.secret.is_none());
    assert!(admission.sources.is_empty());
    assert_eq!(admission.count, 0);
}

#[test]
fn interface_threshold_resets_on_supplied_time_and_cookie_challenges_are_stateless() {
    let (mut admission, mut bytes, mut random) = fixture(2);
    let source = SocketAddress::local_ipv4(1);
    for _ in 0..2 {
        let Decision::Accept(accepted) = admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::ZERO, &mut random)
            .unwrap()
        else {
            panic!("below threshold")
        };
        assert!(
            accepted
                .ephemeral(|| Ok(crate::EphemeralPrivateKey::from_bytes([1; 32])))
                .unwrap()
                .is_some()
        );
    }
    assert!(matches!(
        admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::ZERO, &mut random)
            .unwrap(),
        Decision::Reply(_)
    ));
    assert!(
        admission.sources.is_empty(),
        "unproven sources allocate no bucket"
    );
    assert!(matches!(
        admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::from_secs(1), &mut random)
            .unwrap(),
        Decision::Accept(_)
    ));
}

#[test]
fn cookies_authorize_only_the_original_endpoint_and_expire_with_the_secret() {
    let (mut admission, mut bytes, mut random) = fixture(0);
    let source = SocketAddress::local_ipv4(1);
    let mac1 = mac1(&mut bytes);
    let Decision::Reply(mut packet) = admission
        .check::<BuiltinCrypto>(source, &mut bytes, Duration::ZERO, &mut random)
        .unwrap()
    else {
        panic!("cookie challenge")
    };
    let Message::CookieReply(reply) = Message::decode(&mut packet.payload).unwrap() else {
        panic!("cookie")
    };
    let cookie =
        decrypt_cookie_reply::<BuiltinCrypto>(&admission.cookie_key, &mac1, reply).unwrap();
    attach_cookie(&mut bytes, &cookie);
    assert!(matches!(
        admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::ZERO, &mut random)
            .unwrap(),
        Decision::Accept(_)
    ));
    for _ in 0..4 {
        assert!(matches!(
            admission
                .check::<BuiltinCrypto>(source, &mut bytes, Duration::ZERO, &mut random)
                .unwrap(),
            Decision::Accept(_)
        ));
    }
    assert!(matches!(
        admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::ZERO, &mut random)
            .unwrap(),
        Decision::Drop
    ));
    assert!(matches!(
        admission
            .check::<BuiltinCrypto>(
                SocketAddress::local_ipv4(2),
                &mut bytes,
                Duration::ZERO,
                &mut random
            )
            .unwrap(),
        Decision::Reply(_)
    ));
    assert!(matches!(
        admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::from_secs(119), &mut random)
            .unwrap(),
        Decision::Accept(_)
    ));
    assert!(matches!(
        admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::from_secs(120), &mut random)
            .unwrap(),
        Decision::Reply(_)
    ));
}

#[test]
fn source_burst_refill_isolation_and_backward_time_are_bounded() {
    let (mut admission, _, _) = fixture(0);
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "192.0.2.2".parse().unwrap();
    for _ in 0..5 {
        assert!(admission.allow_source(a, Duration::ZERO));
    }
    assert!(!admission.allow_source(a, Duration::from_millis(49)));
    assert!(admission.allow_source(a, Duration::from_millis(50)));
    assert!(!admission.allow_source(a, Duration::ZERO));
    assert!(!admission.allow_source(a, Duration::from_millis(50)));
    assert!(admission.allow_source(b, Duration::from_millis(50)));
    assert!(admission.allow_source(a, Duration::from_millis(100)));
}

#[test]
fn ipv6_prefixes_and_mapped_ipv4_share_their_source_budget() {
    let (mut admission, _, _) = fixture(0);
    admission.config.source_burst = NonZeroU32::new(1).unwrap();
    assert!(admission.allow_source("192.0.2.1".parse().unwrap(), Duration::ZERO));
    assert!(!admission.allow_source("::ffff:192.0.2.1".parse().unwrap(), Duration::ZERO));
    assert!(admission.allow_source("2001:db8:1::1".parse().unwrap(), Duration::ZERO));
    assert!(!admission.allow_source("2001:db8:1::2".parse().unwrap(), Duration::ZERO));
    assert!(admission.allow_source("2001:db8:2::1".parse().unwrap(), Duration::ZERO));
}

#[test]
fn table_cap_and_eviction_do_not_restore_credit_early() {
    let (mut admission, _, _) = fixture(0);
    admission.config.max_sources = NonZeroUsize::new(1).unwrap();
    admission.config.source_rate = NonZeroU32::new(1).unwrap();
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "192.0.2.2".parse().unwrap();
    for _ in 0..5 {
        assert!(admission.allow_source(a, Duration::ZERO));
    }
    assert!(!admission.allow_source(b, Duration::from_secs(1)));
    assert_eq!(admission.sources.len(), 1);
    assert!(admission.allow_source(b, Duration::from_secs(5)));
    assert!(!admission.allow_source(a, Duration::from_secs(5)));
    assert_eq!(admission.sources.len(), 1);
}

#[test]
fn entropy_failure_is_returned_and_transport_never_requests_entropy() {
    let (mut admission, mut bytes, _) = fixture(0);
    let source = SocketAddress::local_ipv4(1);
    let mut fail = |_: &mut [u8]| Err(io::Error::other("entropy unavailable"));
    assert!(
        admission
            .check::<BuiltinCrypto>(source, &mut bytes, Duration::ZERO, &mut fail)
            .is_err()
    );
    assert!(admission.secret.is_none());
    let Decision::Accept(accepted) = admission
        .check::<BuiltinCrypto>(source, &mut [4, 0, 0, 0], Duration::ZERO, &mut fail)
        .unwrap()
    else {
        panic!("transport bypasses handshake admission")
    };
    assert!(
        accepted
            .ephemeral(|| Err(io::Error::other("not an initiation")))
            .unwrap()
            .is_none()
    );
}
