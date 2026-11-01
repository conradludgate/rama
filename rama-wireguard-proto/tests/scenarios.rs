//! Observable protocol scenarios: loss, reordering, duplication and recovery.
#![expect(clippy::unwrap_used, reason = "scenario fixtures and assertions")]
#[path = "scenarios/harness.rs"]
mod harness;
use harness::{Network, Side};
use std::time::Duration;

#[test]
fn repeated_handshake_loss_stops_and_discards_stale_queued_data() {
    let mut net = Network::new();
    net.send(Side::A, 1);
    let mut attempts = 0;
    for seconds in (0..=95).step_by(5) {
        net.advance(Duration::from_secs(seconds));
        for packet in net.wire.drain(..) {
            assert_eq!(packet.from, Side::A);
            assert_eq!(packet.kind(), 1);
            assert!(seconds < 90, "retry budget must be finite");
            attempts += 1;
            // Drop every initiation.
        }
    }
    assert_eq!(attempts, 18);
    net.handshake(Side::A);
    net.drain();
    net.advance(Duration::from_secs(95));
    net.drain();
    assert!(
        net.received.is_empty(),
        "timed-out queued data was discarded"
    );
    let fresh = net.send(Side::A, 2);
    net.drain();
    assert_eq!(net.received, vec![(Side::B, fresh)]);
}

#[test]
fn reordered_packets_arrive_once_and_forgery_does_not_consume_a_counter() {
    let mut net = Network::new();
    net.establish();
    let first = net.send(Side::A, 1);
    let second = net.send(Side::A, 2);
    let a = net.wire.pop_front().unwrap();
    let b = net.wire.pop_front().unwrap();
    let duplicate = a.duplicate();
    let mut forged = b.duplicate();
    *forged.datagram.payload.last_mut().unwrap() ^= 1;
    assert!(net.deliver(forged).is_err());
    net.deliver(b).unwrap();
    net.deliver(a).unwrap();
    assert!(net.deliver(duplicate).is_err());
    assert_eq!(net.received, vec![(Side::B, second), (Side::B, first)]);
}

#[test]
fn crossed_handshakes_converge_with_reordered_responses() {
    let mut net = Network::new();
    net.engines[1]
        .set_peer_endpoint(net.peers[1], net.addresses[0])
        .unwrap();
    net.handshake(Side::A);
    net.handshake(Side::B);
    let a = net.wire.pop_front().unwrap();
    let b = net.wire.pop_front().unwrap();
    net.deliver(a).unwrap();
    net.deliver(b).unwrap();
    let first_response = net.wire.pop_front().unwrap();
    let second_response = net.wire.pop_front().unwrap();
    net.deliver(second_response).unwrap();
    net.deliver(first_response).unwrap();
    net.drain();
    let a = net.send(Side::A, 1);
    let b = net.send(Side::B, 2);
    net.drain();
    assert_eq!(net.received, vec![(Side::B, a), (Side::A, b)]);
}

#[test]
fn response_cookie_is_cached_for_a_later_retry_without_immediate_resend() {
    use harness::Packet;
    use rama_wireguard_proto::{
        BuiltinCrypto, CookieState, WireGuardCrypto, WireGuardDatagram,
        crypto::encrypt_cookie_reply, proto::Message,
    };
    use zerocopy::IntoBytes as _;
    let mut net = Network::new();
    net.handshake(Side::A);
    let init = net.wire.pop_front().unwrap();
    net.deliver(init).unwrap();
    let mut response = net.wire.pop_front().unwrap();
    let state = CookieState::new([7; 32]);
    let cookie = state.new_cookie::<BuiltinCrypto>(net.addresses[1].into_std());
    let key = BuiltinCrypto::blake2s_hash(b"cookie--", &net.engines[0].device().public_key().0);
    let Message::HandshakeResponse(message) =
        Message::decode(&mut response.datagram.payload).unwrap()
    else {
        panic!("expected a response");
    };
    let challenge = encrypt_cookie_reply::<BuiltinCrypto>(
        &key,
        message.sender.get(),
        &message.mac1,
        cookie,
        [8; 24],
    );
    net.deliver(Packet {
        from: Side::A,
        source: net.addresses[0],
        datagram: WireGuardDatagram {
            destination: net.addresses[1],
            payload: challenge.as_bytes().to_vec(),
        },
    })
    .unwrap();
    assert!(
        net.wire.is_empty(),
        "a cookie must not trigger an immediate resend"
    );
    net.advance(Duration::from_secs(5));
    let retry = net.wire.pop_front().unwrap();
    assert_eq!(retry.from, Side::A);
    net.deliver(retry).unwrap();
    let mut response = net.wire.pop_front().unwrap();
    let Message::HandshakeResponse(message) =
        Message::decode(&mut response.datagram.payload).unwrap()
    else {
        panic!("expected a response");
    };
    use rama_wireguard_proto::crypto::HasMac as _;
    message.verify_mac2::<BuiltinCrypto>(&cookie).unwrap();
    net.deliver(response).unwrap();
    net.drain();
    let packet = net.send(Side::A, 1);
    net.drain();
    assert_eq!(net.received, vec![(Side::B, packet)]);
}
