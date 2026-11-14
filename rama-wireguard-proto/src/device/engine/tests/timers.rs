use super::*;

#[test]
fn sending_on_an_aged_initiator_session_requests_rekey() {
    let (mut client, mut server, cp, sp, ca, sa) = established_pair();
    assert!(client.tick(REKEY_AFTER).unwrap().is_empty());
    assert!(server.tick(REKEY_AFTER).unwrap().is_empty());
    let mut data = server.send(sp, b"responder data").unwrap().payload;
    client.receive_datagram(sa, &mut data, None).unwrap();
    assert!(client.tick(REKEY_AFTER).unwrap().is_empty());
    assert!(server.tick(REKEY_AFTER).unwrap().is_empty());
    let mut data = client.send(cp, b"initiator data").unwrap().payload;
    server.receive_datagram(ca, &mut data, None).unwrap();
    assert!(matches!(client.tick(REKEY_AFTER).unwrap().as_slice(),
        [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == cp));
    assert!(server.tick(REKEY_AFTER).unwrap().is_empty());
}

#[test]
fn receiving_near_expiry_requests_rekey_only_after_authentication() {
    let (mut client, mut server, cp, sp, _, sa) = established_pair();
    let now = Duration::from_secs(165);
    assert!(client.tick(now).unwrap().is_empty());
    assert!(server.tick(now).unwrap().is_empty());
    let mut keepalive = server.send(sp, &[]).unwrap().payload;
    let mut forged = keepalive.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        client.receive_datagram(sa, &mut forged, None),
        Err(EngineError::Device(DeviceError::Crypto(
            crate::CryptoError::Decryption
        )))
    ));
    assert!(client.tick(now).unwrap().is_empty());
    client.receive_datagram(sa, &mut keepalive, None).unwrap();
    assert!(matches!(client.tick(now).unwrap().as_slice(),
        [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == cp));
}

#[test]
fn persistent_keepalive_recovers_after_initial_retry_budget_expires() {
    let (mut client, mut server, cp, sp, ca, sa) = engine_pair();
    client.set_persistent_keepalive(cp, Some(Duration::from_secs(25)));
    let recovered = 'recovery: {
        for second in 0..=150 {
            let now = Duration::from_secs(second);
            server.tick(now).unwrap();
            for action in client.tick(now).unwrap() {
                let WireGuardMaintenance::HandshakeRequired(peer) = action else {
                    continue;
                };
                let mut initiation = client
                    .start_handshake_auto(
                        peer,
                        Tai64n::from_unix_duration(now),
                        EphemeralPrivateKey::from_bytes([(second + 3) as u8; 32]),
                    )
                    .unwrap()
                    .payload;
                // Bring the remote online after the 90-second retry budget expires.
                if second < 100 {
                    continue;
                }
                let mut response = outgoing(
                    server
                        .receive_datagram(
                            ca,
                            &mut initiation,
                            Some(EphemeralPrivateKey::from_bytes([9; 32])),
                        )
                        .unwrap(),
                );
                let mut confirmation =
                    outgoing(client.receive_datagram(sa, &mut response, None).unwrap());
                server
                    .receive_datagram(ca, &mut confirmation, None)
                    .unwrap();
                break 'recovery now;
            }
        }
        panic!("persistent keepalive must restart handshake attempts");
    };
    assert!(client.current_receiver(cp).is_some());
    assert!(server.current_receiver(sp).is_some());
    assert!(matches!(
        client
            .tick(recovered + Duration::from_secs(25))
            .unwrap()
            .as_slice(),
        [WireGuardMaintenance::Send(_)]
    ));
}

#[test]
fn persistent_keepalive_requests_keys_after_expiry() {
    let (mut client, _, cp, _, _, _) = established_pair();
    client.set_persistent_keepalive(cp, Some(Duration::from_secs(240)));
    assert!(client.tick(REJECT_AFTER).unwrap().is_empty());
    assert!(
        matches!(client.tick(Duration::from_secs(240)).unwrap().as_slice(),
        [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == cp)
    );
}

#[test]
fn persistent_keepalive_retries_after_lost_confirmation() {
    let (mut client, mut server, cp, sp, ca, _) = engine_pair();
    server.set_persistent_keepalive(sp, Some(Duration::from_secs(25)));
    let mut initiation = client
        .start_handshake_auto(
            cp,
            Tai64n::from_bytes([1; 12]),
            EphemeralPrivateKey::from_bytes([3; 32]),
        )
        .unwrap()
        .payload;
    server
        .receive_datagram(
            ca,
            &mut initiation,
            Some(EphemeralPrivateKey::from_bytes([4; 32])),
        )
        .unwrap();
    assert!(server.current_receiver(sp).is_none());
    assert!(
        matches!(server.tick(Duration::from_secs(25)).unwrap().as_slice(),
        [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == sp)
    );
    server
        .start_handshake_auto(
            sp,
            Tai64n::from_bytes([2; 12]),
            EphemeralPrivateKey::from_bytes([5; 32]),
        )
        .unwrap();
    // Retry while the responder keypair is still unconfirmed.
    assert!(
        matches!(server.tick(Duration::from_secs(30)).unwrap().as_slice(),
        [WireGuardMaintenance::HandshakeRequired(peer)] if *peer == sp)
    );
}

#[test]
fn authenticated_input_postpones_persistent_keepalives_and_zero_disables_them() {
    let (mut client, mut server, cp, sp, _, sa) = established_pair();
    client.set_persistent_keepalive(cp, Some(Duration::from_secs(25)));
    client.tick(Duration::from_secs(24)).unwrap();
    let mut keepalive = server.send(sp, &[]).unwrap().payload;
    client.receive_datagram(sa, &mut keepalive, None).unwrap();
    assert!(client.tick(Duration::from_secs(25)).unwrap().is_empty());
    assert!(matches!(
        client.tick(Duration::from_secs(49)).unwrap().as_slice(),
        [WireGuardMaintenance::Send(_)]
    ));
    client.set_persistent_keepalive(cp, Some(Duration::ZERO));
    assert!(client.tick(Duration::from_secs(74)).unwrap().is_empty());
}
