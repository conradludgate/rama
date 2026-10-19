//! Endpoint lifecycle, dispatch and type-boundary tests.
#![expect(clippy::unwrap_used, reason = "test fixtures and assertions")]

use super::*;
use crate::{EphemeralPrivateKey, Tai64n};
use rama_core::rt::Executor;
use rama_net::ip::{EcnCodepoint, Ipv4PacketHeader};
use rama_udp::test_utils::MemoryDatagramSocket;

fn config(public_key: PublicKey, endpoint: Option<SocketAddress>, host: u8) -> PeerConfig {
    PeerConfig {
        public_key,
        endpoint,
        preshared_key: Some([93; 32]),
        allowed_ips: vec![format!("10.0.0.{host}/32").parse().unwrap()],
    }
}
fn packet(source: u8, destination: u8, marker: u8) -> Vec<u8> {
    let mut out = vec![0; 21];
    Ipv4PacketHeader {
        source: [10, 0, 0, source].into(),
        destination: [10, 0, 0, destination].into(),
        protocol: 253,
        ttl: 64,
        ecn: EcnCodepoint::from_bits(0),
    }
    .encode(&[marker], &mut out)
    .unwrap();
    out
}
fn sockets() -> (MemoryDatagramSocket, MemoryDatagramSocket) {
    MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(49000),
        SocketAddress::local_ipv4(49001),
        NonZeroUsize::new(32).unwrap(),
    )
}

#[tokio::test(start_paused = true)]
async fn peer_outlives_endpoint_and_last_drop_stops_driver() {
    let (socket, _remote) = sockets();
    let (endpoint, driver) = PeerEndpoint::new(
        StaticPrivateKey::from_bytes([91; 32]),
        socket,
        EndpointConfig::default(),
    );
    let task = driver.spawn(&Executor::new());
    let key = BuiltinCrypto::x25519_pubkey(&StaticPrivateKey::from_bytes([92; 32]));
    let peer = endpoint.add_peer(config(key, None, 2)).await.unwrap();
    drop(endpoint);
    peer.set_persistent_keepalive(Some(Duration::from_secs(25)))
        .await
        .unwrap();
    drop(peer);
    task.await.unwrap().unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn dynamic_packet_peers_share_stream_and_removal_preserves_other_sessions() {
    use crate::{WireGuardAction, transport::DatagramTransport};
    let (socket, remote) = sockets();
    let (endpoint, driver) = PacketEndpoint::new(
        StaticPrivateKey::from_bytes([91; 32]),
        socket,
        EndpointConfig::default(),
    );
    let task = driver.spawn(&Executor::new());
    let mut clients = Vec::new();
    let mut ids = Vec::new();
    let mut transport = DatagramTransport::new(remote);
    let mut buffer = [0; 512];
    for host in 1..=2 {
        let mut client = WireGuardEngine::new(Device::<BuiltinCrypto>::new(
            StaticPrivateKey::from_bytes([94 + host; 32]),
        ));
        let id = endpoint
            .add_peer(config(client.device().public_key(), None, host))
            .await
            .unwrap();
        ids.push(id);
        let peer = client
            .add_peer(&PeerConfig {
                public_key: endpoint.public_key(),
                preshared_key: Some([93; 32]),
                endpoint: Some(SocketAddress::local_ipv4(49000)),
                allowed_ips: vec!["10.0.0.3/32".parse().unwrap()],
            })
            .unwrap();
        let init = client
            .start_handshake_auto(
                peer,
                Tai64n::from_bytes([1; 12]),
                EphemeralPrivateKey::from_bytes([97 + host; 32]),
            )
            .unwrap();
        transport
            .send_to(init.destination, &init.payload)
            .await
            .unwrap();
        let metadata = transport.recv(&mut buffer).await.unwrap();
        for action in client
            .receive_datagram(metadata.peer, &mut buffer[..metadata.len], None)
            .unwrap()
        {
            if let WireGuardAction::Send(packet) = action {
                transport
                    .send_to(packet.destination, &packet.payload)
                    .await
                    .unwrap();
            }
        }
        let data = client.send(peer, &packet(host, 3, host)).unwrap();
        transport
            .send_to(data.destination, &data.payload)
            .await
            .unwrap();
        clients.push((client, peer));
    }
    for (index, host) in [1, 2].into_iter().enumerate() {
        let received = endpoint.recv().await.unwrap();
        assert_eq!(received.peer, ids[index]);
        assert_eq!(received.payload, packet(host, 3, host));
    }
    endpoint.remove_peer(ids[0]).await.unwrap();
    for (index, host) in [1, 2].into_iter().enumerate() {
        let (client, peer) = &mut clients[index];
        let data = client.send(*peer, &packet(host, 3, 9)).unwrap();
        transport
            .send_to(data.destination, &data.payload)
            .await
            .unwrap();
    }
    let received = endpoint.recv().await.unwrap();
    assert_eq!(received.peer, ids[1]);
    assert_eq!(received.payload, packet(2, 3, 9));
    endpoint.close();
    task.await.unwrap().unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn dynamic_handle_ownership_keeps_clones_alive_and_last_drop_removes_peer() {
    let (a_socket, b_socket) = sockets();
    let (a, ad) = PeerEndpoint::new(
        StaticPrivateKey::from_bytes([91; 32]),
        a_socket,
        EndpointConfig::default(),
    );
    let (b, bd) = PacketEndpoint::new(
        StaticPrivateKey::from_bytes([92; 32]),
        b_socket,
        EndpointConfig::default(),
    );
    let at = ad.spawn(&Executor::new());
    let bt = bd.spawn(&Executor::new());
    let b_id = b.add_peer(config(a.public_key(), None, 1)).await.unwrap();
    let peer = a
        .add_peer(config(
            b.public_key(),
            Some(SocketAddress::local_ipv4(49001)),
            2,
        ))
        .await
        .unwrap();
    peer.send_ip_packet(&packet(1, 2, 1)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(60), b.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        packet(1, 2, 1)
    );
    let clone = peer.clone();
    drop(peer);
    b.send_ip_packet(&packet(2, 1, 2)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(60), clone.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        packet(2, 1, 2)
    );
    assert!(matches!(
        a.add_peer(config(b.public_key(), None, 2)).await,
        Err(PeerError::DuplicatePublicKey)
    ));
    drop(clone);
    // Re-register the other side too, exercising stale-key cleanup on both endpoints.
    b.remove_peer(b_id).await.unwrap();
    let new_id = b.add_peer(config(a.public_key(), None, 1)).await.unwrap();
    assert_ne!(new_id, b_id);
    // Registration of the same key proves the old configuration was removed.
    let replacement = a
        .add_peer(config(
            b.public_key(),
            Some(SocketAddress::local_ipv4(49001)),
            2,
        ))
        .await
        .unwrap();
    assert!(matches!(
        replacement.send_ip_packet(&packet(1, 3, 0)).await,
        Err(PeerError::WrongPeer)
    ));
    replacement.send_ip_packet(&packet(1, 2, 3)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(60), b.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        packet(1, 2, 3)
    );
    tokio::time::advance(Duration::from_secs(121)).await;
    b.send_ip_packet(&packet(2, 1, 4)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(60), replacement.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        packet(2, 1, 4)
    );
    a.close();
    b.close();
    at.await.unwrap().unwrap().unwrap();
    bt.await.unwrap().unwrap().unwrap();
    assert!(replacement.recv().await.is_none());
    assert!(b.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn packet_removal_clears_routes_and_never_reuses_ids() {
    let (socket, _remote) = sockets();
    let (endpoint, driver) = PacketEndpoint::new(
        StaticPrivateKey::from_bytes([91; 32]),
        socket,
        EndpointConfig::default(),
    );
    let remote_key = BuiltinCrypto::x25519_pubkey(&StaticPrivateKey::from_bytes([92; 32]));
    let task = driver.spawn(&Executor::new());
    let first = endpoint
        .add_peer(config(remote_key, None, 2))
        .await
        .unwrap();
    endpoint
        .set_persistent_keepalive(first, Some(Duration::from_secs(25)))
        .await
        .unwrap();
    endpoint.remove_peer(first).await.unwrap();
    assert!(matches!(
        endpoint.send_ip_packet(&packet(1, 2, 0)).await,
        Err(EndpointError::Engine(crate::EngineError::NoIpRoute(_)))
    ));
    let second = endpoint
        .add_peer(config(remote_key, None, 2))
        .await
        .unwrap();
    assert_ne!(first, second);
    assert!(matches!(
        endpoint.remove_peer(first).await,
        Err(EndpointError::Configuration(DeviceError::UnknownPeer))
    ));
    endpoint.remove_peer(second).await.unwrap();
    // No configured peers does not close the direct receive stream.
    tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
        .await
        .unwrap_err();
    endpoint.close();
    task.await.unwrap().unwrap().unwrap();
    assert!(endpoint.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn cancelled_registration_after_driver_reply_does_not_leak_configuration() {
    use rama_core::futures::poll;
    let (socket, _remote) = sockets();
    let (endpoint, mut driver) = PacketEndpoint::new(
        StaticPrivateKey::from_bytes([91; 32]),
        socket,
        EndpointConfig::default(),
    );
    let remote_key = BuiltinCrypto::x25519_pubkey(&StaticPrivateKey::from_bytes([92; 32]));
    let mut pending = Box::pin(endpoint.add_peer(config(remote_key, None, 2)));
    assert!(poll!(&mut pending).is_pending());
    let command = driver.commands.recv().await.unwrap();
    driver.command(command).await.unwrap();
    assert_eq!(driver.delivery.len(), 1);
    // The reply is queued but has not been observed by the caller.
    drop(pending);
    driver.remove_dropped_peers();
    assert!(driver.delivery.is_empty());
    assert_eq!(driver.service.engine().device().peer_count(), 0);
    assert!(
        driver
            .service
            .engine()
            .device()
            .peer_for_ip([10, 0, 0, 2].into())
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn last_handle_drop_removes_peer_even_with_full_command_queue() {
    use rama_core::futures::poll;
    let (socket, _remote) = sockets();
    let (endpoint, mut driver) = PeerEndpoint::new(
        StaticPrivateKey::from_bytes([91; 32]),
        socket,
        EndpointConfig {
            command_capacity: NonZeroUsize::MIN,
            ..EndpointConfig::default()
        },
    );
    let remote_key = BuiltinCrypto::x25519_pubkey(&StaticPrivateKey::from_bytes([92; 32]));
    let mut pending = Box::pin(endpoint.add_peer(config(remote_key, None, 2)));
    assert!(poll!(&mut pending).is_pending());
    let command = driver.commands.recv().await.unwrap();
    driver.command(command).await.unwrap();
    let peer = pending.await.unwrap();
    let other_key = BuiltinCrypto::x25519_pubkey(&StaticPrivateKey::from_bytes([94; 32]));
    let mut queued = Box::pin(endpoint.add_peer(config(other_key, None, 3)));
    assert!(poll!(&mut queued).is_pending());
    assert_eq!(endpoint.commands.capacity(), 0);
    drop(peer);
    driver.remove_dropped_peers();
    assert!(driver.delivery.is_empty());
    assert_eq!(driver.service.engine().device().peer_count(), 0);
    drop(queued);
    endpoint.close();
    driver.run().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn full_peer_queue_drops_packets_without_stalling_driver() {
    let (a_socket, b_socket) = sockets();
    let (a, ad) = PeerEndpoint::new(
        StaticPrivateKey::from_bytes([91; 32]),
        a_socket,
        EndpointConfig {
            peer_receive_capacity: NonZeroUsize::MIN,
            ..EndpointConfig::default()
        },
    );
    let (b, bd) = PacketEndpoint::new(
        StaticPrivateKey::from_bytes([92; 32]),
        b_socket,
        EndpointConfig::default(),
    );
    let at = ad.spawn(&Executor::new());
    let bt = bd.spawn(&Executor::new());
    b.add_peer(config(a.public_key(), None, 1)).await.unwrap();
    let peer = a
        .add_peer(config(
            b.public_key(),
            Some(SocketAddress::local_ipv4(49001)),
            2,
        ))
        .await
        .unwrap();
    peer.send_ip_packet(&packet(1, 2, 0)).await.unwrap();
    b.recv().await.unwrap();
    for marker in 1..=3 {
        b.send_ip_packet(&packet(2, 1, marker)).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while peer.dropped_packets() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    peer.send_ip_packet(&packet(1, 2, 4)).await.unwrap();
    assert_eq!(b.recv().await.unwrap().payload, packet(1, 2, 4));
    assert_eq!(peer.recv().await.unwrap().payload, packet(2, 1, 1));
    a.close();
    b.close();
    at.await.unwrap().unwrap().unwrap();
    bt.await.unwrap().unwrap().unwrap();
}
