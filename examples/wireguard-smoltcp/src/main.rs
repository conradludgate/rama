//! Two virtual TCP hosts connected by encrypted UDP on loopback. No privileges required.
use rama_core::rt::Executor;
use rama_net::{address::SocketAddress, stream::Socket as _};
use rama_udp::UdpPacketSocket;
use rama_wireguard::{EndpointConfig, PacketEndpoint, PeerConfig, StaticPrivateKey};
use rama_wireguard_smoltcp::VirtualNetwork;
use rand::TryRng as _;
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(io::Error::other)?;
    Ok(bytes)
}

#[tokio::main(flavor = "current_thread")]
#[expect(
    clippy::print_stdout,
    reason = "the demo prints its topology and verified echo"
)]
async fn main() -> Result<(), rama_core::error::BoxError> {
    let message = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Hello over virtual TCP, smoltcp and Rama WireGuard!".to_owned());
    let client_socket = UdpPacketSocket::bind(SocketAddress::local_ipv4(0)).await?;
    let server_socket = UdpPacketSocket::bind(SocketAddress::local_ipv4(0)).await?;
    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;
    let (client, client_driver) = PacketEndpoint::new(
        StaticPrivateKey::from_bytes(random()?),
        client_socket,
        EndpointConfig::default(),
    );
    let (server, server_driver) = PacketEndpoint::new(
        StaticPrivateKey::from_bytes(random()?),
        server_socket,
        EndpointConfig::default(),
    );
    let exec = Executor::new();
    let client_task = client_driver.spawn(&exec);
    let server_task = server_driver.spawn(&exec);
    let psk = random()?;
    server
        .add_peer(PeerConfig {
            public_key: client.public_key(),
            preshared_key: Some(psk),
            endpoint: None,
            allowed_ips: vec!["10.77.0.1/32".parse()?],
        })
        .await?;
    client
        .add_peer(PeerConfig {
            public_key: server.public_key(),
            preshared_key: Some(psk),
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.77.0.2/32".parse()?],
        })
        .await?;
    let (client_net, client_net_driver) = VirtualNetwork::new(
        client.clone(),
        Ipv4Addr::new(10, 77, 0, 1),
        u64::from_le_bytes(random()?),
    );
    let (server_net, server_net_driver) = VirtualNetwork::new(
        server.clone(),
        Ipv4Addr::new(10, 77, 0, 2),
        u64::from_le_bytes(random()?),
    );
    let client_net_task = tokio::spawn(client_net_driver.run());
    let server_net_task = tokio::spawn(server_net_driver.run());
    let mut listener = server_net.listen(7000)?;
    println!("WireGuard UDP: {client_addr} <-> {server_addr}");
    println!("Virtual TCP: 10.77.0.1:49152 -> 10.77.0.2:7000");
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            async {
                let (mut stream, _remote) = listener.accept().await?;
                let (mut read, mut write) = tokio::io::split(&mut stream);
                tokio::io::copy(&mut read, &mut write).await?;
                write.shutdown().await
            },
            async {
                let stream = client_net
                    .connect(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 7000))
                    .await?;
                let (mut read, mut write) = tokio::io::split(stream);
                let (_, echoed) = tokio::try_join!(
                    async {
                        write.write_all(message.as_bytes()).await?;
                        write.shutdown().await
                    },
                    async {
                        let mut echoed = Vec::new();
                        read.read_to_end(&mut echoed).await?;
                        io::Result::Ok(echoed)
                    }
                )?;
                if echoed != message.as_bytes() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "virtual TCP echo mismatch",
                    ));
                }
                Ok(())
            }
        )
    })
    .await;
    client.close();
    server.close();
    client_task.await?.transpose()?;
    server_task.await?.transpose()?;
    client_net_task.await??;
    server_net_task.await??;
    result??;
    println!("Verified TCP echo ({} bytes): {message}", message.len());
    Ok(())
}
