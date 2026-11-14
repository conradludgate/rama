//! Run with `--features runtime`; see ../README.md for a two-host setup.

#[cfg(target_os = "linux")]
#[path = "linux_tun/tun.rs"]
mod tun;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), rama_core::error::BoxError> {
    linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), rama_core::error::BoxError> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this example requires Linux",
    )
    .into())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs::OpenOptions,
        io::{self, Write as _},
        net::IpAddr,
        os::unix::fs::OpenOptionsExt as _,
    };

    use super::tun::WireGuardTunService;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rama_net::address::SocketAddress;
    use rama_udp::UdpPacketSocket;
    use rama_wireguard::{
        BuiltinCrypto, EndpointConfig, PacketEndpoint, PeerConfig, PublicKey, StaticPrivateKey,
        WireGuardCrypto as _,
    };
    use rand::TryRng as _;
    use tun_rs::{DeviceBuilder, Layer};
    use zeroize::Zeroizing;

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn decode_key(encoded: &str) -> Result<[u8; 32], rama_core::error::BoxError> {
        let bytes = Zeroizing::new(STANDARD.decode(encoded.trim())?);
        bytes
            .as_slice()
            .try_into()
            .map_err(|_error| invalid("expected a base64-encoded 32-byte key").into())
    }

    #[expect(
        clippy::print_stdout,
        reason = "the CLI emits public keys and interface status"
    )]
    pub(super) async fn run() -> Result<(), rama_core::error::BoxError> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.len() == 2 && args[0] == "keygen" {
            let mut bytes = Zeroizing::new([0; 32]);
            rand::rngs::SysRng.try_fill_bytes(&mut *bytes)?;
            let secret = StaticPrivateKey::from_bytes(*bytes);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&args[1])?;
            let encoded = Zeroizing::new(STANDARD.encode(*bytes));
            writeln!(file, "{}", encoded.as_str())?;
            println!(
                "{}",
                STANDARD.encode(BuiltinCrypto::x25519_pubkey(&secret).0)
            );
            return Ok(());
        }
        if args.len() == 2 && args[0] == "pubkey" {
            let encoded = Zeroizing::new(std::fs::read_to_string(&args[1])?);
            let secret = StaticPrivateKey::from_bytes(decode_key(&encoded)?);
            println!(
                "{}",
                STANDARD.encode(BuiltinCrypto::x25519_pubkey(&secret).0)
            );
            return Ok(());
        }
        if args.len() != 8 || args[0] != "run" {
            return Err(invalid("usage: linux_tun keygen PRIVATE_FILE | pubkey PRIVATE_FILE | run NAME IP/PREFIX LISTEN PRIVATE_FILE PEER_PUBLIC ENDPOINT_OR_DASH ALLOWED_IPS").into());
        }
        let (address, prefix) = args[2]
            .split_once('/')
            .ok_or_else(|| invalid("expected IP/PREFIX"))?;
        let address: IpAddr = address.parse()?;
        let prefix: u8 = prefix.parse()?;
        let listen: SocketAddress = args[3].parse()?;
        let encoded = Zeroizing::new(std::fs::read_to_string(&args[4])?);
        let secret = StaticPrivateKey::from_bytes(decode_key(&encoded)?);
        let peer_config = PeerConfig {
            public_key: PublicKey(decode_key(&args[5])?),
            allowed_ips: args[7]
                .split(',')
                .map(str::parse)
                .collect::<Result<_, _>>()?,
            preshared_key: None,
            endpoint: if args[6] == "-" {
                None
            } else {
                Some(args[6].parse()?)
            },
        };
        let socket = UdpPacketSocket::bind(listen).await?;
        let builder = DeviceBuilder::new()
            .name(&args[1])
            .layer(Layer::L3)
            .packet_information(false)
            .offload(false)
            .mtu(1420);
        let builder = match address {
            IpAddr::V4(ip) if prefix <= 32 => builder.ipv4(ip, prefix, None),
            IpAddr::V6(ip) if prefix <= 128 => builder.ipv6(ip, prefix),
            _ => return Err(invalid("invalid IP prefix length").into()),
        };
        let tun = builder.build_async()?;
        println!("{} up at {}, listening on {}", tun.name()?, args[2], listen);
        let (endpoint, driver) = PacketEndpoint::new(secret, socket, EndpointConfig::default());
        let mut task = driver.spawn(&rama_core::rt::Executor::new());
        let peer = endpoint.add_peer(peer_config).await?;
        endpoint
            .set_persistent_keepalive(peer, Some(std::time::Duration::from_secs(25)))
            .await?;
        let tunnel = WireGuardTunService::new(endpoint.clone(), tun)?;
        tokio::select! {
            result = tunnel.run() => {
                endpoint.close();
                task.await?.transpose()?;
                result?;
            }
            result = &mut task => {
                result?.transpose()?;
                return Err(invalid("WireGuard driver stopped").into());
            }
        }
        Ok(())
    }
}
