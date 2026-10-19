//! Linux layer-3 TUN packet I/O over a WireGuard endpoint.
//!
//! Protocol state, UDP I/O and scheduling belong to the endpoint's socket driver.
//! Configure addresses and routes with [`tun_rs::DeviceBuilder`] or the operating system.

use rama_core::telemetry::tracing;
use rama_wireguard::{EndpointError, PacketEndpoint, TunnelPacket};
use std::io;
use tun_rs::AsyncDevice;

/// Connects a Linux TUN interface to an independently driven WireGuard endpoint.
/// Requires direct packet mode, so peer receivers cannot compete with TUN I/O.
pub(super) struct WireGuardTunService {
    endpoint: PacketEndpoint,
    tun: AsyncDevice,
}
impl WireGuardTunService {
    /// Uses a configured layer-3 interface and an endpoint whose driver is running.
    /// Create the device with `Layer::L3`, `packet_information(false)` and
    /// `offload(false)`. The MTU must leave room for WireGuard overhead (usually 1420).
    pub(super) fn new(endpoint: PacketEndpoint, tun: AsyncDevice) -> io::Result<Self> {
        if tun.mtu()? > 65_472 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN MTU exceeds the WireGuard UDP payload limit",
            ));
        }
        Ok(Self { endpoint, tun })
    }

    /// Copies IP packets until cancelled, the endpoint closes, or TUN I/O fails.
    pub(super) async fn run(self) -> Result<(), TunServiceError> {
        let mut buffer = vec![0; 65_536];
        loop {
            enum Event {
                Ip(io::Result<usize>),
                Packet(Option<TunnelPacket>),
            }
            let event = tokio::select! {
                result = self.tun.recv(&mut buffer) => Event::Ip(result),
                packet = self.endpoint.recv() => Event::Packet(packet),
            };
            match event {
                Event::Ip(result) => {
                    let length = result?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TUN interface closed",
                        )
                        .into());
                    }
                    let Ok(packet) = rama_net::ip::IpPacket::parse(&buffer[..length]) else {
                        continue;
                    };
                    if packet.as_bytes().len() > usize::from(self.tun.mtu()?) {
                        continue;
                    }
                    match self.endpoint.send_ip_packet(packet.as_bytes()).await {
                        Ok(()) => {}
                        Err(EndpointError::Engine(error)) => {
                            tracing::debug!(?error, "discarding unroutable IP packet")
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Event::Packet(Some(packet)) => {
                    if self.tun.send(&packet.payload).await? != packet.payload.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "short TUN packet write",
                        )
                        .into());
                    }
                }
                Event::Packet(None) => return Err(EndpointError::Closed.into()),
            }
        }
    }
}

/// Errors returned by the Linux TUN pump.
#[derive(Debug)]
pub(super) enum TunServiceError {
    Endpoint(EndpointError),
    Io(io::Error),
}
impl std::fmt::Display for TunServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for TunServiceError {}
impl From<io::Error> for TunServiceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<EndpointError> for TunServiceError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}
