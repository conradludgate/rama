//! Deterministic packet delivery using only the public engine API.
use rama_net::{
    address::SocketAddress,
    ip::{EcnCodepoint, Ipv4PacketHeader},
};
use rama_wireguard_proto::{
    BuiltinCrypto, Device, EngineError, EphemeralPrivateKey, PeerConfig, PeerId, StaticPrivateKey,
    Tai64n, WireGuardAction, WireGuardDatagram, WireGuardEngine, WireGuardMaintenance,
};
use std::{collections::VecDeque, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Side {
    A,
    B,
}
impl Side {
    pub(super) fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
    pub(super) fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}
pub(super) struct Packet {
    pub(super) from: Side,
    pub(super) source: SocketAddress,
    pub(super) datagram: WireGuardDatagram,
}
impl Packet {
    pub(super) fn kind(&self) -> u32 {
        u32::from_le_bytes(self.datagram.payload[..4].try_into().unwrap())
    }
    pub(super) fn duplicate(&self) -> Self {
        Self {
            from: self.from,
            source: self.source,
            datagram: WireGuardDatagram {
                destination: self.datagram.destination,
                payload: self.datagram.payload.clone(),
            },
        }
    }
}
pub(super) struct Network {
    pub(super) engines: [WireGuardEngine<BuiltinCrypto>; 2],
    pub(super) peers: [PeerId; 2],
    pub(super) addresses: [SocketAddress; 2],
    pub(super) now: Duration,
    pub(super) wire: VecDeque<Packet>,
    pub(super) received: Vec<(Side, Vec<u8>)>,
    fresh: u8,
}
impl Network {
    pub(super) fn new() -> Self {
        let addresses = [
            SocketAddress::local_ipv4(45000),
            SocketAddress::local_ipv4(45001),
        ];
        let mut a = WireGuardEngine::new(Device::<BuiltinCrypto>::new(
            StaticPrivateKey::from_bytes([1; 32]),
        ));
        let mut b = WireGuardEngine::new(Device::<BuiltinCrypto>::new(
            StaticPrivateKey::from_bytes([2; 32]),
        ));
        let ap = a
            .add_peer(&PeerConfig {
                public_key: b.device().public_key(),
                preshared_key: None,
                endpoint: Some(addresses[1]),
                allowed_ips: vec!["10.77.0.2/32".parse().unwrap()],
            })
            .unwrap();
        let bp = b
            .add_peer(&PeerConfig {
                public_key: a.device().public_key(),
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec!["10.77.0.1/32".parse().unwrap()],
            })
            .unwrap();
        Self {
            engines: [a, b],
            peers: [ap, bp],
            addresses,
            now: Duration::ZERO,
            wire: VecDeque::new(),
            received: Vec::new(),
            fresh: 2,
        }
    }
    fn ephemeral(&mut self) -> EphemeralPrivateKey {
        self.fresh = self.fresh.checked_add(1).unwrap();
        EphemeralPrivateKey::from_bytes([self.fresh; 32])
    }
    fn enqueue(&mut self, from: Side, datagram: WireGuardDatagram) {
        self.wire.push_back(Packet {
            from,
            source: self.addresses[from.index()],
            datagram,
        });
    }
    pub(super) fn handshake(&mut self, side: Side) {
        let ephemeral = self.ephemeral();
        let timestamp = Tai64n::from_unix_duration(
            Duration::from_secs(1_700_000_000)
                + self.now
                + Duration::from_nanos(u64::from(self.fresh)),
        );
        let i = side.index();
        let datagram = self.engines[i]
            .start_handshake_auto(self.peers[i], timestamp, ephemeral)
            .unwrap();
        self.enqueue(side, datagram);
    }
    pub(super) fn advance(&mut self, now: Duration) {
        assert!(now >= self.now);
        self.now = now;
        for side in [Side::A, Side::B] {
            for action in self.engines[side.index()].tick(now).unwrap() {
                match action {
                    WireGuardMaintenance::Send(packet) => self.enqueue(side, packet),
                    WireGuardMaintenance::HandshakeRequired(_) => self.handshake(side),
                }
            }
        }
    }
    pub(super) fn deliver(&mut self, mut packet: Packet) -> Result<(), EngineError> {
        let target = packet.from.other();
        assert_eq!(packet.datagram.destination, self.addresses[target.index()]);
        let ephemeral = (packet.kind() == 1).then(|| self.ephemeral());
        for action in self.engines[target.index()].receive_ip_datagram(
            packet.source,
            &mut packet.datagram.payload,
            ephemeral,
        )? {
            match action {
                WireGuardAction::Send(packet) => self.enqueue(target, packet),
                WireGuardAction::Receive(packet) => self.received.push((target, packet.payload)),
            }
        }
        Ok(())
    }
    pub(super) fn drain(&mut self) {
        for _ in 0..100 {
            let Some(packet) = self.wire.pop_front() else {
                return;
            };
            self.deliver(packet).unwrap();
        }
        assert!(self.wire.is_empty(), "protocol did not settle");
    }
    pub(super) fn establish(&mut self) {
        self.handshake(Side::A);
        self.drain();
    }
    pub(super) fn send(&mut self, side: Side, marker: u8) -> Vec<u8> {
        let mut bytes = [0; 64];
        let source = side.index() as u8 + 1;
        let destination = side.other().index() as u8 + 1;
        let packet = Ipv4PacketHeader {
            source: [10, 77, 0, source].into(),
            destination: [10, 77, 0, destination].into(),
            protocol: 253,
            ttl: 64,
            ecn: EcnCodepoint::NotEct,
        }
        .encode(&[marker], &mut bytes)
        .unwrap()
        .to_vec();
        if let Some(datagram) = self.engines[side.index()].send_ip_packet(&packet).unwrap() {
            self.enqueue(side, datagram);
        }
        packet
    }
}
