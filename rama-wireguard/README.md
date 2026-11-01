# rama-wireguard

WireGuard endpoints, a socket driver and Rama UDP/TUN integration. The protocol,
cryptography, peer state and deterministic engine live in
[`rama-wireguard-proto`](../rama-wireguard-proto) and are re-exported here. The
built-in provider uses `rama-crypto/rustcrypto`.

The protocol crate performs no socket I/O and takes protocol time, timestamps and
ephemeral keys as inputs. This crate supplies those inputs and executes I/O.
`DatagramTransport` lives in `transport`, outside the protocol/device layer.
The manual `WireGuardTunnelService::run_receive_loop` handles incoming traffic
and handler replies only; callers must schedule protocol maintenance separately.
Use a runtime endpoint and its driver for automatic scheduling.

## Protocol engine and IP routing

`device::WireGuardEngine` is independent of the async runtime and OS interface.
Call `tick(elapsed)` before processing I/O and at least once per second, using a
monotonic duration from a consistent origin. It emits `WireGuardMaintenance`:

- `Send(datagram)`: write the datagram to its UDP destination.
- `HandshakeRequired(peer)`: supply fresh ephemeral randomness and a wall-clock
  TAI64N timestamp to `start_handshake_auto`, then transmit the initiation.

The engine owns five-second retry rate limiting, a 90-second retry budget,
keepalives after unanswered incoming traffic, initiator rekeying at 120 seconds,
per-key rejection at 180 seconds, and transport counter limits. Expiry applies to
current, previous and unconfirmed receive keys. Optional persistent keepalives are
configured with `set_persistent_keepalive`. Expired retries release pending keys
and queued packets. One outbound IP packet per peer is retained during a handshake.
Only nonempty transport data arms a keepalive reply; empty keepalives and key
confirmations do not solicit replies.
If confirmation is lost and no confirmed send keys remain, queued IP traffic can
request a new handshake without waiting for unconfirmed receive keys to expire.

Configure `PeerConfig::allowed_ips` with the peer's inner IP prefixes. The engine
uses the most specific destination prefix to choose an outgoing peer, and the
same table to validate incoming sources. Empty allowed IPs accept no IP traffic.
`send_ip_packet` and `receive_ip_datagram` expose this IP policy; the lower-level
`send` and `receive_datagram` methods deliberately handle arbitrary transport
payloads and do not perform IP source validation.

For established traffic with reusable buffers, `send_into(peer, payload, output)`
returns a borrowed encrypted datagram and `receive_transport_in_place(source,
datagram)` returns optional borrowed plaintext. Sending needs 32 bytes plus the
payload length rounded up to a multiple of 16; an undersized output leaves the
nonce, timers and storage unchanged. Reused padding is cleared before encryption.
Receiving authenticates before committing replay, endpoint or timer updates.
Empty confirmations and keepalives update state but return no plaintext packet.
The transport-only receiver rejects handshake/cookie messages; continue using
`receive_datagram` for those. Validate received IP sources with
`validate_ip_packet` before delivery, including removal of transport padding.

These methods avoid packet/action allocations with allocation-free crypto
providers after session setup. They do not make the async endpoint allocation
free: its owned buffers, queues and send acknowledgements are separate work.
Input bytes may change on failed authentication and must then be discarded.
The existing owned receive methods also decrypt transport input in place, then
copy the authenticated output into owned packets.

`rama-net::ip` provides reusable `IpPacket` borrowed parsing, basic IPv4/IPv6
header encoders and `IpPrefixMap` longest-prefix lookup. Parsing removes tunnel
padding using the IP length and leaves options/extension headers opaque. It does
not verify IP/transport checksums, reassemble fragments or support jumbograms.

## Async endpoint and peers

Enable `rama-wireguard/runtime` (included by `rama/wireguard`) for the async API.
`PeerEndpoint::new(private_key, socket, config)` returns an empty endpoint and
one unspawned `EndpointDriver`. Run it directly or call `driver.spawn(&exec)`
with Rama's `Executor`. No tasks are spawned for individual peers. Keep the task
handle to inspect local I/O errors; executor cancellation stops the driver.
Endpoint construction accepts only an identity and socket, so peers cannot be
preconfigured through an engine. `new_with_crypto::<C, _>` selects a custom provider.

```rust,ignore
let (endpoint, driver) = PeerEndpoint::new(private_key, socket, EndpointConfig::default());
let task = driver.spawn(&exec);
let peer = endpoint.add_peer(peer_config).await?;
peer.send_ip_packet(&packet).await?;
let received = peer.recv().await; // PeerPacket { source, payload }, without a peer ID
peer.set_persistent_keepalive(Some(Duration::from_secs(25))).await?;
drop(peer); // Last clone dropping schedules configuration and key removal.
endpoint.close();
task.await?; // Inspect the optional driver result as well.
```

Peer handles survive rekeys and endpoint roaming, and own their registration.
Clones share one receive queue. Dropping the last clone wakes the driver to remove
configuration, routes, pending handshakes, all transport key generations, timers
and queued outgoing IP packets. This removal bypasses the bounded command queue.
Peer mode exposes neither identifier-based operations nor IDs in received packets
or peer errors. Duplicate public keys are rejected rather than creating ambiguous
registrations. Cancelling an incomplete `add_peer` rolls the registration back,
even if the driver has already queued its reply.

For direct IP packet I/O, use `PacketEndpoint::new(private_key, socket, config)`.
It is the `Endpoint<PacketMode>` wrapper; `PeerEndpoint` is `Endpoint<PeerMode>`.
Packet mode exposes `add_peer(config).await -> PeerId`, `remove_peer(id).await`,
`set_persistent_keepalive(id, interval)`, routed `send_ip_packet` and `recv()`.
Peer IDs are never reused within an endpoint. Its shared receive queue is bounded
by `packet_receive_capacity`; already delivered packets can remain queued after
removal. Peer mode uses `peer_receive_capacity` for each queue and exposes sending
through its owning handles. Both modes support shutdown.

Receive overflow drops the newest packet, counted by `dropped_packets()` on the
packet endpoint or peer. Sending applies backpressure through the bounded command
queue before copying packet data. Send success means driver acceptance, not remote
delivery; during a handshake only the latest packet per peer is retained.

The sealed `ReceiveMode` trait keeps the two receive interfaces distinct. The
driver uses one dispatch map: packet mode clones the same sender for each dynamic
registration, while peer mode supplies an independent queue. There are no
competing endpoint-wide and per-peer receive paths. TUN and smoltcp require
packet mode.

The driver uses Tokio's monotonic clock, including paused test time, with a
one-second maintenance wakeup. Handshake timestamps come from the wall clock and
are kept increasing during the driver's lifetime. `close()` requests shutdown
without command queue capacity; dropping all endpoint and peer handles also
stops the driver. Receivers drain already queued packets before returning `None`.

### Incoming handshake admission

The socket driver checks handshake framing and MAC1 before generating responder
randomness or doing Noise key exchange. After 100 MAC1-valid initiations/responses
in a one-second interface-wide window, it requires a source-bound cookie. A valid
cookie then permits 20 handshakes per second with a burst of five per IPv4 address
or IPv6 /64. IPv4-mapped IPv6 shares its IPv4 budget. Peers behind one NAT share
that source budget. These are configurable defaults, not per-peer limits.

Configure them before spawning with
`driver.with_handshake_admission(HandshakeAdmissionConfig { .. })`. A zero
`handshake_threshold` always requires cookies. `source_rate`, `source_burst` and
`max_sources` control the per-source budget and memory bound; the default table
holds at most 4096 sources. Cookie-less traffic creates no source entries. A full
table refuses new sources until sufficiently idle entries can be reclaimed;
existing sources retain their own budgets.

Cookies bind the source address family, IP and UDP port. Cookie secrets rotate
after 120 seconds of use. Cookie replies are cached without immediate resends;
the initiator's retry timer drives the next exchange, including when a response
was challenged. Manual engine/service APIs retain explicit `HandshakePolicy`
control and do not automatically apply the runtime driver's admission policy.

## Linux TUN

The `linux_tun` example connects configured peers to a Linux layer-3 TUN
interface through `tun-rs`, a Linux-only development dependency. The TUN packet
pump lives in the example; the library exposes the packet endpoint API.
The endpoint's socket driver drives maintenance and obtains fresh keys/timestamps.
The TUN adapter only copies validated IPv4/IPv6 packets through the endpoint API. Invalid network packets
are discarded. TAP Ethernet frames are not supported by this IP tunnel.

Create the interface with `DeviceBuilder::layer(Layer::L3)`,
`packet_information(false)` and `offload(false)`. Addresses and OS routes remain
application configuration. Creation/configuration needs `CAP_NET_ADMIN` in the
relevant network namespace, and `/dev/net/tun` must be available. Automatic path
MTU discovery remains unimplemented. Admission uses configured handshake budgets;
it does not adapt them from CPU or queue-pressure measurements.

### Run on two hosts

Build the example:

```sh
cargo build -p rama-wireguard --features runtime --example linux_tun
```

Create a private key file on each host (mode 0600); the command prints its public
key, which you exchange with the other host:

```sh
target/debug/examples/linux_tun keygen ./private.key
```

On host A, using host B's public key and reachable UDP endpoint:

```sh
sudo target/debug/examples/linux_tun run rama-wg 10.77.0.1/24 0.0.0.0:51820 \
  ./private.key PEER_PUBLIC_KEY HOST_B_IP:51820 10.77.0.2/32
```

On host B, using host A's public key (`-` waits for an incoming initiation):

```sh
sudo target/debug/examples/linux_tun run rama-wg 10.77.0.2/24 0.0.0.0:51820 \
  ./private.key PEER_PUBLIC_KEY - 10.77.0.1/32
```

The connected `10.77.0.0/24` route goes through TUN. Test with
`ping 10.77.0.2` on host A and `ping 10.77.0.1` on host B. The UDP endpoint route
must stay outside the tunnel. The example uses MTU 1420, one peer and no preshared key. The last argument is a
comma-separated list of allowed IPv4/IPv6 prefixes.
The non-persistent interface is removed when the process closes it.

### Isolated smoke tests

These use disposable user/network namespaces with a veth pair and require
`ip`, `nsenter`, `ping`, user-namespace support and `/dev/net/tun`. They do not
change the host's interfaces or routes:

```sh
bash rama-wireguard/tests/linux_tun_smoke.sh target/debug/examples/linux_tun
```

Test against Linux kernel WireGuard instead of a second Rama endpoint with
`wireguard-tools` installed (the kernel must support WireGuard):

```sh
bash rama-wireguard/tests/linux_tun_smoke.sh target/debug/examples/linux_tun --kernel
```

`WG=/path/to/wg` selects a CLI outside `PATH`. Both modes check bidirectional
IPv4/IPv6 pings, full-MTU packets, and recovery after malformed UDP datagrams.
CI runs both modes on Linux with a 90-second deadline. On systems that restrict
unprivileged user namespaces, run the script with `sudo`; it still creates a
private network namespace before configuring interfaces. Failed runs print the
endpoint logs before cleaning up.

### Cookie and overload test coverage

The in-memory driver test forces cookie challenges in both directions and checks
that queued IP packets arrive after the retry exchanges. Admission tests use
explicit time for threshold windows, bursts/refill, source isolation, table
saturation and secret rotation. Invalid MAC1s need no randomness or source state.
Protocol scenarios cover repeated loss, reordered/duplicate data, crossed
handshakes and response-cookie caching without immediate retransmission.

A useful next kernel fixture would drive `WireGuardEngine` directly over UDP,
force Rama's cookie policy, and assert that a kernel-initiated handshake retries
with valid MAC2 before allowing data. Rama would not need a TUN device for this
fixture: it could inject and inspect inner IP packets directly. Keep the TUN
smoke test as separate coverage of OS integration.

Testing kernel-issued cookies needs a different approach. Linux enables cookie
challenges based on handshake queue pressure, with system-wide load hysteresis;
a fixed packet flood is therefore unsuitable as a deterministic CI assertion.
Use independent cookie vectors for Rama's consumer and an optional kernel load
test for stress coverage. The deterministic limiter and in-memory driver tests
do not establish kernel overload behavior or a universal safe request rate.

