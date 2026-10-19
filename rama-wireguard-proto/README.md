# rama-wireguard-proto

WireGuard's deterministic protocol implementation: wire formats, Noise IKpsk2
handshakes, transport encryption and replay windows, peer configuration, IP
routing and protocol timers. Initially based on
[conradludgate/rustyguard](https://github.com/conradludgate/rustyguard).

Use this crate when supplying your own packet I/O and scheduling. For Rama's UDP
socket driver, typed endpoints, peer handle lifetimes,
use [`rama-wireguard`](../rama-wireguard), which re-exports the common protocol
modules and types.

## Boundary

- `proto`: WireGuard packet layouts and framing.
- `crypto`: Noise, transport keys, cookies and the provider trait. The built-in
  provider requires `rama-crypto/rustcrypto`.
- `device`: configured peers, allowed-IP routing, handshake coordination and
  `WireGuardEngine`.

There is no direct dependency on Tokio, Rama's UDP layer or its executor. Packet
I/O and cryptographic random-key generation belong to the caller. The engine
accepts monotonic elapsed time through `tick`, handshake timestamps through
`Tai64n`, and explicit ephemeral private keys. It returns outgoing datagrams,
decrypted tunnel packets and maintenance requests for the caller to execute.

This crate currently uses `std`. Shared `rama-crypto` and `rama-net` dependencies
still pull in runtime libraries transitively; this split does not promise a
minimal transitive dependency graph or `no_std` support.

## Driving the engine

Configure a `Device<C>` with the local private key, then create a
`WireGuardEngine<C>`. Low-level users explicitly add/remove peers. The runtime
endpoint API separately enforces dynamic registration and handle ownership.

Before processing I/O, and at least once per second, call `tick(elapsed)` with a
nondecreasing duration from a consistent origin:

- `WireGuardMaintenance::Send`: transmit the returned datagram.
- `WireGuardMaintenance::HandshakeRequired`: supply fresh ephemeral randomness
  and a wall-clock timestamp to `start_handshake_auto`, then transmit its result.

`send_ip_packet` routes by the destination's longest matching allowed prefix and
queues the latest packet while waiting for a handshake. `receive_ip_datagram`
validates the authenticated peer's source prefix and removes IP padding. The
lower-level `send`/`receive_datagram` methods process raw tunnel payloads.

Protocol timing includes retries, keepalives, rekeying and expiry of every receive
key generation. Peer removal clears routes, pending handshakes, all sessions,
timers and queued packets. See the runtime crate README for deployment examples
and remaining limitations, including adaptive overload policy and MTU discovery.

## Checks

```sh
cargo check -p rama-wireguard-proto --locked
cargo test -p rama-wireguard-proto --locked
```

Tests cover known crypto vectors, handshake/cookie processing, replay/counter
limits, IP routing and protocol lifecycle using explicit virtual time. UDP,
queue ownership, cancellation and interoperability tests belong to the runtime
crate.
