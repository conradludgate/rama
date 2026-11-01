# rama-wireguard-proto

WireGuard packet formats, Noise IKpsk2 handshakes, transport protection and
cookie primitives for Rama. Initially based on
[conradludgate/rustyguard](https://github.com/conradludgate/rustyguard).

- `proto`: checked wire layouts, framing and TAI64N timestamps.
- `crypto`: owned secret keys, a synchronous provider contract, the RustCrypto
  implementation, handshake/PSK/MAC/cookie operations and transport replay state.

The caller supplies timestamps, ephemeral randomness and packet storage. This
crate performs no socket I/O and reads no clock. Source-bound cookies include
address family, IP and UDP port. Transport replay state is committed only after
successful authentication, and counters are rejected before nonce exhaustion.
The `crypto` module's key operations support caller-owned packet buffers.

This crate currently uses `std`; transitive Rama dependencies do not establish
`no_std` or embedded support. Device/engine orchestration is a later stack layer.

```sh
cargo test -p rama-wireguard-proto --locked
cargo check -p rama-wireguard-proto --no-default-features --locked
```
