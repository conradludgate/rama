# rama-wireguard-proto

WireGuard wire formats, cryptographic primitives and configured device state.
`Device<C>` coordinates peer identities, handshakes, cookies, transport sessions
and allowed-IP routing. Cryptographic randomness and I/O are supplied by callers.
Peer removal clears configuration and owned routes; peer IDs are never reused.

The built-in provider requires `rama-crypto/rustcrypto`. This crate uses std.
Run `cargo test -p rama-wireguard-proto --locked` for protocol and device tests.
