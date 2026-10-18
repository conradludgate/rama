# rama-wireguard-proto

WireGuard wire formats, Noise IKpsk2 handshakes, cookies, transport encryption
and replay protection. Built-in primitives use `rama-crypto/rustcrypto`.

This std-based protocol library takes cryptographic randomness as input.
It provides no socket I/O or runtime driver.

Run `cargo test -p rama-wireguard-proto --locked` for crypto vectors and protocol tests.
