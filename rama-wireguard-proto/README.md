# rama-wireguard-proto

Checked WireGuard packet formats and decoding for Rama. Initially based on
[conradludgate/rustyguard](https://github.com/conradludgate/rustyguard).

`proto` contains wire layouts, message decoding, errors and TAI64N timestamps.
There is no socket I/O, peer routing or background task in this crate.

```sh
cargo test -p rama-wireguard-proto --locked
```
