# rama-wireguard

Manually driven UDP adapters for `rama-wireguard-proto`, whose common modules
and types are re-exported here. `DatagramTransport` handles packet I/O;
`WireGuardService` executes engine actions over a Rama datagram socket.

Callers supply protocol time, handshake timestamps and ephemeral keys.
`WireGuardTunnelService` dispatches raw tunnel payloads through a Rama service.
Run `cargo test -p rama-wireguard --features test-utils --locked` for in-memory
UDP and cookie challenge/retry coverage.
