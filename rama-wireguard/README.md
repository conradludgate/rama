# rama-wireguard

Rama UDP and service adapters for the deterministic `rama-wireguard-proto`
engine. Initially based on [rustyguard](https://github.com/conradludgate/rustyguard).

The caller drives `WireGuardService` receives and maintenance explicitly.
`WireGuardTunnelService::run_receive_loop` only dispatches received payloads;
it does not replace scheduling `tick` and supplying requested handshakes.
The next commit adds the bounded runtime endpoint and driver APIs.
