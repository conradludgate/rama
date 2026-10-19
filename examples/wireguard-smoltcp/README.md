# Virtual TCP over WireGuard

A userspace TCP network built with [smoltcp](https://docs.rs/smoltcp/0.14.0/smoltcp/)
and Rama's WireGuard endpoint. Run from the repository root:

```sh
cargo run -p rama-wireguard-smoltcp --locked
cargo run -p rama-wireguard-smoltcp --locked -- 'your message'
```

The demo starts two virtual hosts in one process:

```text
TCP client (10.77.0.1:49152)              TCP echo server (10.77.0.2:7000)
           │                                           │
     smoltcp IPv4/TCP                            smoltcp IPv4/TCP
           │ IP packets                                │ IP packets
     Rama WireGuard endpoint ← encrypted UDP → Rama WireGuard endpoint
```

Only the outer UDP sockets use the OS network stack, bound to ephemeral loopback
ports. Both TCP sockets live in smoltcp. No root, TUN/TAP device, network namespace,
interface address or OS route changes are required. The virtual addresses are
not accessible to ordinary OS TCP sockets. Fresh static keys, a shared PSK and
TCP sequence-number seeds are generated for every run; nothing is persisted.
The demo verifies every echoed byte and has a 30-second overall timeout.

## How it works

`VirtualNetwork` owns a smoltcp interface, socket set and a small `phy::Device`
with `Medium::Ip`. Its transmit tokens enqueue complete IP packets for
`PacketEndpoint::send_ip_packet`; incoming authenticated packets from `PacketEndpoint::recv`
feed its receive tokens. The WireGuard endpoint owns allowed-IP routing and
source validation. Each UDP socket has its own independently running WireGuard
driver, with all peers and cryptographic sessions managed there.

`VirtualNetwork::new` returns a network handle and a `NetworkDriver`. Run the
driver once per virtual host alongside the WireGuard driver. Application code
then uses listener and stream wrappers:

```rust,ignore
let (network, driver) = VirtualNetwork::new(endpoint, address, seed);
let task = tokio::spawn(driver.run());
let mut listener = network.listen(7000)?;
let (mut stream, remote) = listener.accept().await?;
// On the other virtual host:
let mut stream = network.connect(remote_address).await?;
stream.write_all(b"hello").await?;
```

`TcpStream` implements Tokio `AsyncRead` and `AsyncWrite`, so `split`, `copy`,
`read_to_end`, `write_all` and `shutdown` work normally. Reads and writes can run
concurrently, with bounded TCP buffers providing backpressure. `shutdown` drains
the send queue before half-closing; reads can continue until the peer sends EOF.
Dropping a stream leaves graceful teardown to the driver. Dropping the driver
wakes pending operations with an error.

The listener maintains four pending smoltcp sockets as a small accept backlog.
Each accept replenishes a slot, allowing repeated and concurrent connections.
The driver owns polling, outgoing packets and retransmission timers; application
I/O wakes it when socket state changes. It uses Tokio's monotonic clock. Device
queues have a 64-packet bound and TCP send/receive buffers are 16 KiB each. MTU
1420 keeps inner packets within the tunnel's usual size budget.

This is example integration code, limited to IPv4 and addresses in the same /24.
It does not provide DNS, forwarding or MTU discovery. Pass an endpoint configured
for a remote machine to use the same bridge across hosts, with matching allowed
IPs. The executable handles key exchange in-process for a self-contained demo.
Use a single packet consumer for each virtual interface.

## Tests

```sh
cargo test -p rama-wireguard-smoltcp --locked
```

The test uses in-memory UDP and paused Tokio time. It drops the first WireGuard
initiation, then drops traffic after TCP establishment and duplicates subsequent
packets. It checks exact 192 KiB echoes across concurrent connections and repeated accepts, exercising WireGuard retry/replay
handling, TCP retransmission, segmentation and partial reads/writes without
privileges or real-time sleeps. Another test checks that stopping the driver fails
pending accepts and connects. CI runs these tests and the real-loopback demo.
