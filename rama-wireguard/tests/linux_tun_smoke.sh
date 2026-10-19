#!/usr/bin/env bash
# Two real TUN interfaces and UDP endpoints, confined to temporary network namespaces.
# Build first: cargo build -p rama-wireguard --features runtime --example linux_tun
# Run: bash rama-wireguard/tests/linux_tun_smoke.sh target/debug/examples/linux_tun
set -euo pipefail

if [[ ${1:-} != --inside ]]; then
    binary=$(realpath "${1:-target/debug/examples/linux_tun}")
    if [[ $EUID == 0 ]]; then
        exec unshare --net bash "$0" --inside "$binary" "${@:2}"
    fi
    exec unshare --user --map-root-user --net bash "$0" --inside "$binary" "${@:2}"
fi
binary=$2
kernel=${3:-}
if [[ -n $kernel && $kernel != --kernel ]]; then
    printf 'Unknown mode: %s\n' "$kernel" >&2
    exit 2
fi
for tool in ip nsenter ping; do command -v "$tool" >/dev/null; done
scratch=$(mktemp -d)
child=
client=
server=
cleanup() {
    status=$?
    for pid in "$client" "$server" "$child"; do
        if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
    if (( status != 0 )); then
        for log in "$scratch"/*.log; do
            if [[ -f $log ]]; then cat "$log" >&2; fi
        done
    fi
    rm -rf "$scratch"
    exit "$status"
}
trap cleanup EXIT

# Holding a second network namespace by PID avoids global ip-netns mounts or names.
unshare --net sleep 300 &
child=$!
parent_net=$(readlink /proc/self/ns/net)
for _ in {1..100}; do
    if [[ $(readlink "/proc/$child/ns/net") != "$parent_net" ]]; then break; fi
    sleep 0.01
done
ip link set lo up
nsenter -t "$child" -n ip link set lo up
ip link add wg-parent type veth peer name wg-child
ip link set wg-child netns "$child"
ip addr add 192.0.2.1/30 dev wg-parent
ip link set wg-parent up
nsenter -t "$child" -n ip addr add 192.0.2.2/30 dev wg-child
nsenter -t "$child" -n ip link set wg-child up

client_public=$("$binary" keygen "$scratch/client.key")
server_public=$("$binary" keygen "$scratch/server.key")
if [[ $kernel == --kernel ]]; then
    wg=${WG:-wg}
    nsenter -t "$child" -n ip link add rama-server type wireguard
    nsenter -t "$child" -n "$wg" set rama-server private-key "$scratch/server.key" \
        listen-port 51820 peer "$client_public" allowed-ips 10.77.0.1/32,fd77::1/128
    nsenter -t "$child" -n ip addr add 10.77.0.2/24 dev rama-server
    nsenter -t "$child" -n ip link set rama-server mtu 1420 up
    printf '%s\n' 'Linux kernel WireGuard peer ready.' >"$scratch/server.log"
else
    nsenter -t "$child" -n "$binary" run rama-server 10.77.0.2/24 192.0.2.2:51820 \
        "$scratch/server.key" "$client_public" - 10.77.0.1/32,fd77::1/128 >"$scratch/server.log" 2>&1 &
    server=$!
fi
"$binary" run rama-client 10.77.0.1/24 192.0.2.1:51820 \
    "$scratch/client.key" "$server_public" 192.0.2.2:51820 10.77.0.2/32,fd77::2/128 >"$scratch/client.log" 2>&1 &
client=$!
for _ in {1..100}; do
    if ip link show rama-client >/dev/null 2>&1 && nsenter -t "$child" -n ip link show rama-server >/dev/null 2>&1; then break; fi
    sleep 0.05
done
ip link show rama-client >/dev/null
nsenter -t "$child" -n ip link show rama-server >/dev/null
cat "$scratch/client.log" "$scratch/server.log"
# Noise and malformed UDP packets must not kill either pump.
printf 'bad' >/dev/udp/192.0.2.1/51820
printf 'bad' >/dev/udp/192.0.2.2/51820
# Exercise both IP versions, including non-aligned inner lengths and full-MTU packets.
ip -6 addr add fd77::1/64 dev rama-client nodad
nsenter -t "$child" -n ip -6 addr add fd77::2/64 dev rama-server nodad
ping -n -c 3 -W 2 10.77.0.2
nsenter -t "$child" -n ping -n -c 3 -W 2 10.77.0.1
ping -n -c 2 -W 2 -s 1392 -M do 10.77.0.2
ping -6 -n -c 2 -W 2 fd77::2
nsenter -t "$child" -n ping -6 -n -c 2 -W 2 fd77::1
kill -0 "$client"
if [[ -n $server ]]; then kill -0 "$server"; fi
printf '%s\n' 'Linux TUN WireGuard smoke test passed (IPv4, IPv6, bidirectional, full MTU).'
