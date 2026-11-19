#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

for c in bridge-a bridge-b tun-a tun-b; do
    $SUDO docker rm -f "$c" >/dev/null 2>&1 || true
done
$SUDO docker network rm tun0 net-a >/dev/null 2>&1 || true
$SUDO docker swarm leave --force >/dev/null 2>&1 || true

$SUDO ip netns exec g1 ip link del gre1 2>/dev/null || true
$SUDO ip netns exec g2 ip link del gre1 2>/dev/null || true
$SUDO ip netns del g1 2>/dev/null || true
$SUDO ip netns del g2 2>/dev/null || true

rm -f bridge.pcap vxlan.pcap

echo "teardown complete"
