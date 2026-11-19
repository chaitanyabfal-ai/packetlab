#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

SUBNET=10.99.0.0/24
UPLINK=$($SUDO ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
UPLINK=${UPLINK:-eth0}

$SUDO iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE 2>/dev/null || true
$SUDO iptables -D FORWARD -i br0 -o "$UPLINK" -j ACCEPT 2>/dev/null || true
$SUDO iptables -D FORWARD -i "$UPLINK" -o br0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

$SUDO ip netns del client 2>/dev/null || true
$SUDO ip link del br0 2>/dev/null || true
$SUDO ip link del veth0 2>/dev/null || true

if [ -f /tmp/packetlab_ip_forward.prev ]; then
    $SUDO sysctl -w "net.ipv4.ip_forward=$(cat /tmp/packetlab_ip_forward.prev)"
    rm -f /tmp/packetlab_ip_forward.prev
fi

rm -f br0.pcap uplink.pcap

echo "teardown complete"
