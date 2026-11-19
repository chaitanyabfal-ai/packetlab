#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

SUBNET=10.99.0.0/24
GW=10.99.0.1
CLIENT=10.99.0.2
UPLINK=$($SUDO ip route get 1.1.1.1 | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
UPLINK=${UPLINK:-eth0}

echo "$($SUDO sysctl -n net.ipv4.ip_forward)" > /tmp/packetlab_ip_forward.prev

$SUDO ip netns add client
$SUDO ip link add veth0 type veth peer name veth1
$SUDO ip link set veth1 netns client
$SUDO ip link add br0 type bridge
$SUDO ip link set veth0 master br0
$SUDO ip addr add "$GW/24" dev br0
$SUDO ip link set br0 up
$SUDO ip link set veth0 up
$SUDO ip netns exec client ip addr add "$CLIENT/24" dev veth1
$SUDO ip netns exec client ip link set veth1 up
$SUDO ip netns exec client ip link set lo up
$SUDO ip netns exec client ip route add default via "$GW"

$SUDO sysctl -w net.ipv4.ip_forward=1
$SUDO iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE
$SUDO iptables -A FORWARD -i br0 -o "$UPLINK" -j ACCEPT
$SUDO iptables -A FORWARD -i "$UPLINK" -o br0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "setup complete:"
echo "  netns client=$CLIENT/24 via br0=$GW, default gw $GW"
echo "  MASQUERADE $SUBNET -> $UPLINK, ip_forward=1"
$SUDO bridge link
$SUDO iptables -t nat -L POSTROUTING -n --line-numbers | grep MASQUERADE || true
