#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

$SUDO docker swarm init --advertise-addr "${ADVERTISE_ADDR:-127.0.0.1}" >/dev/null
$SUDO docker network create -d bridge net-a >/dev/null
$SUDO docker network create -d overlay --attachable tun0 >/dev/null

$SUDO docker run -d --name bridge-a --network net-a alpine sleep 3600 >/dev/null
$SUDO docker run -d --name bridge-b --network net-a alpine sleep 3600 >/dev/null
$SUDO docker run -d --name tun-a --network tun0 alpine sleep 3600 >/dev/null
$SUDO docker run -d --name tun-b --network tun0 alpine sleep 3600 >/dev/null

BR_IF=$($SUDO docker network inspect net-a -f '{{index .Options "com.docker.network.bridge.name"}}')
echo "bridge network net-a -> ${BR_IF:-br-$( $SUDO docker network inspect net-a -f '{{.Id}}' | cut -c1-12 )}"
$SUDO ip link show type vxlan || true

echo "container IPs:"
for c in bridge-a bridge-b tun-a tun-b; do
    echo "  $c: $($SUDO docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$c")"
done

$SUDO ip netns add g1
$SUDO ip netns add g2
$SUDO ip link add g1-veth type veth peer name g2-veth
$SUDO ip link set g1-veth netns g1
$SUDO ip link set g2-veth netns g2
$SUDO ip netns exec g1 ip addr add 10.77.0.1/24 dev g1-veth
$SUDO ip netns exec g2 ip addr add 10.77.0.2/24 dev g2-veth
$SUDO ip netns exec g1 ip link set g1-veth up
$SUDO ip netns exec g2 ip link set g2-veth up
$SUDO ip netns exec g1 ip tunnel add gre1 mode gre local 10.77.0.1 remote 10.77.0.2 ttl 64
$SUDO ip netns exec g2 ip tunnel add gre1 mode gre local 10.77.0.2 remote 10.77.0.1 ttl 64
$SUDO ip netns exec g1 ip addr add 10.78.0.1/24 dev gre1
$SUDO ip netns exec g2 ip addr add 10.78.0.2/24 dev gre1
$SUDO ip netns exec g1 ip link set gre1 up
$SUDO ip netns exec g2 ip link set gre1 up

echo "setup complete: net-a, tun0, containers bridge-a/bridge-b/tun-a/tun-b, gre netns g1/g2"
