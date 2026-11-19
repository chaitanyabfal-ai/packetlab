#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
TOOLS=../../tools/pcap_analyze.py

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

BR_IF=$($SUDO docker network inspect net-a -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null || true)
if [ -z "$BR_IF" ]; then
    BR_IF="br-$($SUDO docker network inspect net-a -f '{{.Id}}' | cut -c1-12)"
fi
VX_IF=$($SUDO ip -o link show type vxlan | awk -F': ' '{print $2}' | head -1 || true)

cleanup() {
    for p in ${TD_BR_PID:-} ${TD_VX_PID:-}; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

$SUDO tcpdump -i "$BR_IF" -nn -w bridge.pcap icmp &
TD_BR_PID=$!
if [ -n "$VX_IF" ]; then
    $SUDO tcpdump -i "$VX_IF" -nn -w vxlan.pcap 'udp port 4789' &
    TD_VX_PID=$!
fi
sleep 1

IP_A=$($SUDO docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bridge-a)
IP_B=$($SUDO docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bridge-b)
$SUDO docker exec bridge-a ping -c 3 "$IP_B" >/dev/null

if [ -n "$VX_IF" ]; then
    TUN_A=$($SUDO docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tun-a)
    TUN_B=$($SUDO docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tun-b)
    $SUDO docker exec tun-a ping -c 3 "$TUN_B" >/dev/null
    echo "VXLAN MTU probe (DF pings from tun-a=$TUN_A to tun-b=$TUN_B):"
    $SUDO docker exec tun-a ping -M do -c 1 -s 1500 "$TUN_B" 2>&1 | head -2 || true
    $SUDO docker exec tun-a ping -M do -c 1 -s 1422 "$TUN_B" 2>&1 | head -2 || true
fi

sleep 1
kill ${TD_BR_PID:-0} 2>/dev/null || true
[ -n "${TD_VX_PID:-}" ] && kill "$TD_VX_PID" 2>/dev/null || true
wait 2>/dev/null || true
TD_BR_PID="" TD_VX_PID=""

echo "== bridge capture ($BR_IF) =="
python3 "$TOOLS" bridge.pcap --summary --flows
if [ -f vxlan.pcap ]; then
    echo "== vxlan capture ($VX_IF) =="
    python3 "$TOOLS" vxlan.pcap --vxlan --summary
fi
