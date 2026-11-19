#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
TOOLS=../../tools/pcap_analyze.py

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

UPLINK=$($SUDO ip route get 1.1.1.1 | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
UPLINK=${UPLINK:-eth0}

cleanup() {
    for p in ${TD_BR_PID:-} ${TD_UP_PID:-}; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

$SUDO tcpdump -i br0 -nn -w br0.pcap &
TD_BR_PID=$!
$SUDO tcpdump -i "$UPLINK" -nn -w uplink.pcap "icmp or port 80 or port 443" &
TD_UP_PID=$!
sleep 1

$SUDO ip netns exec client ping -c 3 1.1.1.1 || true
$SUDO ip netns exec client curl -s --max-time 10 http://example.com/ -o /dev/null || true
sleep 1

kill ${TD_BR_PID:-0} 2>/dev/null || true
kill ${TD_UP_PID:-0} 2>/dev/null || true
wait 2>/dev/null || true
TD_BR_PID="" TD_UP_PID=""

echo "== conntrack entries for 10.99.0.2 =="
$SUDO conntrack -L 2>/dev/null | grep 10.99.0.2 || $SUDO grep 10.99.0.2 /proc/net/nf_conntrack 2>/dev/null || echo "(no conntrack tool; check /proc/net/nf_conntrack)"

echo "== br0 capture (inside the bridge) =="
python3 "$TOOLS" br0.pcap --summary --flows
echo "== uplink capture (after NAT) =="
python3 "$TOOLS" uplink.pcap --summary --flows
