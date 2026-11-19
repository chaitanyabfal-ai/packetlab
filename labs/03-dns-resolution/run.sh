#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PCAP=dns.pcap
TOOLS=../../tools/pcap_analyze.py

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

IFACE=$($SUDO ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
IFACE=${IFACE:-eth0}
echo "capturing on $IFACE"

cleanup() {
    [ -n "${TD_PID:-}" ] && kill "$TD_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

$SUDO tcpdump -i "$IFACE" -nn -w "$PCAP" 'udp port 53' &
TD_PID=$!
sleep 1

dig +short example.com >/dev/null 2>&1 || true
dig +short AAAA example.com >/dev/null 2>&1 || true
dig +short www.github.com >/dev/null 2>&1 || true
dig +short MX example.com >/dev/null 2>&1 || true
dig +short "no-such-name-$RANDOM.example.com" >/dev/null 2>&1 || true
dig +short @8.8.8.8 example.com >/dev/null 2>&1 || true
sleep 1

$SUDO kill "$TD_PID" 2>/dev/null || kill "$TD_PID" 2>/dev/null || true
TD_PID=""
wait 2>/dev/null || true

echo "== capture written to $PCAP =="
python3 "$TOOLS" "$PCAP" --dns
