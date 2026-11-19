#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PCAP=retrans.pcap
PORT=8001
TOOLS=../../tools/pcap_analyze.py
LOSS="${LOSS:-15%}"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

cleanup() {
    $SUDO tc qdisc del dev lo root 2>/dev/null || true
    [ -n "${TD_PID:-}" ] && kill "$TD_PID" 2>/dev/null || true
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

$SUDO tc qdisc replace dev lo root netem loss "$LOSS"
echo "loss on lo: $LOSS"

$SUDO tcpdump -i lo -nn -w "$PCAP" "tcp port $PORT" &
TD_PID=$!
sleep 1

BIG=$(mktemp)
head -c 4194304 /dev/urandom > "$BIG"
SRV_DIR=$(dirname "$BIG")
(cd "$SRV_DIR" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
SRV_PID=$!
sleep 1

curl -s --retry 5 --max-time 60 "http://127.0.0.1:$PORT/$(basename "$BIG")" -o /dev/null || true
sleep 1

kill "$SRV_PID" 2>/dev/null || true
SRV_PID=""
sleep 1
$SUDO kill "$TD_PID" 2>/dev/null || kill "$TD_PID" 2>/dev/null || true
TD_PID=""
wait 2>/dev/null || true
rm -f "$BIG"

echo "== capture written to $PCAP =="
python3 "$TOOLS" "$PCAP" --retrans --flows
