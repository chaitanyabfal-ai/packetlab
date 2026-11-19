#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PCAP=handshake.pcap
PORT=8000
TOOLS=../../tools/pcap_analyze.py

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

cleanup() {
    [ -n "${TD_PID:-}" ] && kill "$TD_PID" 2>/dev/null || true
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

$SUDO tcpdump -i lo -nn -w "$PCAP" "tcp port $PORT" &
TD_PID=$!
sleep 1

python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
SRV_PID=$!
sleep 1

curl -s "http://127.0.0.1:$PORT/" >/dev/null
sleep 1

kill "$SRV_PID" 2>/dev/null || true
SRV_PID=""
sleep 1
$SUDO kill "$TD_PID" 2>/dev/null || kill "$TD_PID" 2>/dev/null || true
TD_PID=""
wait 2>/dev/null || true

echo "== capture written to $PCAP =="
python3 "$TOOLS" "$PCAP" --handshake --flows --tcp
