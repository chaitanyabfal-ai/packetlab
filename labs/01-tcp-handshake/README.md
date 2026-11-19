# Lab 01 — TCP three-way handshake

Capture a real TCP connection on loopback with `tcpdump`, then decode the
SYN / SYN-ACK / ACK exchange, the negotiated options, and the FIN teardown.

## Objectives

- See the 3-way handshake and 4-way teardown on the wire.
- Read initial sequence numbers and how each side acknowledges them.
- Decode SYN options: MSS, window scale, SACK-permitted, timestamps.
- Measure handshake RTT from packet timestamps.

## Prerequisites

Root (`sudo`), `tcpdump`, `curl`, `python3`. No external network needed.

## Steps

```sh
sudo ./run.sh
```

`run.sh` does the following:

1. Starts `tcpdump -i lo -w handshake.pcap 'tcp port 8000'`.
2. Starts `python3 -m http.server 8000` on 127.0.0.1.
3. Runs one `curl` request against it.
4. Stops capture and server, then runs the analyzer:
   `tools/pcap_analyze.py handshake.pcap --handshake --flows --tcp`.

Manual alternative:

```sh
sudo tcpdump -i lo -nn -w handshake.pcap 'tcp port 8000' &
python3 -m http.server 8000 --bind 127.0.0.1 &
curl -s http://127.0.0.1:8000/ > /dev/null
sudo pkill tcpdump
python3 ../../tools/pcap_analyze.py handshake.pcap --handshake --flows
```

Open the pcap in Wireshark too: `wireshark handshake.pcap` and use the filters
from `docs/wireshark-filters.md` (`tcp.handshake`, `tcp.options.mss_val`).

## Questions to answer (record in FINDINGS.md)

1. Which side sent the first SYN, and what was its initial sequence number?
   Is it random? (Compare two runs.)
2. How does the server's SYN-ACK acknowledge the client ISN?
3. What MSS, window scale, SACK and timestamp options were negotiated?
4. What is the measured handshake RTT on loopback? Why is it sub-millisecond?
5. Which packet carries the first application bytes, and what does its
   seq/ack pair look like relative to the ISNs?
6. Describe the teardown: how many FINs, and in what order?

## Offline drill

```sh
make -C ../.. fixtures
python3 ../../tools/pcap_analyze.py ../../fixtures/handshake.pcap --handshake --flows
```

## Cleanup

`run.sh` removes its server and capture processes. Delete `handshake.pcap`
when done (pcaps are gitignored).
