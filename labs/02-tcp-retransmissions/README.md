# Lab 02 — TCP retransmissions: RTO backoff vs. fast retransmit

Force packet loss on loopback with `tc netem`, push a larger transfer through
it, capture everything, and distinguish retransmission triggers:
retransmission timeout (RTO) with exponential backoff vs. fast retransmit after
three duplicate ACKs.

## Objectives

- Observe lost segments and their retransmissions in a capture.
- Measure RTO backoff (1s, 2s, 4s ... on loopback-scale RTTs).
- Observe duplicate ACKs and the fast-retransmit threshold (3 dup ACKs).
- Correlate both with Wireshark's `tcp.analysis.*` flags.

## Prerequisites

Root (`sudo`), `tcpdump`, `tc` (`iproute2`), `python3`. Works entirely on `lo`.

## Steps

```sh
sudo ./run.sh
```

`run.sh`:

1. Adds `tc qdisc add dev lo root netem loss 15%`.
2. Captures `tcp port 8001` on `lo`.
3. Serves a generated 4 MiB file from `python3 -m http.server 8001` and
   downloads it with `curl` (retries with `curl --retry` if the connection
   breaks).
4. Removes the netem qdisc (also done by the EXIT trap on failure).
5. Analyzes with `--retrans --flows --tcp`.

Manual variant with more control over loss:

```sh
sudo tc qdisc add dev lo root netem loss 20% delay 5ms
sudo tcpdump -i lo -nn -w retrans.pcap 'tcp port 8001' &
python3 -m http.server 8001 --bind 127.0.0.1 &
curl -s --retry 5 http://127.0.0.1:8001/big.bin -o /dev/null
sudo pkill tcpdump
sudo tc qdisc del dev lo root
python3 ../../tools/pcap_analyze.py retrans.pcap --retrans --flows
```

In Wireshark: `tcp.analysis.retransmission`, `tcp.analysis.fast_retransmission`,
`tcp.analysis.duplicate_ack`.

## Questions to answer (record in FINDINGS.md)

1. How many retransmissions did the analyzer find, and of which segments?
2. For RTO-triggered retransmissions, what are the intervals between
   successive retransmissions of the same segment? Do they double?
3. How many duplicate ACKs preceded the fast retransmit, and how quickly
   did it fire relative to the RTT?
4. What does the receiver's ACK number tell you about which byte it is
   missing? Why do duplicate ACKs repeat the same ACK number?
5. Why does the sender's congestion window matter here (cwnd vs. ssthresh)?
6. What happens to the transfer time compared to a loss-free run?

## Offline drill

```sh
make -C ../.. fixtures
python3 ../../tools/pcap_analyze.py ../../fixtures/retrans.pcap --retrans --flows
```

The fixture contains two RTO retransmissions with 1s then 2s backoff, followed
by a fast retransmit after 3 duplicate ACKs.

## Cleanup

`run.sh` always restores `lo` (`tc qdisc del dev lo root`) via its trap.
Verify with `tc qdisc show dev lo` — it should be empty afterwards.
