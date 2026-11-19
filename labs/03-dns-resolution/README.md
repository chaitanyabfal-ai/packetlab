# Lab 03 — DNS resolution on the wire

Capture UDP/53 traffic while resolving names with `dig`, then decode queries
and responses: transaction IDs, flags (RD/RA/AA), question sections, CNAME
chains, A/AAAA answers, TTLs, and NXDOMAIN.

## Objectives

- Match each DNS response to its query by transaction ID.
- Distinguish stub-resolver traffic (RD=1 to your resolver) from
  authoritative answers (AA=1, seen with `dig +trace`).
- Read CNAME chains and answer TTLs; explain caching implications.
- Decode rcode values, especially NXDOMAIN vs. NODATA.

## Prerequisites

Root (`sudo`) only for `tcpdump`; `dig` (`dnsutils` / `bind-utils`); a working
default route and resolver in `/etc/resolv.conf`.

## Steps

```sh
sudo ./run.sh
```

`run.sh`:

1. Finds the default interface (`ip route get 1.1.1.1`) and captures
   `udp port 53` on it into `dns.pcap`.
2. Runs: `dig example.com`, `dig AAAA example.com`, `dig www.github.com`
   (CNAME chain), `dig MX example.com`, `dig no-such-name-<random>.example.com`
   (NXDOMAIN), and `dig @8.8.8.8 example.com` (direct query to a public
   resolver).
3. Stops the capture and analyzes with `--dns`.

Manual variant with a full recursive walk:

```sh
IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
sudo tcpdump -i "$IFACE" -nn -w dns.pcap 'udp port 53' &
dig +trace example.com
dig @8.8.8.8 example.com
sudo pkill tcpdump
python3 ../../tools/pcap_analyze.py dns.pcap --dns
```

In Wireshark: `dns`, `dns.flags.response==1`, `dns.cname`, `dns.resp.ttl`,
`dns.flags.rcode==3`.

## Questions to answer (record in FINDINGS.md)

1. Which resolver did your stub queries go to, and was RD set? Was RA set in
   its answers?
2. Match each response to its query via `txid` — how does the analyzer show
   the pairing?
3. For a name behind a CNAME (e.g. www.github.com), what does the answer
   section contain, in what order?
4. Compare TTLs of A vs. CNAME answers. What happens on the second query for
   the same name — does your resolver still send a packet? (Try `dig` twice
   under one capture and watch the query count.)
5. What rcode did the non-existent name return, and what does the answer
   section look like for it?
6. With `dig +trace`, which servers were contacted in order (root -> TLD ->
   authoritative), and which responses had AA=1?
7. What is the difference between querying your local resolver and
   `@8.8.8.8` directly, visible in the capture?

## Offline drill

```sh
make -C ../.. fixtures
python3 ../../tools/pcap_analyze.py ../../fixtures/dns.pcap --dns
```

The fixture models an A query answered with CNAME + A, an AAAA query, and an
NXDOMAIN.

## Cleanup

`run.sh` stops its own capture. Delete `dns.pcap` when done.
