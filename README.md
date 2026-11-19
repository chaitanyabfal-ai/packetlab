# packetlab

Self-driven protocol and packet-practice labs for Linux. Each lab captures real
traffic with `tcpdump`, decodes it with the bundled dependency-free analyzer (or
Wireshark), and asks you to explain what you saw at the packet level.

Coverage:

- TCP three-way handshake and connection teardown
- TCP retransmissions: RTO backoff vs. fast retransmit on duplicate ACKs
- DNS resolution: queries, CNAME chains, A/AAAA, TTLs, NXDOMAIN, recursion flags
- Tunnelling with Docker networks: bridges, VXLAN overlay encapsulation, MTU effects
- Packet flow through a Linux bridge and NAT (iptables MASQUERADE, conntrack)

## Layout

```
tools/pcap_analyze.py   dependency-free pcap analyzer (TCP flows, handshakes,
                        retransmissions, DNS decode, VXLAN inner-packet decode)
tools/pcapgen.py        synthetic pcap fixture generator (offline drills)
tools/test_tools.py     unit tests: fixtures round-trip through the analyzer
labs/01-tcp-handshake/          capture + analyze a real 3-way handshake
labs/02-tcp-retransmissions/    force loss with netem, observe RTO/fast-retransmit
labs/03-dns-resolution/         capture port 53, decode queries and answers
labs/04-docker-networks-tunnels/ bridges, overlay/VXLAN, tunnel MTU
labs/05-bridge-nat/             netns + veth + bridge + MASQUERADE trace
docs/architecture.md            whole-picture component + packet-path diagrams (Mermaid)
docs/architecture-diagram.svg   rendered architecture diagram (make diagram)
docs/deep-dive.md               concepts from first principles to deep dive, axiom by axiom
docs/deep-dive.pdf              PDF rendering of the deep dive (`make pdf`; needs
                                `pip install -r tools/requirements-docs.txt`, fonts in assets/fonts/)
docs/wireshark-filters.md       display-filter cheat sheet for every lab
docs/findings-template.md       template for recording observations per lab
```

## Prerequisites

- Linux host with root (`sudo`) for the live-capture labs
- `tcpdump` (`apt install tcpdump` / `dnf install tcpdump`)
- `python3` >= 3.8 (no pip packages needed; the analyzer is stdlib-only)
- `dig` (`apt install dnsutils` / `dnf install bind-utils`) for lab 03
- Docker Engine for lab 04 (single-node swarm is enough)
- Wireshark optional: any `.pcap` produced here opens directly in Wireshark/tshark

Only capture traffic on networks you own or are authorized to observe.

## Quickstart

```sh
make test        # run analyzer unit tests (no root needed)
make fixtures    # write synthetic pcaps into fixtures/
make analyze FILE=fixtures/handshake.pcap MODE="--handshake --flows"
make diagram     # regenerate docs/architecture-diagram.svg
make pdf         # regenerate docs/deep-dive.pdf (pip install -r tools/requirements-docs.txt first)
```

New here? Read [docs/deep-dive.md](docs/deep-dive.md) (concepts from axioms to
deep dive) and [docs/architecture.md](docs/architecture.md) (whole-picture
diagram) before running the labs.

Then pick a lab:

```sh
cd labs/01-tcp-handshake && sudo ./run.sh
```

Every lab has a `README.md` with objectives, steps, observation questions, and a
cleanup path, plus a `run.sh` that wires capture -> traffic -> analysis together.
Labs 01-03 work on `lo`; labs 04-05 need Docker and root.

## Offline mode

No root, no network? Generate the bundled fixtures and analyze them:

```sh
make fixtures
python3 tools/pcap_analyze.py fixtures/retrans.pcap --retrans
python3 tools/pcap_analyze.py fixtures/dns.pcap --dns
python3 tools/pcap_analyze.py fixtures/vxlan.pcap --vxlan
```

`fixtures/handshake.pcap`, `retrans.pcap`, `dns.pcap` and `vxlan.pcap` model a
handshake, RTO backoff + fast retransmit, a CNAME/A/AAAA/NXDOMAIN exchange, and a
VXLAN-encapsulated ICMP echo respectively.

## Analyzer usage

```sh
python3 tools/pcap_analyze.py capture.pcap                 # all sections
python3 tools/pcap_analyze.py capture.pcap --handshake     # SYN/SYN-ACK/ACK + RTT + options
python3 tools/pcap_analyze.py capture.pcap --retrans       # retransmissions, dup ACKs, kind
python3 tools/pcap_analyze.py capture.pcap --flows         # per-flow stats
python3 tools/pcap_analyze.py capture.pcap --tcp           # every TCP packet
python3 tools/pcap_analyze.py capture.pcap --dns           # decoded DNS messages
python3 tools/pcap_analyze.py capture.pcap --vxlan         # VXLAN outer + inner packets
python3 tools/pcap_analyze.py capture.pcap --host 10.0.0.1 --port 80 --json
```
