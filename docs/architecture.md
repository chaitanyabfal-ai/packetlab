# packetlab — architecture

Whole-picture view of the project: what runs where, which artifacts flow where,
and how one packet travels through each lab topology.

Rendered diagram: [architecture-diagram.svg](architecture-diagram.svg)
(regenerate with `make diagram` — `tools/diagram.py`, stdlib only, no graphviz).

## Component map

```mermaid
flowchart LR
    subgraph HOST["Linux host (root for live labs)"]
        subgraph OBS["Observe & analyze toolchain"]
            DRIVERS["labs 01-03 drivers<br/>curl / http.server / dig / tc netem"]
            TCPDUMP["tcpdump -i lo|eth0 -w *.pcap<br/>(AF_PACKET tap)"]
            PCAPGEN["tools/pcapgen.py<br/>fixtures/*.pcap (offline)"]
            ANALYZE["tools/pcap_analyze.py<br/>TCP flows / handshake / retrans / DNS / VXLAN"]
            TESTS["tools/test_tools.py<br/>8 unittests, no root needed"]
            OUT["docs/findings-template.md<br/>+ Wireshark / tshark"]
        end
        subgraph KERN["Kernel networking — lab 05"]
            NS["netns client<br/>10.99.0.2/24"]
            VETH["veth pair"]
            BR0["bridge br0<br/>10.99.0.1/24"]
            ROUTE["routing table + ip_forward"]
            NAT["iptables nat POSTROUTING<br/>MASQUERADE + conntrack"]
        end
        subgraph DOCK["Docker — lab 04"]
            SWARM["docker swarm init"]
            NETA["net-a: bridge network<br/>br-&lt;id&gt; + containers"]
            TUN0["tun0: overlay network<br/>VXLAN VNI over UDP/4789"]
            GRE["GRE tunnel<br/>netns g1/g2 (ip tunnel)"]
        end
        ETH0["eth0 — host uplink"]
    end
    INET["Internet / WAN"]

    DRIVERS --> TCPDUMP --> ANALYZE --> OUT
    PCAPGEN --> ANALYZE
    TESTS --> ANALYZE
    NS --> VETH --> BR0 --> ROUTE --> NAT --> ETH0 --> INET
    NETA --> ETH0
    TUN0 -->|"VXLAN encap, outer UDP/4789"| ETH0
    GRE --> ETH0
```

## Artifact flow

```
labs/*/run.sh ──tcpdump──> labs/*/*.pcap ──> tools/pcap_analyze.py ──> terminal report / --json
                                                        │
tools/pcapgen.py ──> fixtures/*.pcap ──────────────────┘   (offline, no root)
                                                          │
                                          docs/findings-template.md + Wireshark
```

`.pcap` and `fixtures/` are gitignored; everything else is source.

## Packet paths per lab

### Lab 01 — TCP handshake (loopback)

```mermaid
sequenceDiagram
    participant C as client :49152
    participant K as kernel lo
    participant S as server :8000
    C->>K: SYN seq=ISN_c (options: MSS, WS, SACK, TS)
    K->>S: SYN seq=ISN_c
    S->>K: SYN-ACK seq=ISN_s ack=ISN_c+1
    K->>C: SYN-ACK
    C->>K: ACK ack=ISN_s+1   ← handshake RTT measured here
    K->>S: ACK
    Note over C,S: data + FIN teardown (4-way)
```

Analyzer: `--handshake --flows --tcp` reports ISNs, options, RTT per flow.

### Lab 02 — retransmissions (loopback + netem loss)

```
client ──seg seq=X──X──> (lost by netem)
client ──seg seq=X──> at RTO+1s        (retransmission, backoff)
client ──seg seq=X──> at RTO+3s        (backoff doubles)
server ──ACK=X──> server ──ACK=X──> server ──ACK=X──>  (3 dup ACKs)
client ──seg seq=X──> immediately      (fast retransmit, within ~1 RTT)
```

Analyzer: `--retrans` labels each retransmission `rto` or `fast-retransmit`
with `since_first` and `dup_acks_before`.

### Lab 03 — DNS (uplink, UDP/53)

```mermaid
sequenceDiagram
    participant C as stub (host)
    participant R as resolver (RD=1)
    participant A as authoritative (AA=1, via +trace)
    C->>R: query txid=0x1a2b www.example.com A (RD=1)
    R-->>C: response txid=0x1a2b CNAME + A, TTL=300, RA=1
    C->>R: query AAAA / MX / nonexistent (rcode=NXDOMAIN)
    C->>A: dig @8.8.8.8 — direct, skips local resolver
```

Analyzer: `--dns` decodes txid pairing, flags, questions, answers with TTLs.

### Lab 04 — Docker bridge vs. overlay (VXLAN)

```
bridge path : container ──veth──> br-<id> ──L2──> other container        (plain frames on the bridge)
overlay path: container ──veth──> vxlan dev ──encap──> outer IP/UDP/4789 ──> eth0 ──> peer host ──> decap ──> peer container
              inner frame = eth + ip + tcp/udp/icmp, VNI selects the L2 segment
GRE path    : netns g1 ──gre tunnel (24 B hdr)──> netns g2
MTU math    : VXLAN +50 B (20 IP + 8 UDP + 8 VXLAN + 14 eth)  → 1500 becomes 1450
              GRE +24 B (4 GRE + 20 IP)                            → 1500 becomes 1476
```

Analyzer: `--vxlan` prints outer src/dst + VNI + decoded inner packet
(see `fixtures/vxlan.pcap` offline).

### Lab 05 — bridge + NAT (netns → bridge → route → SNAT)

```
netns client 10.99.0.2 ──veth1/veth0──> br0 (L2 forward, MACs untouched)
        ──> routing decision (ip_forward=1, dst not local)
        ──> iptables nat POSTROUTING MASQUERADE (src IP → host uplink IP, conntrack entry)
        ──> eth0 ──> Internet
reply: Internet ──> conntrack ──> de-NAT ──> br0 ──> veth ──> client
```

`trace.sh` captures on `br0` and on the uplink simultaneously: same flow,
different src MAC (L2) and src IP (NAT) at each tap.

## Repo layout

```
tools/    pcap_analyze.py (decoder), pcapgen.py (fixtures), test_tools.py (tests), diagram.py (SVG)
labs/     01 handshake · 02 retransmissions · 03 DNS · 04 docker tunnels · 05 bridge+NAT
docs/     architecture.md (this file) · architecture-diagram.svg · deep-dive.md ·
          wireshark-filters.md · findings-template.md
Makefile  test · fixtures · analyze · diagram · clean
```
