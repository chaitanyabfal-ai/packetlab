# Wireshark / tshark display-filter cheat sheet

Every `.pcap` produced by these labs opens directly in Wireshark or with
`tshark -r file.pcap -Y '<filter>'`.

## Lab 01 — TCP handshake

| Filter | Shows |
|---|---|
| `tcp.flags.syn==1 && tcp.flags.ack==0` | client SYNs (connection attempts) |
| `tcp.flags.syn==1 && tcp.flags.ack==1` | server SYN-ACKs |
| `tcp.handshake` | all handshake packets |
| `tcp.flags==0x12` | SYN-ACK by raw flags |
| `tcp.options.mss_val` | negotiated MSS per SYN |
| `tcp.options.wscale.shift` | window-scale factor |
| `tcp.analysis.initial_rtt` | measured handshake RTT |
| `tcp.flags.fin==1` | teardown FINs |

## Lab 02 — Retransmissions

| Filter | Shows |
|---|---|
| `tcp.analysis.retransmission` | all retransmitted segments |
| `tcp.analysis.fast_retransmission` | fast retransmits (3+ dup ACKs) |
| `tcp.analysis.duplicate_ack` | duplicate ACKs |
| `tcp.analysis.ack_rtt` | ACK-based RTT samples |
| `tcp.analysis.rto` | packets where RTO was the trigger |
| `tcp.analysis.lost_segment` | gaps indicating loss |

Compare `frame.time_delta` between successive retransmissions of the same
segment: RTO retransmissions back off exponentially (~1s, 2s, 4s on `lo`),
fast retransmits happen within one RTT.

## Lab 03 — DNS

| Filter | Shows |
|---|---|
| `dns` | all DNS traffic |
| `dns.flags.response==0` | queries |
| `dns.flags.response==1` | responses |
| `dns.qry.type==1` / `==28` | A / AAAA queries |
| `dns.flags.rcode==3` | NXDOMAIN responses |
| `dns.flags.recursive_desired==1` | RD set (stub -> resolver) |
| `dns.cname` | CNAME chain answers |
| `dns.resp.ttl` | answer TTLs |
| `dns.flags.authoritative==1` | authoritative answers (from +trace) |

## Lab 04 — Docker networks & tunnels

| Filter | Shows |
|---|---|
| `vxlan` | VXLAN-encapsulated frames (outer UDP/4789) |
| `udp.port==4789` | raw overlay traffic between swarm nodes |
| `icmp` | inner ICMP once decoded |
| `arp` | bridge learning / neighbor discovery on `br-*` |
| `tcp.port==2375 || tcp.port==2376` | Docker API / swarm traffic |

## Lab 05 — Bridge & NAT

| Filter | Shows |
|---|---|
| `ether.src` / `ether.dst` | MAC rewriting across the bridge vs. after routing |
| `ip.src` / `ip.dst` | IP rewriting by MASQUERADE |
| `icmp` | ping through the NAT |
| `tcp` | forwarded flows with rewritten source IP |
| `arp` | gateway resolution on `br0` |

## General

| Filter | Shows |
|---|---|
| `tcp.stream eq N` | one TCP conversation end-to-end |
| `ip.addr==10.0.0.2` | everything to/from a host |
| `frame.len > 1500` | jumbo frames |
| `tcp.len > 0` | data-carrying segments only |
