# Video resources — packet & protocol concepts (YouTube)

Curated, lab-mapped list. Watch in the suggested order; each entry notes which
packetlab lab/doc section it supports. Links verified via web search.

## Suggested order

Foundations -> TCP handshake -> packet analysis basics -> DNS -> retransmissions
-> NAT/bridge -> Docker/VXLAN. Then re-run the labs while following along in
Wireshark.

## 1. Foundations — layers, encapsulation, what a packet is

| Video | Why | Supports |
|---|---|---|
| [CS50's Understanding Technology 2017 — "Internet" lecture](https://www.youtube.com/watch?v=n_KghQP86Sw) | IP, DNS, packets, TCP/IP, ports, protocols, UDP, ICMP — the ideal axiom-level start | deep-dive §1–3, §5–7 |
| [CS50 2020 — "Passing TCP/IP Packet 1 of 3"](https://www.youtube.com/watch?v=DcjCUdiddm4) | one packet hop-by-hop | deep-dive §11 |
| [Each layer of the OSI model and TCP/IP explained](https://www.youtube.com/watch?v=kCuyS7ihr_E) | per-layer jobs + encapsulation | deep-dive §3 |
| [TCP/IP Model Explained — 4 layers, encapsulation, OSI comparison](https://www.youtube.com/watch?v=kc3kWoMIPPE) | TCP/IP vs OSI, PDUs (segment/packet/frame) | deep-dive §3 |
| [Animated Computer Networks Full Course For Beginners (4.5h)](https://www.youtube.com/watch?v=3rfLhqRrBn0) | OSI, TCP/IP, DNS from scratch | deep-dive §1–7 |
| [Practical Networking — Networking Fundamentals playlist](https://www.youtube.com/playlist?list=PLIFyRwBY_4bRLmKfP1KnZA6rZbRHtxmXi) (Ed Harmoush) | how data actually moves through the internet | deep-dive §5, §11 |
| [Practical Networking — Subnetting Mastery playlist](https://www.youtube.com/playlist?list=PLIFyRwBY_4bQUE4IB5c4VPRyDoLgOdExE) | CIDR/subnetting, needed for lab 05's 10.99.0.0/24 | labs 04–05 |
| [Practical Networking — TCP vs UDP](https://www.youtube.com/watch?v=jE_FcgpQ7Co) | transport-layer contrast | deep-dive §6 |

## 2. Lab 01 — TCP three-way handshake

| Video | Why |
|---|---|
| [TCP 3-Way Handshake Explained — SYN, SYN-ACK, ACK + practical Wireshark lab](https://www.youtube.com/watch?v=V9wj1NiErUY) | includes a hands-on Wireshark capture — matches lab 01 exactly |
| [How the Three-Way Handshake Works? SYN, SYN-ACK, ACK](https://www.youtube.com/watch?v=p8LvU3DF1Pc) | clean animation of SYN/SYN-ACK/ACK |
| [How TCP really works — three-way handshake, TCP/IP deep dive](https://www.youtube.com/watch?v=rmFX1V49K8U) | deeper: ISNs, state machine |

## 3. Packet analysis — tcpdump / pcap / Wireshark (all labs)

| Video / channel | Why |
|---|---|
| [Chris Greer — YouTube channel](https://www.youtube.com/@ChrisGreer) | the reference channel for protocol analysis with Wireshark (Wireshark Foundation-affiliated) |
| [Use Wireshark to Analyze Network Traffic — tcpdump, pcap, display filters](https://www.youtube.com/watch?v=oy37VizASt8) | capture + `ip.src`/`ip.dst` filtering |
| [The Art of Network Engineering Ep. 103 — Chris Greer on packet capturing & Wireshark](https://www.youtube.com/watch?v=bkxvYFrkXMs) | capture points, what to look for |

## 4. Lab 02 — retransmissions, dup ACKs, RTO

| Video | Why |
|---|---|
| [Hak5 HakTip 133 — Wireshark 101: TCP Retransmissions and Duplicates](https://www.youtube.com/watch?v=tjZ2IgiG2PU) | `tcp.analysis.retransmission` / `duplicate_ack` in Wireshark |
| [How TCP RETRANSMISSIONS Work — analyzing packet loss (hands-on, pcap included)](https://www.youtube.com/watch?v=HTQLipAG27I) | RTO vs fast retransmit with a downloadable pcap to follow along |
| [TCP Duplicate ACKs Explained — how to troubleshoot them (hands-on, pcap included)](https://www.youtube.com/watch?v=Hq-nOMEPh4U) | the 3-dup-ACK rule |
| [LoveMyTool — Duplicate Packets and TCP Retransmissions](https://www.youtube.com/watch?v=Fkh2ihkZZNA) | retransmission vs duplicate vs routing loop |

## 5. Lab 03 — DNS resolution

| Video | Why |
|---|---|
| [How DNS Works Under the Hood — packet by packet](https://www.youtube.com/watch?v=3FPaTvCJojQ) | full recursive lookup, wire-level |
| [DNS Resolution, Step by Step](https://www.youtube.com/watch?v=3EvjwlQ43_4) | resolver -> root -> TLD -> authoritative |
| [how DNS works!](https://www.youtube.com/watch?v=kV1u701wxgg) | authoritative vs recursive + caching |
| [Understanding Recursive DNS Name Resolution](https://www.youtube.com/watch?v=lyX9K5a52rI) | recursion mechanics |
| [PowerCert — How a DNS Server (DNS) works](https://www.youtube.com/watch?v=mpQZVYPuDGU) | animated hierarchy overview |

## 6. Lab 05 — NAT, bridges, routing

| Video | Why |
|---|---|
| [PowerCert — NAT Explained (Network Address Translation)](https://www.youtube.com/watch?v=FTUV0t6JaDA) | animated public/private translation |
| [Network Address Translation (NAT) Explained](https://www.youtube.com/watch?v=rQta7N_HirU) | the NAT table, step by step |
| [How NAT ACTUALLY Works — packet flows, connection states](https://www.youtube.com/watch?v=o9XrodLfi48) | closest to conntrack/MASQUERADE in lab 05 |
| [NAT Masquerading — iptables tutorial](https://www.youtube.com/watch?v=kQYQ_3ayz8w) | the exact `POSTROUTING -j MASQUERADE` rule from lab 05 |

## 7. Lab 04 — Docker networking, bridges, VXLAN/tunnels

| Video | Why |
|---|---|
| [DockerCon — Deeper Dive in Docker Overlay Networks](https://www.youtube.com/watch?v=IgDLNcpmfqI) | namespaces, VXLAN, netlink, kv-store — how Docker really builds overlays |
| [Docker Networking — Bridge / Host / Overlay drivers](https://www.youtube.com/watch?v=2bn5_FJJu8w) | all three drivers with timestamps |
| [Docker bridge network deep dive (with live demos)](https://www.youtube.com/watch?v=Tx12haz-4VA) | containers pinging via bridge IPs |
| [Docker Networking Explained Visually — bridge networks, IPs, ports, DNS](https://www.youtube.com/watch?v=LV56F-VvYh0) | why containers can't use localhost |
| [VXLAN Part 1 — Encapsulating the network](https://www.youtube.com/watch?v=RSbbIMwgUys) | underlay/overlay, VTEP |
| [VxLAN Part 2 — Header Format and Encapsulation](https://www.youtube.com/watch?v=jjr8aIIRkYc) | VNI + header math (the +50 bytes of lab 04) |
| [VxLAN Part 1 — How VxLAN Works](https://www.youtube.com/watch?v=YNqKDI_bnPM) | vendor-neutral overview |

## Tips

- After each video, reproduce it with the matching lab (`labs/0X-*/run.sh`) and
  cross-check in Wireshark using `docs/wireshark-filters.md`.
- For retransmission videos that ship a pcap, open it in Wireshark and also run
  `python3 tools/pcap_analyze.py <file> --retrans --tcp` to see the same events
  the bundled analyzer detects.
- Offline practice anytime: `make fixtures` then analyze `fixtures/*.pcap`.
