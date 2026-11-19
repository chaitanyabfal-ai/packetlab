# packetlab — from first principles to deep dive

A step-by-step explanation of every concept this project practices, starting
from the axioms (the handful of facts networking is built on) and ending at the
deep mechanics you observe in the labs. Each section ends with **where you see
it in packetlab**. Read top to bottom; each section assumes only the previous
ones.

---

## 0. How to use this doc

- Sections 1–2 are the ground: what a packet is and how layers work. Do not skip.
- Sections 3–7 are "the wire": link, IP, transport (TCP/UDP), application (DNS).
- Sections 8–9 are "the plumbing": NAT/forwarding and virtual networks/tunnels.
- Section 10 is "the microscope": how capture and analysis work.
- Section 11 walks one real packet end-to-end through the lab topologies.
- Section 12 maps every lab to concepts, commands, and analyzer modes.

If you only have 15 minutes: read 1, 2, 6 (TCP), and 12.

---

## 1. Axioms — the facts everything else is built on

Everything in packetlab reduces to six axioms. If you remember these, every
header field and every lab observation has a reason.

1. **A1 — A network moves bits over a medium.** Copper, fiber, radio. Bits are
   grouped into *frames* by the link layer. Nothing else exists physically.
2. **A2 — A link only reaches its neighbors.** Ethernet talks to devices on the
   same wire/segment (via MAC addresses). It cannot deliver to the whole
   internet by itself. (Axiom of locality.)
3. **A3 — Delivery is unreliable.** Packets can be lost, duplicated, reordered,
   or corrupted. The network does not promise anything; reliability must be
   built *on top* if you need it. This single axiom explains TCP, retransmis-
   sions, sequence numbers, and ACKs.
4. **A4 — Time exists and is measurable.** Every hop adds latency (RTT). Timers
   fire, retransmissions wait, congestion windows grow. Packet captures store
   timestamps precisely so you can measure all of this.
5. **A5 — Every layer has its own addressing.** MAC (link), IP (network),
   port (transport), name (application). Each layer only understands its own.
6. **A6 — State makes protocols work.** TCP connection state, bridge MAC tables,
   NAT conntrack entries, DNS caches: protocols keep small amounts of memory to
   turn unreliable delivery into useful behavior.

Plus the structural axiom:

0. **A0 — Encapsulation.** Each layer wraps the layer above: the IP packet
   lives inside an Ethernet frame; the TCP segment lives inside the IP packet;
   the HTTP request lives inside the TCP segment. A tunnel (VXLAN/GRE) is just
   encapsulation of a whole frame inside another packet — recursively.

```
Ethernet frame          IPv4 packet            TCP segment          HTTP
+-----------+--------+----------------------+------------------+---------+
| eth hdr   | payload| ip hdr | payload     | tcp hdr | payload| GET /.. |
+-----------+--------+----------------------+------------------+---------+
   L2 wraps L3          L3 wraps L4            L4 wraps L7
```

**Where you see it:** `tools/pcap_analyze.py` peels exactly these layers:
`parse_ethernet -> parse_ipv4 -> parse_tcp/udp -> parse_dns`, and for VXLAN
peels a *second* Ethernet/IP stack inside the UDP payload (`--vxlan`).

---

## 2. What a capture file actually is

`tcpdump -w file.pcap` writes the **libpcap format**: a 24-byte global header
(magic number, version, linktype) followed by records of
`(timestamp_sec, timestamp_usec, captured_len, original_len, packet_bytes)`.
That is all a `.pcap` is — which is why `tools/pcap_analyze.py` can read it with
`struct.unpack` and nothing else.

- **linktype** tells you the L2 framing: `1` = Ethernet, `101` = raw IP,
  `113` = Linux cooked (captures on `any`). The analyzer handles all three.
- **timestamps** are wall-clock with microsecond precision — the basis of every
  RTT/backoff measurement in labs 01–02.
- The analyzer turns bytes into `Packet` objects with typed fields
  (`tcp.seq`, `dns.answers`, `vxlan.vni`, ...), then runs per-flow state
  machines (section 6) to detect handshakes and retransmissions.

**Where you see it:** every lab writes a `.pcap`; `make fixtures` writes the
same format synthetically via `tools/pcapgen.py`, and `tools/test_tools.py`
proves the decoder round-trips them.

---

## 3. The layer model — why layers exist

Layers exist so each one can solve one problem and ignore the rest (A0).
The TCP/IP model used here has four layers; OSI has seven, the extra ones
(session/presentation) are folded into the application layer.

| Layer | Job | Header fields that matter | PDU name |
|---|---|---|---|
| 7 Application | what the data means (DNS, HTTP) | DNS msg / HTTP text | message |
| 4 Transport | end-to-end delivery between *processes* | src/dst **port**, seq, ack, flags, window | segment (TCP) / datagram (UDP) |
| 3 Network | delivery between *hosts*, possibly far away | src/dst **IP**, TTL, protocol, frag | packet |
| 2 Link | delivery between *neighbors* on one wire | src/dst **MAC**, ethertype | frame |

Key insight: **IP gives you host-to-host, TCP gives you process-to-process on
top of it, and ports are how one host runs many services at once.**

**Where you see it:** the analyzer's `proto` field (`tcp`/`udp`/`icmp`/`dns`/
`vxlan`) is exactly this stack; `--host`/`--port` filters operate at layers 3/4.

---

## 4. Layer 2 — Ethernet, MACs, ARP, bridges

An Ethernet frame is: `dst MAC (6B) | src MAC (6B) | ethertype (2B) | payload | FCS`.
`ethertype 0x0800` means "payload is IPv4" (0x0806 = ARP, VLAN tags 0x8100 in
between — the analyzer skips them).

- **MAC addresses** are flat, burned-in identifiers. They answer "which device
  on *this* wire?" (A2).
- **ARP** resolves IP → MAC on the local segment ("who has 10.0.0.1? tell
  10.0.0.2"). It only works within a broadcast domain.
- A **bridge** (e.g. `br0`, or Docker's `br-<id>`) forwards frames between its
  ports based on destination MAC, and *learns* which MAC lives on which port by
  watching source MACs (A6). It operates purely at L2: it never looks at the IP
  header, so IPs pass through unchanged.
- A **switch** is a multi-port bridge in hardware.

**Where you see it:** lab 05 — `trace.sh` captures on `br0` and shows the
client's MAC and `10.99.0.2` untouched; lab 04 — `ip link show type bridge`,
`bridge link`, and `tcpdump -i br-<id>` show plain L2 frames between containers.
Wireshark: `arp`, `ether.src`.

---

## 5. Layer 3 — IP, routing, TTL, ICMP

The IPv4 header (20 B minimum) carries: version/IHL, total length, ID,
flags/fragment offset, **TTL**, **protocol** (6=TCP, 17=UDP, 1=ICMP),
header checksum, **src IP**, **dst IP**.

- **IP addressing + subnets** (CIDR, e.g. `10.99.0.0/24`) let a router group
  destinations. Routing = **longest-prefix match** against the routing table;
  the `default` route (0.0.0.0/0) catches everything else.
- **TTL** decrements at every router; at 0 the packet is dropped and an ICMP
  time-exceeded is sent back. This is what `traceroute` measures, and it's a
  safety net against routing loops.
- **Fragmentation**: if a packet exceeds the next hop's MTU and DF (don't
  fragment) is not set, it is split; the receiver reassembles by fragment
  offset. (Tunnels make this visible — see section 9.)
- **ICMP** is IP's control channel: echo request/reply (`ping`), destination
  unreachable, time exceeded.
- Forwarding a packet *through* a host (not to it) requires
  `net.ipv4.ip_forward=1` — the heart of lab 05.

**Where you see it:** lab 05 routing from the netns through `br0` to `eth0`;
lab 04's `ping -M do -s <size>` DF probes that expose tunnel MTU limits;
analyzer `--summary` counts `icmp` packets, and the VXLAN fixture decodes inner
ICMP.

---

## 6. Layer 4 — ports, UDP, and the TCP deep dive

### 6.1 Ports and sockets

A **port** (16-bit) identifies a process on a host. A **socket** is the
`(IP, port)` pair; a TCP **connection** is identified by the 4-tuple
`(src IP, src port, dst IP, dst port)`. That 4-tuple is the analyzer's flow
key — `--flows` groups packets by exactly this.

### 6.2 UDP

UDP header = `src port | dst port | length | checksum` + payload. That's it:
no state, no ordering, no retransmission — a thin wrapper giving you ports and
a checksum over IP's best-effort delivery (A3). DNS uses UDP/53 (with TCP/53
fallback for large answers).

### 6.3 TCP — reliable, ordered bytes over an unreliable network

TCP's entire design answers axiom A3. The model: a **byte stream** identified by
32-bit **sequence numbers**. Every byte sent has a sequence number; the
receiver **ACKs the next byte it expects** (cumulative ACK).

The TCP header (20 B minimum): `src port | dst port | seq | ack | data offset
+ flags | window | checksum | urgent ptr | options`.
Flags: **SYN, ACK, FIN, RST, PSH, URG, ECE, CWR**.

**The 3-way handshake (lab 01).** Before data, both sides synchronize sequence
numbers:

```
client -> server: SYN seq=ISN_c            (ISN = initial sequence number, random for security)
server -> client: SYN-ACK seq=ISN_s ack=ISN_c+1
client -> server: ACK ack=ISN_s+1          <- handshake complete; RTT = t(ACK) - t(SYN)
```

Each SYN carries **options**: MSS (max segment size, e.g. 1460 on Ethernet
1500 − 40), window scale (the 16-bit window field is shifted, e.g. ×128),
SACK-permitted, timestamps. The analyzer prints these from `--handshake`.

**Data transfer.** Sender: `seq` = first byte of this segment. Receiver:
`ack` = next expected byte = last received + 1. Cumulative: one ACK covers
everything below it. Delayed ACKs (often every 2nd segment) trade ACK traffic
for latency.

**Loss and retransmission (lab 02).** If a segment is lost (A3), the receiver
can't advance its cumulative ACK, so it re-sends the last ACK — a **duplicate
ACK**. Two recovery mechanisms:

- **RTO (retransmission timeout):** the sender keeps a timer per outstanding
  segment. If it expires, retransmit and **double the RTO** (exponential
  backoff: ~1s, 2s, 4s ... on fast links). Lab 02's netem loss produces exactly
  this; `--retrans` shows `since_first` growing 1s → 3s.
- **Fast retransmit:** after **3 duplicate ACKs** for the same missing byte,
  retransmit immediately (within ~1 RTT) instead of waiting for the RTO. Lab
  02's fixture and live capture show `kind=fast-retransmit` with
  `dup_acks_before=3`.

**Flow control.** The receiver advertises a **window** (bytes it can buffer).
The sender never has more than `window` bytes in flight. Window scale multiplies
it. This keeps a fast sender from overrunning a slow receiver.

**Congestion control (why loss matters beyond the flow).** The sender also
keeps a **congestion window (cwnd)** limited by the network's health: slow
start (cwnd grows exponentially per RTT), congestion avoidance (+1 MSS per RTT),
and on loss: fast recovery (3 dup ACKs) or cwnd reset to 1 MSS + slow start
(RTO). Loss signals congestion (A3 interpreted), which is why retransmissions
are also a congestion signal.

**Teardown.** 4-way FIN exchange (each side FINs then ACKs the other's FIN);
the side that closes first ends in **TIME_WAIT** (2×MSL) so late packets don't
corrupt a future connection reusing the same 4-tuple.

**Where you see it:** labs 01 (`--handshake --flows --tcp`) and 02 (`--retrans`
with RTO/fast-retransmit classification, dup-ACK counting across the reverse
direction). Wireshark: `tcp.handshake`, `tcp.analysis.retransmission`,
`tcp.analysis.duplicate_ack`, `tcp.analysis.initial_rtt`.

---

## 7. Layer 7 — DNS, decoded (lab 03)

DNS turns names into addresses. The namespace is a tree: `www.example.com.`
(root `.` → `com` → `example.com` → `www`). Each **zone** is served by
**authoritative** name servers; your machine talks to a **stub resolver**
(usually your router/ISP, listed in `/etc/resolv.conf`).

A DNS message (over UDP/53): **header** (12 B: txid, flags, 4 section counts)
+ **question** + **answer** + **authority** + **additional** sections.

Header flags the labs decode:

- **QR** = query (0) or response (1)
- **RD** (recursion desired) — set by stubs: "please resolve this for me"
- **RA** (recursion available) — set by resolvers that can recurse
- **AA** (authoritative answer) — set by the zone's own servers
- **rcode**: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN (name does not exist), ...

**Resolution modes:**
- *Recursive*: stub asks resolver with RD=1; the resolver walks the tree
  (root → TLD → authoritative) and returns the final answer. One query from
  the client, many on the wire.
- *Iterative*: `dig +trace` does the walk itself, asking each server for a
  referral (NS records in the authority section); answers from the zone itself
  have AA=1.

**Records you meet in lab 03:** A (IPv4), AAAA (IPv6), CNAME (alias →
canonical name; the answer section can be a *chain*: `www.github.com CNAME
github.com` + `github.com A ...`), MX, NS, PTR (reverse), SOA, TXT.

**Names in messages use compression:** a pointer `0xC0 0x0C` refers back to
offset 12 — the analyzer's `parse_dns_name` follows these pointers, which is
why it can decode real captures, not just the fixture.

**Matching & caching:** the **txid** pairs response to query (16-bit, so
collisions are possible — hence the source port is randomized too). Answers
carry a **TTL**; resolvers cache for that long, so a second lookup for the
same name often generates *no* packet at all. NXDOMAIN is cached negatively via
the SOA record in the authority section.

**Where you see it:** lab 03 `--dns` output (txid pairing, RD/RA, CNAME chain,
TTL=300, rcode=NXDOMAIN). Wireshark: `dns.flags.response`, `dns.cname`,
`dns.resp.ttl`, `dns.flags.rcode==3`.

---

## 8. NAT and forwarding — lab 05

IPv4 has ~4.3B addresses; we ran out. **NAT** lets many private hosts
(`10.x`, `192.168.x`) share one public IP.

Mechanics (what lab 05 builds by hand):

1. `ip_forward=1` — kernel routes packets between interfaces.
2. iptables **FORWARD** chain permits the flow (and the reply, via
   `conntrack --ctstate ESTABLISHED,RELATED`).
3. **nat/POSTROUTING MASQUERADE** rewrites the *source IP* (and usually source
   port) of outgoing packets to the uplink's IP. MASQUERADE = SNAT that follows
   the interface's current address (right for DHCP uplinks).
4. **conntrack** (A6) remembers the mapping
   `10.99.0.2:51234 -> 1.1.1.1:80  <=>  <publicIP>:51234 -> 1.1.1.1:80`,
   so replies are de-NATed back to the client. `conntrack -L` shows it.

Packet-by-packet (what `trace.sh` shows): on `br0` the packet still has
src `10.99.0.2` and the client's MAC → `br0`'s MAC (L2 only, section 4). After
routing, on `eth0` the src IP is the public IP and MACs are host↔gateway —
two headers changed at two different layers, for two different reasons.

Implications: NAT breaks end-to-end reachability (no inbound connections without
port forwarding), which is why P2P/VoIP need STUN/hole-punching; some protocols
embed IPs in payload and need ALGs.

**Where you see it:** lab 05 `setup.sh`/`trace.sh`/`teardown.sh`; lab 04's
`iptables -t nat -L` shows the same MASQUERADE Docker installs automatically.
Analyzer: compare `--summary --flows` on `br0.pcap` vs `uplink.pcap`.

---

## 9. Virtual networks and tunnels — lab 04

### 9.1 Namespaces, veth, bridges

- A **network namespace** (`ip netns`) is a private copy of the kernel's
  network stack (interfaces, routes, iptables) — what a container really is.
- A **veth pair** is a virtual cable: one end in namespace A, the other in B;
  a packet entering one end exits the other.
- A **bridge** connects several veth ends (section 4). Docker's default bridge
  (`docker0`) and user bridges (`br-<id>`) are exactly this, plus iptables.

### 9.2 Docker bridge vs. overlay

- `docker network create -d bridge net-a` → a `br-<id>` bridge, veth per
  container, and iptables: a `DOCKER` chain for port publishing plus
  MASQUERADE for outbound (section 8). Containers talk at L2.
- `docker network create -d overlay tun0` (needs a swarm; one node suffices)
  → **VXLAN**: each overlay network gets a **VNI** (24-bit virtual segment ID)
  and a kernel `vxlan` device. Frames between containers on *different* hosts
  are encapsulated: `outer eth | outer IP | outer UDP dst port 4789 | VXLAN hdr
  (flags+VNI) | inner eth | inner IP | ... | payload`. The underlay only sees
  host-to-host UDP. This is A0 applied recursively: an L2 frame inside an L3
  packet.
- **MTU math (lab 04's DF probes):** outer adds 20 (IP) + 8 (UDP) + 8 (VXLAN) +
  14 (inner eth) = **50 bytes**, so a 1500-byte underlay carries 1450-byte inner
  packets: `ping -M do -s 1422` works, `-s 1500` gets "message too long".
  GRE adds 4 + 20 = **24 bytes** (1476). Fragmentation or MSS clamping handles
  the rest.

### 9.3 Why tunnels

Tunnels let you build a private L2 network on top of any L3 connectivity
(VPNs, SD-WAN, cloud overlays). Costs: extra header bytes (MTU), extra CPU
(encap/decap, checksums), and indirection (harder to debug — hence capture at
each layer, which is exactly what the labs do).

**Where you see it:** lab 04 — `ip link show type vxlan`, `docker network
inspect tun0`, `tcpdump -i <vxlan-if> udp port 4789`, MTU probes, GRE netns.
Offline: `pcap_analyze.py fixtures/vxlan.pcap --vxlan` prints outer
172.17.0.x, VNI 42, and the decoded inner ICMP echo pair. Wireshark: `vxlan`,
`udp.port==4789`.

---

## 10. Observability — how we watch packets

- **Capture point:** `tcpdump` opens an `AF_PACKET` socket — the kernel hands
  it a copy of every frame on the interface (promiscuous mode sees others'
  frames too). That's why capture needs root. It writes libpcap (section 2).
- **BPF filters** (`tcpdump 'tcp port 80'`) are compiled to bytecode and run
  *in the kernel*, so only matching packets cross to userspace.
- **Wireshark/tshark** are dissectors: they decode every layer and add
  *analysis* (`tcp.analysis.retransmission`, `duplicate_ack`, `initial_rtt`)
  computed from per-flow state — the same idea as our analyzer.
- **Our analyzer** (`tools/pcap_analyze.py`) does the same in ~600 lines of
  stdlib: parse pcap → parse eth/IP/TCP/UDP/DNS/(VXLAN) → group by 4-tuple
  flow → run small state machines (handshake detection, seq-range tracking for
  retransmissions, reverse-direction dup-ACK counting) → report human or JSON.
- **Synthetic fixtures** (`tools/pcapgen.py`) build valid packets *with real
  checksums* (IP header checksum, TCP/UDP pseudo-header checksum) and write
  them as pcap — so you can practice analysis offline and unit-test the decoder
  (`tools/test_tools.py`, 8 tests).
- **Measurement:** RTT = t(ACK) − t(SYN) from pcap timestamps; backoff =
  deltas between successive retransmissions; TTL/timestamps fields carry
  per-packet timing inside TCP options.

Only capture traffic on networks you own or are authorized to observe.

---

## 11. One packet, end to end

Walk a `curl http://example.com/` issued from lab 05's `client` namespace:

1. **App:** curl asks the stub resolver → DNS query UDP/53 to `10.99.0.1`
   (lab 03 pattern). Response cached by TTL.
2. **Transport:** curl opens a socket → **3-way handshake** with example.com's
   IP (lab 01 pattern): SYN → SYN-ACK → ACK, options negotiated.
3. **Network:** SYN packet routed: dst not local → `ip_forward` → POSTROUTING
   **MASQUERADE** rewrites src to the public IP, conntrack entry created
   (lab 05).
4. **Link:** frame leaves `eth0` with dst MAC = default gateway (ARP first).
5. **Internet:** routers forward by dst IP (TTL decrements), NAT at the edge,
   server's SYN-ACK returns, conntrack de-NATs it back to `10.99.0.2`.
6. **Data:** HTTP GET in segments; server ACKs cumulatively; any loss →
   dup ACKs → fast retransmit or RTO backoff (lab 02).
7. **Capture:** at every step, `tcpdump` on `br0` and `eth0` recorded the
   frame; the analyzer reconstructs the flow, handshake RTT, and any
   retransmissions.

Through lab 04's overlay instead, steps 3–4 are replaced by: inner frame →
VXLAN encap (VNI, UDP/4789) → underlay routing → remote host decap → inner
bridge → peer container. Same inner packet, one more layer of wrapping.

---

## 12. Lab map — concept → command → output

| Lab | Concepts (sections) | Run | Analyze | Wireshark filters |
|---|---|---|---|---|
| 01 handshake | 2, 6.3 handshake/teardown | `sudo labs/01-tcp-handshake/run.sh` | `--handshake --flows --tcp` | `tcp.handshake`, `tcp.options.mss_val` |
| 02 retransmissions | 6.3 RTO/fast-retransmit, 10 | `sudo labs/02-tcp-retransmissions/run.sh` | `--retrans --flows` | `tcp.analysis.retransmission`, `duplicate_ack` |
| 03 DNS | 7 | `sudo labs/03-dns-resolution/run.sh` | `--dns` | `dns`, `dns.cname`, `dns.resp.ttl` |
| 04 docker tunnels | 4, 8, 9 | `sudo labs/04-docker-networks-tunnels/{setup,run,teardown}.sh` | `--vxlan --summary` | `vxlan`, `udp.port==4789` |
| 05 bridge + NAT | 4, 5, 8 | `sudo labs/05-bridge-nat/{setup,trace,teardown}.sh` | `--summary --flows` on both pcaps | `ip.src`, `ether.dst`, `arp` |

Offline (no root): `make test && make fixtures`, then
`python3 tools/pcap_analyze.py fixtures/{handshake,retrans,dns,vxlan}.pcap <mode>`.

Suggested order: 01 → 03 → 02 → 05 → 04, then re-do 02 and 04 while watching
`tshark -r ... -Y '<filter>'` to cross-check the analyzer.

---

## 13. Glossary

- **ACK / cumulative ACK** — receiver tells sender the next byte it expects; one ACK covers all lower seq numbers.
- **Bridge** — L2 multi-port forwarder that learns MAC→port.
- **conntrack** — kernel table tracking NAT/flow state so replies can be mapped back.
- **cwnd / ssthresh** — TCP congestion window and its slow-start threshold.
- **DF / MTU / MSS** — don't-fragment flag / max frame size / max TCP payload per segment.
- **Encapsulation** — wrapping a whole packet/frame as the payload of another (A0); tunnels are recursive encapsulation.
- **Flow / 4-tuple** — (src IP, src port, dst IP, dst port) identifying a TCP/UDP conversation.
- **ISN** — initial sequence number; randomized per connection.
- **MASQUERADE** — SNAT using the outgoing interface's address; standard home-NAT.
- **pcap** — libpcap capture format: global header + timestamped records.
- **RTO** — retransmission timeout; doubled on each consecutive timeout (backoff).
- **RTT** — round-trip time; measured from capture timestamps.
- **TTL** — IP hop limit (and DNS cache lifetime — same word, two layers).
- **VXLAN / VNI** — L2-over-L3 tunnel over UDP/4789; VXLAN Network Identifier = virtual segment ID.
- **veth** — virtual Ethernet cable between namespaces.

See [architecture.md](architecture.md) for the whole-picture diagram and
[wireshark-filters.md](wireshark-filters.md) for the filter cheat sheet.
