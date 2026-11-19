# Lab 04 — Tunnelling with Docker networks: bridges, VXLAN overlay, MTU

Reproduce tunnelling concepts with Docker: a user-defined bridge, a swarm
overlay network carried over VXLAN (UDP/4789), packet inspection on the
bridge and VXLAN interfaces, and the MTU/encapsulation cost of tunnelling.
Also builds a kernel GRE tunnel between two namespaces for comparison.

## Objectives

- Inspect what `docker network create` actually builds: `br-<id>` bridges,
  veth pairs, and iptables chains.
- See VXLAN encapsulation on the wire: outer IP/UDP/4789, inner Ethernet frame.
- Measure the tunnel MTU penalty (VXLAN adds 50 bytes) with `ping -M do`.
- Compare bridge networking (L2) vs. overlay tunnelling (L2 over L3).

## Prerequisites

Root, Docker Engine (single node is enough: `docker swarm init`), `tcpdump`,
`iproute2`, and the ability to pull `alpine` (or any small image).

## Steps

```sh
sudo ./setup.sh        # swarm init + overlay network + 2 containers + gre demo
sudo ./run.sh          # captures on bridge + vxlan while pinging across
sudo ./teardown.sh     # remove containers, networks, swarm, gre tunnel
```

### Part A — user-defined bridge

`setup.sh` creates `net-a` (bridge driver). Inspect the artifacts:

```sh
docker network inspect net-a
ip link show type bridge          # br-<id>
bridge link                       # veth endpoints attached to the bridge
sudo iptables -t nat -L -n -v     # DOCKER chain + MASQUERADE rule
sudo tcpdump -i br-<id> -nn -c 20 icmp &
```

Ping between two containers on `net-a` and watch plain L2 frames on the bridge.

### Part B — overlay network over VXLAN

`setup.sh` runs `docker swarm init` and creates overlay network `tun0`
(`--attachable`), then joins containers `tun-a` and `tun-b`. Inspect:

```sh
docker network inspect tun0
ip link show type vxlan           # vxlan device(s), UDP port 4789
sudo tcpdump -i <vxlan-if> -nn -c 20 'udp port 4789' &
```

Ping `tun-a` -> `tun-b`; the capture shows outer IP/UDP/4789 packets. Decode one
with the analyzer's `--vxlan` mode (outer header + inner ICMP) or Wireshark's
`vxlan` dissector.

### Part C — tunnel MTU

VXLAN adds 50 bytes (20 IP + 8 UDP + 8 VXLAN + 14 inner Ethernet). Find the
largest DF packet that still crosses the overlay:

```sh
docker exec tun-a ping -M do -s 1500 <tun-b-ip>   # expect "message too long"
docker exec tun-a ping -M do -s 1422 <tun-b-ip>   # largest that fits (1472-50)
```

### Part D — kernel GRE tunnel between namespaces (no Docker)

`setup.sh` also creates netns `g1`/`g2` with a `gre` tunnel between them:

```sh
ip netns exec g1 ping -M do -s 1472 <g2 tunnel ip>
sudo tcpdump -i eth0 -nn 'gre' -c 10 &
```

GRE adds 24 bytes (4 GRE + 20 IP). Compare with the VXLAN overhead.

## Questions to answer (record in FINDINGS.md)

1. Which artifacts did `docker network create -d bridge` leave on the host
   (interfaces, iptables rules, chains)? Where does outbound NAT happen?
2. In the VXLAN capture, what are the outer src/dst IPs and ports, and what is
   inside the payload? Map it to the inner container IPs.
3. What VNI did the overlay use, and where does it appear in the packet?
4. Measured tunnel MTU for VXLAN and for GRE — does it match the header math?
5. Why does the bridge capture show the inner MACs directly while the VXLAN
   capture shows the host IPs on the outside?
6. When would you pick a bridge network vs. an overlay vs. host networking?

## Offline drill

```sh
make -C ../.. fixtures
python3 ../../tools/pcap_analyze.py ../../fixtures/vxlan.pcap --vxlan
```

The fixture is one VXLAN-encapsulated ICMP echo request/reply pair (VNI 42).

## Cleanup

`sudo ./teardown.sh` removes containers, networks, the swarm, the GRE tunnel
and the namespaces. Verify with `docker network ls` and `ip netns list`.
