# Lab 05 — Packet flow through a bridge and NAT

Build a mini "container network" by hand: a network namespace connected to a
Linux bridge via a veth pair, with iptables MASQUERADE NAT to the outside.
Then trace one packet at every hop: veth -> bridge -> routing decision ->
SNAT -> uplink, watching MAC and IP headers change.

## Objectives

- Build bridge + veth + namespace plumbing with `ip`.
- See L2 forwarding on the bridge vs. L3 routing at the gateway.
- Observe MASQUERADE rewriting the source IP (and conntrack tracking it).
- Correlate tcpdump views on `br0` vs. the uplink for the same flow.

## Topology

```
netns "client" 10.99.0.2/24  --veth-->  br0 10.99.0.1/24  -->  host uplink (NAT/MASQUERADE) --> internet
```

## Prerequisites

Root, `iproute2`, `iptables`, `tcpdump`, `conntrack` tool (or read
`/proc/net/nf_conntrack`), `ping`/`curl`.

## Steps

```sh
sudo ./setup.sh     # netns client, veth pair, br0, ip_forward, MASQUERADE
sudo ./trace.sh     # capture on br0 + uplink, then ping + curl from the ns
sudo ./teardown.sh  # remove everything
```

### What setup.sh does

```sh
ip netns add client
ip link add veth0 type veth peer name veth1
ip link set veth1 netns client
ip link add br0 type bridge
ip link set veth0 master br0
ip addr add 10.99.0.1/24 dev br0
ip link set br0 up; ip link set veth0 up
ip netns exec client ip addr add 10.99.0.2/24 dev veth1
ip netns exec client ip link set veth1 up
ip netns exec client ip link set lo up
ip netns exec client ip route add default via 10.99.0.1
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 ! -d 10.99.0.0/24 -j MASQUERADE
iptables -A FORWARD -i br0 -j ACCEPT
iptables -A FORWARD -o br0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

### What trace.sh shows

Two tcpdumps run at once (`br0` and the uplink) while the namespace pings
`1.1.1.1` and curls a website. Compare:

- On `br0`: src MAC = client veth, dst MAC = br0; src IP 10.99.0.2 unchanged.
- On the uplink: src IP rewritten to the host's uplink IP (MASQUERADE);
  MACs are the host/uplink pair.
- `conntrack -L` shows the 10.99.0.2 -> external mapping.

Analyze with the bundled tool, e.g.:

```sh
python3 ../../tools/pcap_analyze.py br0.pcap --summary --flows
python3 ../../tools/pcap_analyze.py uplink.pcap --summary --flows
```

## Questions to answer (record in FINDINGS.md)

1. At which hop does the source MAC change, and at which hop does the source
   IP change? Why the difference (L2 vs. L3 vs. NAT)?
2. What did MASQUERADE rewrite, and how did conntrack remember the mapping so
   replies could come back?
3. Why did the bridge forward the frame without touching the IP header?
4. What would happen if `ip_forward` were 0? (Try it: `sysctl -w
   net.ipv4.ip_forward=0`, re-run trace.sh, restore.)
5. Which iptables chain/table does MASQUERADE live in, and why POSTROUTING?
6. In Wireshark, filter the uplink capture for the flow and confirm only the
   outer IP changed (`ip.src` before/after).

## Cleanup

`sudo ./teardown.sh` deletes the namespace, veth, bridge, iptables rules and
restores `ip_forward` to its previous value.
