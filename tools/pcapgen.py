#!/usr/bin/env python3
"""Generate synthetic pcap fixtures for offline packet-lab drills."""

import argparse
import os
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def eth(dst, src, ethertype, payload):
    return bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) \
        + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ident=0x1234, ttl=64):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, ttl, proto, 0,
                      bytes(int(x) for x in src.split(".")),
                      bytes(int(x) for x in dst.split(".")))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, seq, ack, flags, window, payload=b"", options=b""):
    off = (20 + len(options) + 3) // 4
    options = options + b"\x00" * (off * 4 - 20 - len(options))
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (off << 12) | flags,
                      window, 0, 0) + options
    return hdr, payload


def tcp_packet(src, dst, sport, dport, seq, ack, flags, window, payload=b"", options=b"", ident=0x1234):
    hdr, payload = tcp(sport, dport, seq, ack, flags, window, payload, options)
    pseudo = bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split(".")) \
        + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    csum = checksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return ipv4(src, dst, 6, hdr + payload, ident=ident)


def udp_packet(src, dst, sport, dport, payload, ident=0x1234):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split(".")) \
        + struct.pack("!BBH", 0, 17, length)
    csum = checksum(pseudo + hdr + payload)
    if csum == 0:
        csum = 0xFFFF
    hdr = hdr[:6] + struct.pack("!H", csum)
    return ipv4(src, dst, 17, hdr + payload, ident=ident)


def icmp_echo(ident, seq, payload=b"packetlab", itype=8):
    hdr = struct.pack("!BBHHH", itype, 0, 0, ident, seq)
    csum = checksum(hdr + payload)
    return struct.pack("!BBHHH", itype, 0, csum, ident, seq) + payload


def opt_mss(mss):
    return struct.pack("!BBH", 2, 4, mss)


def opt_wscale(shift):
    return struct.pack("!BBB", 3, 3, shift)


def opt_sack_permitted():
    return struct.pack("!BB", 4, 2)


def opt_timestamps(tsval, tsecr):
    return struct.pack("!BBII", 8, 10, tsval, tsecr)


def dns_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(txid, qname, qtype=1, rd=True):
    flags = 0x0100 if rd else 0
    return struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0) + dns_name(qname) + struct.pack("!HH", qtype, 1)


def dns_response(txid, qname, qtype, answers, rcode=0, aa=False):
    flags = 0x8000 | 0x0100 | 0x0080 | (0x0400 if aa else 0) | rcode
    msg = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0)
    msg += dns_name(qname) + struct.pack("!HH", qtype, 1)
    for rtype, ttl, rdata in answers:
        msg += struct.pack("!H", 0xC00C) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return msg


CLIENT_MAC = "02:00:00:00:00:02"
SERVER_MAC = "02:00:00:00:00:01"
CLIENT = "10.0.0.2"
SERVER = "10.0.0.1"


def gen_handshake():
    pkts = []
    t0 = 1_700_000_000.0
    opts = opt_mss(1460) + opt_sack_permitted() + opt_timestamps(1000, 0) + opt_wscale(7)
    p = tcp_packet(CLIENT, SERVER, 49152, 80, 1000, 0, 0x02, 64240, options=opts)
    pkts.append((t0, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    opts2 = opt_mss(1460) + opt_sack_permitted() + opt_timestamps(5000, 1000) + opt_wscale(7)
    p = tcp_packet(SERVER, CLIENT, 80, 49152, 7000, 1001, 0x12, 64240, options=opts2)
    pkts.append((t0 + 0.0004, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    p = tcp_packet(CLIENT, SERVER, 49152, 80, 1001, 7001, 0x10, 64240)
    pkts.append((t0 + 0.0008, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    req = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    p = tcp_packet(CLIENT, SERVER, 49152, 80, 1001, 7001, 0x18, 64240, payload=req)
    pkts.append((t0 + 0.0010, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    p = tcp_packet(SERVER, CLIENT, 80, 49152, 7001, 1001 + len(req), 0x10, 64240)
    pkts.append((t0 + 0.0014, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    body = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    p = tcp_packet(SERVER, CLIENT, 80, 49152, 7001, 1001 + len(req), 0x18, 64240, payload=body)
    pkts.append((t0 + 0.0016, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    p = tcp_packet(CLIENT, SERVER, 49152, 80, 1001 + len(req), 7001 + len(body), 0x11, 64240)
    pkts.append((t0 + 0.0020, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    p = tcp_packet(SERVER, CLIENT, 80, 49152, 7001 + len(body), 1002 + len(req), 0x11, 64240)
    pkts.append((t0 + 0.0024, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    return pkts


def gen_retrans():
    pkts = []
    t0 = 1_700_000_100.0
    c, s = 50000, 80
    seq = 5000
    payload = b"x" * 100
    p = tcp_packet(CLIENT, SERVER, c, s, seq, 0, 0x18, 64240, payload=payload, ident=1)
    pkts.append((t0, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    p = tcp_packet(SERVER, CLIENT, s, c, 9000, seq, 0x10, 64240, ident=2)
    pkts.append((t0 + 0.001, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    p = tcp_packet(CLIENT, SERVER, c, s, seq, 0, 0x18, 64240, payload=payload, ident=3)
    pkts.append((t0 + 1.0, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    p = tcp_packet(SERVER, CLIENT, s, c, 9000, seq, 0x10, 64240, ident=4)
    pkts.append((t0 + 1.001, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    p = tcp_packet(CLIENT, SERVER, c, s, seq, 0, 0x18, 64240, payload=payload, ident=5)
    pkts.append((t0 + 3.0, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    p = tcp_packet(SERVER, CLIENT, s, c, 9000, seq + 100, 0x10, 64240, ident=6)
    pkts.append((t0 + 3.001, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    seq2 = seq + 100
    for i, (seqn, ts) in enumerate([(seq2, t0 + 3.010), (seq2 + 100, t0 + 3.020), (seq2 + 200, t0 + 3.030)]):
        p = tcp_packet(CLIENT, SERVER, c, s, seqn, 0, 0x18, 64240, payload=b"y" * 100, ident=10 + i)
        pkts.append((ts, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    for i, ts in enumerate([3.040, 3.050, 3.060, 3.065]):
        p = tcp_packet(SERVER, CLIENT, s, c, 9000, seq2 + 100, 0x10, 64240, ident=20 + i)
        pkts.append((t0 + ts, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    p = tcp_packet(CLIENT, SERVER, c, s, seq2 + 100, 0, 0x18, 64240, payload=b"y" * 100, ident=24)
    pkts.append((t0 + 3.070, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    p = tcp_packet(SERVER, CLIENT, s, c, 9000, seq2 + 300, 0x10, 64240, ident=25)
    pkts.append((t0 + 3.080, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    return pkts


def gen_dns():
    pkts = []
    t0 = 1_700_000_200.0
    resolver = "192.168.1.1"
    client = "192.168.1.50"
    q = dns_query(0x1A2B, "www.example.com", 1)
    p = udp_packet(client, resolver, 53000, 53, q)
    pkts.append((t0, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    cname_rdata = dns_name("example.com")
    a_rdata = bytes([93, 184, 216, 34])
    answers = [(5, 300, cname_rdata), (1, 300, a_rdata)]
    r = dns_response(0x1A2B, "www.example.com", 1, answers)
    p = udp_packet(resolver, client, 53, 53000, r)
    pkts.append((t0 + 0.012, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    q = dns_query(0x1A2C, "www.example.com", 28)
    p = udp_packet(client, resolver, 53001, 53, q)
    pkts.append((t0 + 0.020, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    aaaa = bytes.fromhex("26062800022000010248189325c81946")
    r = dns_response(0x1A2C, "www.example.com", 28, [(28, 300, aaaa)])
    p = udp_packet(resolver, client, 53, 53001, r)
    pkts.append((t0 + 0.030, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    q = dns_query(0x1A2D, "no-such-name.example.com", 1)
    p = udp_packet(client, resolver, 53002, 53, q)
    pkts.append((t0 + 0.040, eth(CLIENT_MAC, SERVER_MAC, 0x0800, p)))
    r = dns_response(0x1A2D, "no-such-name.example.com", 1, [], rcode=3)
    p = udp_packet(resolver, client, 53, 53002, r)
    pkts.append((t0 + 0.050, eth(SERVER_MAC, CLIENT_MAC, 0x0800, p)))
    return pkts


def gen_vxlan():
    pkts = []
    t0 = 1_700_000_300.0
    outer_src, outer_dst = "172.17.0.2", "172.17.0.3"
    inner = eth("02:00:00:aa:00:02", "02:00:00:aa:00:01", 0x0800,
                ipv4("10.10.0.2", "10.10.0.1", 1, icmp_echo(1, 1), ident=99))
    vxlan_hdr = struct.pack("!I", 0x08000000 | 42) + b"\x00" * 4
    outer = udp_packet(outer_src, outer_dst, 40000, 4789, vxlan_hdr + inner, ident=7)
    pkts.append((t0, eth("02:00:00:00:0a:02", "02:00:00:00:0a:03", 0x0800, outer)))
    reply_inner = eth("02:00:00:aa:00:01", "02:00:00:aa:00:02", 0x0800,
                      ipv4("10.10.0.1", "10.10.0.2", 1, icmp_echo(1, 1, itype=0), ident=100))
    outer2 = udp_packet(outer_dst, outer_src, 4789, 40000, vxlan_hdr + reply_inner, ident=8)
    pkts.append((t0 + 0.001, eth("02:00:00:00:0a:03", "02:00:00:00:0a:02", 0x0800, outer2)))
    return pkts


def write_pcap(path, packets, linktype=1):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, data in packets:
            sec = int(ts)
            frac = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, frac, len(data), len(data)))
            fh.write(data)


FIXTURES = {
    "handshake.pcap": gen_handshake,
    "retrans.pcap": gen_retrans,
    "dns.pcap": gen_dns,
    "vxlan.pcap": gen_vxlan,
}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Write synthetic pcap fixtures.")
    ap.add_argument("--out", help="output directory (default: fixtures/)")
    ap.add_argument("--name", help="write a single fixture by name, to stdout path --out")
    args = ap.parse_args(argv)
    outdir = args.out or "fixtures"
    os.makedirs(outdir, exist_ok=True)
    names = [args.name] if args.name else sorted(FIXTURES)
    for name in names:
        path = os.path.join(outdir, name)
        write_pcap(path, FIXTURES[name]())
        print("wrote %s (%d packets)" % (path, len(FIXTURES[name]())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
