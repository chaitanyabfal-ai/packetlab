#!/usr/bin/env python3
"""Dependency-free pcap analyzer for TCP, DNS and VXLAN packet labs."""

import argparse
import ipaddress
import json
import struct
import sys
from dataclasses import dataclass, field

PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),
    0x4D3CB2A1: (">", 1_000_000_000),
}

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_SLL = 113
LINKTYPE_SLL2 = 276

TCP_FLAG_NAMES = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY",
}

DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}


@dataclass
class TCPInfo:
    sport: int = 0
    dport: int = 0
    seq: int = 0
    ack: int = 0
    flags: int = 0
    window: int = 0
    payload_len: int = 0
    options: list = field(default_factory=list)

    @property
    def flag_names(self):
        return [name for bit, name in TCP_FLAG_NAMES if self.flags & bit]


@dataclass
class UDPInfo:
    sport: int = 0
    dport: int = 0
    payload_len: int = 0


@dataclass
class DNSInfo:
    txid: int = 0
    flags: int = 0
    questions: list = field(default_factory=list)
    answers: list = field(default_factory=list)
    authorities: list = field(default_factory=list)
    additionals: list = field(default_factory=list)

    @property
    def is_response(self):
        return bool(self.flags & 0x8000)

    @property
    def rcode(self):
        return DNS_RCODES.get(self.flags & 0x000F, str(self.flags & 0x000F))

    @property
    def recursion_desired(self):
        return bool(self.flags & 0x0100)

    @property
    def recursion_available(self):
        return bool(self.flags & 0x0080)


@dataclass
class Packet:
    index: int
    ts: float
    linktype: int
    src: str = ""
    dst: str = ""
    proto: str = ""
    tcp: TCPInfo = None
    udp: UDPInfo = None
    dns: DNSInfo = None
    icmp: dict = None
    vxlan: dict = None
    length: int = 0


def read_pcap(path):
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ValueError("file too short for a pcap global header")
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in PCAP_MAGICS:
            raise ValueError("not a libpcap file (bad magic 0x%08x)" % magic)
        endian, divisor = PCAP_MAGICS[magic]
        _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
            endian + "HHiiii", header[4:24]
        )
        index = 0
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", rec)
            data = fh.read(incl)
            if len(data) < incl:
                break
            yield index, ts_sec + ts_frac / divisor, linktype & 0xFFFF, data
            index += 1


def _mac(b):
    return ":".join("%02x" % x for x in b)


def parse_ethernet(data):
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    off = 14
    while ethertype in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
        ethertype = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    return ethertype, data[off:]


def parse_sll(data):
    if len(data) < 16:
        return None
    return struct.unpack("!H", data[14:16])[0], data[16:]


def parse_ipv4(data):
    if len(data) < 20:
        return None
    v_ihl = data[0]
    if v_ihl >> 4 != 4:
        return None
    ihl = (v_ihl & 0x0F) * 4
    total_len = struct.unpack("!H", data[2:4])[0]
    flags_frag = struct.unpack("!H", data[6:8])[0]
    frag_offset = (flags_frag & 0x1FFF) * 8
    more_fragments = bool(flags_frag & 0x2000)
    proto = data[9]
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))
    payload = data[ihl:total_len] if total_len <= len(data) else data[ihl:]
    return {
        "src": src, "dst": dst, "proto": proto,
        "frag_offset": frag_offset, "more_fragments": more_fragments,
        "payload": payload,
    }


def parse_tcp(data):
    if len(data) < 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", data[:12])
    off_flags = struct.unpack("!H", data[12:14])[0]
    offset = (off_flags >> 12) * 4
    flags = off_flags & 0x01FF
    window = struct.unpack("!H", data[14:16])[0]
    options = []
    opt = data[20:offset] if offset >= 20 else b""
    i = 0
    while i < len(opt):
        kind = opt[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opt):
            break
        length = opt[i + 1]
        if length < 2 or i + length > len(opt):
            break
        body = opt[i + 2:i + length]
        if kind == 2 and len(body) == 2:
            options.append(("MSS", struct.unpack("!H", body)[0]))
        elif kind == 3 and len(body) == 1:
            options.append(("WSCALE", body[0]))
        elif kind == 4:
            options.append(("SACK_PERMITTED", True))
        elif kind == 8 and len(body) == 8:
            tsval, tsecr = struct.unpack("!II", body)
            options.append(("TIMESTAMPS", tsval, tsecr))
        else:
            options.append(("OPT%d" % kind, body.hex()))
        i += length
    payload_len = len(data[offset:]) if offset <= len(data) else 0
    return TCPInfo(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags,
                   window=window, payload_len=payload_len, options=options)


def parse_udp(data):
    if len(data) < 8:
        return None
    sport, dport, length = struct.unpack("!HHH", data[:6])
    return UDPInfo(sport=sport, dport=dport, payload_len=max(0, length - 8))


def parse_dns_name(buf, off):
    labels = []
    end = off
    jumped = False
    seen = set()
    while True:
        if off >= len(buf) or off in seen:
            raise ValueError("bad name pointer")
        seen.add(off)
        length = buf[off]
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            continue
        if off + 1 + length > len(buf):
            raise ValueError("truncated label")
        labels.append(buf[off + 1:off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), end


def _parse_rr(buf, off):
    name, off = parse_dns_name(buf, off)
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", buf[off:off + 10])
    off += 10
    rdata_off = off
    rdata = buf[off:off + rdlength]
    off += rdlength
    value = rdata.hex()
    try:
        if rtype == 1 and rdlength == 4:
            value = str(ipaddress.IPv4Address(rdata))
        elif rtype == 28 and rdlength == 16:
            value = str(ipaddress.IPv6Address(rdata))
        elif rtype in (2, 5, 12):
            value, _ = parse_dns_name(buf, rdata_off)
        elif rtype == 15 and rdlength >= 3:
            pref = struct.unpack("!H", rdata[:2])[0]
            mx, _ = parse_dns_name(buf, rdata_off + 2)
            value = "%d %s" % (pref, mx)
        elif rtype == 16:
            parts = []
            p = 0
            while p < len(rdata):
                ln = rdata[p]
                parts.append(rdata[p + 1:p + 1 + ln].decode("ascii", "replace"))
                p += 1 + ln
            value = " ".join(parts)
        elif rtype == 6:
            mname, p = parse_dns_name(buf, rdata_off)
            rname, p = parse_dns_name(buf, p)
            nums = struct.unpack("!IIIII", buf[p:p + 20])
            value = "%s %s %s" % (mname, rname, " ".join(str(n) for n in nums))
    except (ValueError, struct.error):
        pass
    return {
        "name": name, "type": DNS_TYPES.get(rtype, str(rtype)),
        "class": rclass, "ttl": ttl, "value": value,
    }, off


def parse_dns(data):
    if len(data) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    info = DNSInfo(txid=txid, flags=flags)
    off = 12
    try:
        for _ in range(qd):
            name, off = parse_dns_name(data, off)
            qtype, qclass = struct.unpack("!HH", data[off:off + 4])
            off += 4
            info.questions.append({
                "name": name, "type": DNS_TYPES.get(qtype, str(qtype)),
                "class": qclass,
            })
        for count, target in ((an, info.answers), (ns, info.authorities), (ar, info.additionals)):
            for _ in range(count):
                rr, off = _parse_rr(data, off)
                target.append(rr)
    except (ValueError, struct.error, IndexError):
        pass
    return info


def parse_icmp(data):
    if len(data) < 4:
        return None
    itype, code = data[0], data[1]
    out = {"type": ICMP_TYPES.get(itype, str(itype)), "code": code}
    if itype in (0, 8) and len(data) >= 8:
        ident, seq = struct.unpack("!HH", data[4:8])
        out["id"] = ident
        out["seq"] = seq
    return out


def parse_packet(index, ts, linktype, data):
    pkt = Packet(index=index, ts=ts, linktype=linktype, length=len(data))
    if linktype == LINKTYPE_ETHERNET:
        parsed = parse_ethernet(data)
        if not parsed:
            return pkt
        ethertype, payload = parsed
    elif linktype == LINKTYPE_RAW:
        ethertype, payload = 0x0800, data
    elif linktype == LINKTYPE_SLL:
        parsed = parse_sll(data)
        if not parsed:
            return pkt
        ethertype, payload = parsed
    else:
        return pkt
    if ethertype != 0x0800:
        return pkt
    ip = parse_ipv4(payload)
    if not ip:
        return pkt
    pkt.src, pkt.dst = ip["src"], ip["dst"]
    if ip["frag_offset"] != 0:
        pkt.proto = "ipv4-fragment"
        return pkt
    if ip["proto"] == 6:
        pkt.proto = "tcp"
        pkt.tcp = parse_tcp(ip["payload"])
    elif ip["proto"] == 17:
        pkt.proto = "udp"
        udp = parse_udp(ip["payload"])
        pkt.udp = udp
        if udp and (udp.sport == 53 or udp.dport == 53):
            pkt.dns = parse_dns(ip["payload"][8:])
        elif udp and (udp.sport == 4789 or udp.dport == 4789):
            body = ip["payload"][8:]
            if len(body) >= 8 and body[0] & 0x08:
                vni = int.from_bytes(body[1:4], "big")
                inner = parse_ethernet(body[8:])
                if inner and inner[0] == 0x0800:
                    inner_ip = parse_ipv4(inner[1])
                    if inner_ip:
                        inner_pkt = {"src": inner_ip["src"], "dst": inner_ip["dst"]}
                        if inner_ip["proto"] == 1:
                            inner_pkt["icmp"] = parse_icmp(inner_ip["payload"])
                        elif inner_ip["proto"] == 6:
                            t = parse_tcp(inner_ip["payload"])
                            if t:
                                inner_pkt["tcp"] = {
                                    "sport": t.sport, "dport": t.dport,
                                    "seq": t.seq, "ack": t.ack,
                                    "flags": t.flag_names,
                                }
                        pkt.vxlan = {"vni": vni, "inner": inner_pkt}
    elif ip["proto"] == 1:
        pkt.proto = "icmp"
        pkt.icmp = parse_icmp(ip["payload"])
    else:
        pkt.proto = "ip-proto-%d" % ip["proto"]
    return pkt


def flow_key(pkt):
    if pkt.proto == "tcp" and pkt.tcp:
        a = (pkt.src, pkt.tcp.sport)
        b = (pkt.dst, pkt.tcp.dport)
        return ("tcp",) + tuple(sorted([a, b]))
    if pkt.proto == "udp" and pkt.udp:
        a = (pkt.src, pkt.udp.sport)
        b = (pkt.dst, pkt.udp.dport)
        return ("udp",) + tuple(sorted([a, b]))
    return (pkt.proto, pkt.src, pkt.dst)


class Flow:
    def __init__(self):
        self.packets = 0
        self.data_bytes = 0
        self.first_ts = None
        self.last_ts = None
        self.retransmissions = []
        self.dup_ack_max = 0
        self._dir_state = {}
        self._handshake = {"syn": None, "synack": None, "ack": None}

    def _dir(self, key):
        if key not in self._dir_state:
            self._dir_state[key] = {"max_end": 0, "seen": {}, "last_ack": None, "dup": 0}
        return self._dir_state[key]

    def add(self, pkt):
        self.packets += 1
        if self.first_ts is None:
            self.first_ts = pkt.ts
        self.last_ts = pkt.ts
        if pkt.proto != "tcp" or not pkt.tcp:
            return
        t = pkt.tcp
        dkey = (pkt.src, t.sport, pkt.dst, t.dport)
        st = self._dir(dkey)
        if t.payload_len > 0:
            self.data_bytes += t.payload_len
            first = st["seen"].get(t.seq)
            peer = self._dir((pkt.dst, t.dport, pkt.src, t.sport))
            if first is not None or t.seq < st["max_end"]:
                self.retransmissions.append({
                    "ts": pkt.ts,
                    "from": "%s:%d" % (pkt.src, t.sport),
                    "seq": t.seq,
                    "len": t.payload_len,
                    "since_first": round(pkt.ts - (first if first is not None else st["max_end_ts"]), 6),
                    "dup_acks_before": peer["dup"],
                    "kind": "fast-retransmit" if peer["dup"] >= 3 else "rto",
                })
            else:
                st["seen"].setdefault(t.seq, pkt.ts)
            st["max_end"] = max(st["max_end"], t.seq + t.payload_len)
            st["max_end_ts"] = st["seen"].get(t.seq, pkt.ts)
        if t.flags & 0x10 and t.payload_len == 0 and not (t.flags & (0x02 | 0x01 | 0x04)):
            if st["last_ack"] == t.ack:
                st["dup"] += 1
                self.dup_ack_max = max(self.dup_ack_max, st["dup"])
            else:
                st["last_ack"] = t.ack
                st["dup"] = 0
        if t.flags & 0x02 and not t.flags & 0x10:
            if self._handshake["syn"] is None:
                self._handshake["syn"] = pkt
        elif t.flags & 0x02 and t.flags & 0x10:
            if self._handshake["synack"] is None:
                self._handshake["synack"] = pkt
        elif t.flags & 0x10 and self._handshake["syn"] is not None and self._handshake["synack"] is not None:
            if self._handshake["ack"] is None:
                self._handshake["ack"] = pkt

    def handshake_rtt(self):
        hs = self._handshake
        if hs["syn"] and hs["synack"] and hs["ack"]:
            return round(hs["ack"].ts - hs["syn"].ts, 6)
        return None


def collect(packets):
    flows = {}
    for pkt in packets:
        flows.setdefault(flow_key(pkt), Flow()).add(pkt)
    return flows


def passes_filters(pkt, host, port):
    if host and host not in (pkt.src, pkt.dst):
        return False
    if port is not None:
        if pkt.proto == "tcp" and pkt.tcp and port in (pkt.tcp.sport, pkt.tcp.dport):
            return True
        if pkt.proto == "udp" and pkt.udp and port in (pkt.udp.sport, pkt.udp.dport):
            return True
        return False
    return True


def fmt_flags(flags):
    return "".join(name[0] for bit, name in TCP_FLAG_NAMES if flags & bit) or "-"


def report(packets, modes, as_json):
    flows = collect(packets)
    out = {"packet_count": len(packets)}
    if "summary" in modes:
        protos = {}
        for pkt in packets:
            protos[pkt.proto] = protos.get(pkt.proto, 0) + 1
        out["summary"] = protos
        out["first_ts"] = packets[0].ts if packets else None
        out["last_ts"] = packets[-1].ts if packets else None
    if "flows" in modes:
        out["flows"] = [
            {
                "key": list(key),
                "packets": f.packets,
                "data_bytes": f.data_bytes,
                "duration": round(f.last_ts - f.first_ts, 6) if f.first_ts is not None else 0,
                "retransmissions": len(f.retransmissions),
                "max_dup_acks": f.dup_ack_max,
                "handshake_rtt": f.handshake_rtt(),
            }
            for key, f in sorted(flows.items(), key=lambda kv: kv[1].first_ts or 0)
        ]
    if "handshake" in modes:
        out["handshakes"] = []
        for key, f in flows.items():
            hs = f._handshake
            if hs["syn"] and hs["synack"] and hs["ack"]:
                syn = hs["syn"]
                out["handshakes"].append({
                    "client": "%s:%d" % (syn.src, syn.tcp.sport),
                    "server": "%s:%d" % (syn.dst, syn.tcp.dport),
                    "client_isn": syn.tcp.seq,
                    "server_isn": hs["synack"].tcp.seq,
                    "syn_options": [list(o) for o in syn.tcp.options],
                    "synack_options": [list(o) for o in hs["synack"].tcp.options],
                    "rtt_seconds": f.handshake_rtt(),
                })
    if "retrans" in modes:
        out["retransmissions"] = []
        for key, f in flows.items():
            for r in f.retransmissions:
                out["retransmissions"].append(dict(r, flow=[str(x) for x in key]))
        out["retransmissions"].sort(key=lambda r: r["ts"])
        out["total_retransmissions"] = len(out["retransmissions"])
    if "tcp" in modes:
        out["tcp_packets"] = [
            {
                "i": p.index, "ts": round(p.ts, 6), "src": "%s:%d" % (p.src, p.tcp.sport),
                "dst": "%s:%d" % (p.dst, p.tcp.dport), "seq": p.tcp.seq, "ack": p.tcp.ack,
                "flags": fmt_flags(p.tcp.flags), "win": p.tcp.window, "len": p.tcp.payload_len,
            }
            for p in packets if p.proto == "tcp" and p.tcp
        ]
    if "dns" in modes:
        out["dns_messages"] = []
        for p in packets:
            if p.dns:
                d = p.dns
                out["dns_messages"].append({
                    "i": p.index, "ts": round(p.ts, 6),
                    "src": "%s:%d" % (p.src, p.udp.sport), "dst": "%s:%d" % (p.dst, p.udp.dport),
                    "txid": "0x%04x" % d.txid, "response": d.is_response,
                    "rcode": d.rcode, "rd": d.recursion_desired, "ra": d.recursion_available,
                    "questions": d.questions, "answers": d.answers,
                    "authorities": d.authorities, "additionals": d.additionals,
                })
    if "vxlan" in modes:
        out["vxlan_packets"] = [
            {"i": p.index, "ts": round(p.ts, 6), "src": p.src, "dst": p.dst,
             "vni": p.vxlan["vni"], "inner": p.vxlan["inner"]}
            for p in packets if p.vxlan
        ]
    if as_json:
        print(json.dumps(out, indent=2))
        return
    _print_human(out, modes, packets)


def _print_human(out, modes, packets):
    if "summary" in modes:
        print("== Summary ==")
        print("packets: %d  span: %.6fs" % (out["packet_count"],
              (out["last_ts"] or 0) - (out["first_ts"] or 0)))
        for proto, count in sorted(out["summary"].items()):
            print("  %-16s %d" % (proto, count))
    if "handshake" in modes and out.get("handshakes"):
        print("== TCP handshakes ==")
        for h in out["handshakes"]:
            print("  %s -> %s  client_isn=%d server_isn=%d rtt=%.6fs"
                  % (h["client"], h["server"], h["client_isn"], h["server_isn"], h["rtt_seconds"]))
            print("    SYN options:    %s" % h["syn_options"])
            print("    SYN-ACK options: %s" % h["synack_options"])
    if "retrans" in modes and out.get("retransmissions"):
        print("== Retransmissions (%d) ==" % out["total_retransmissions"])
        for r in out["retransmissions"]:
            print("  t=%.6f %s seq=%d len=%d since_first=%.3fs dup_acks_before=%d %s"
                  % (r["ts"], r["from"], r["seq"], r["len"], r["since_first"],
                     r["dup_acks_before"], r["kind"]))
    elif "retrans" in modes:
        print("== Retransmissions ==\n  none detected")
    if "flows" in modes and out.get("flows"):
        print("== Flows ==")
        for f in out["flows"]:
            key = f["key"]
            label = " | ".join(str(x) for x in key)
            if key[0] in ("tcp", "udp") and len(key) == 3:
                label = "%s %s:%s <-> %s:%s" % (key[0], key[1][0], key[1][1], key[2][0], key[2][1])
            print("  %s packets=%d data=%dB dur=%.6fs rexmit=%d dupack_max=%d rtt=%s"
                  % (label, f["packets"], f["data_bytes"], f["duration"],
                     f["retransmissions"], f["max_dup_acks"], f["handshake_rtt"]))
    if "tcp" in modes and out.get("tcp_packets"):
        print("== TCP packets ==")
        for t in out["tcp_packets"]:
            print("  #%d t=%.6f %s -> %s seq=%d ack=%d [%s] win=%d len=%d"
                  % (t["i"], t["ts"], t["src"], t["dst"], t["seq"], t["ack"],
                     t["flags"], t["win"], t["len"]))
    if "dns" in modes and out.get("dns_messages"):
        print("== DNS messages ==")
        for d in out["dns_messages"]:
            kind = "RESP" if d["response"] else "QUERY"
            print("  #%d t=%.6f %s %s -> %s txid=%s rcode=%s rd=%s ra=%s"
                  % (d["i"], d["ts"], kind, d["src"], d["dst"], d["txid"],
                     d["rcode"], d["rd"], d["ra"]))
            for q in d["questions"]:
                print("      Q: %s %s" % (q["name"], q["type"]))
            for a in d["answers"]:
                print("      A: %s %s ttl=%d %s" % (a["name"], a["type"], a["ttl"], a["value"]))
    if "vxlan" in modes and out.get("vxlan_packets"):
        print("== VXLAN packets ==")
        for v in out["vxlan_packets"]:
            print("  #%d t=%.6f outer %s -> %s vni=%d inner=%s"
                  % (v["i"], v["ts"], v["src"], v["dst"], v["vni"], v["inner"]))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Analyze pcap files without external dependencies.")
    ap.add_argument("pcap", help="path to a libpcap capture file")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--flows", action="store_true")
    ap.add_argument("--handshake", action="store_true")
    ap.add_argument("--retrans", action="store_true")
    ap.add_argument("--tcp", action="store_true", help="list every TCP packet")
    ap.add_argument("--dns", action="store_true")
    ap.add_argument("--vxlan", action="store_true")
    ap.add_argument("--host", help="keep only packets to/from this IP")
    ap.add_argument("--port", type=int, help="keep only packets with this TCP/UDP port")
    ap.add_argument("--limit", type=int, default=0, help="stop after N packets")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)
    modes = [m for m, on in (("summary", args.summary), ("flows", args.flows),
                             ("handshake", args.handshake), ("retrans", args.retrans),
                             ("tcp", args.tcp), ("dns", args.dns), ("vxlan", args.vxlan)) if on]
    if not modes:
        modes = ["summary", "handshake", "retrans", "flows", "dns", "vxlan"]
    packets = []
    for index, ts, linktype, data in read_pcap(args.pcap):
        pkt = parse_packet(index, ts, linktype, data)
        if not passes_filters(pkt, args.host, args.port):
            continue
        packets.append(pkt)
        if args.limit and len(packets) >= args.limit:
            break
    if not packets:
        print("no packets matched", file=sys.stderr)
        return 1
    report(packets, modes, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
