#!/usr/bin/env python3
"""Unit tests: pcapgen fixtures must round-trip through pcap_analyze."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pcap_analyze as pa
import pcapgen as pg

TOOLS = os.path.dirname(os.path.abspath(__file__))


def load(path):
    return [pa.parse_packet(i, ts, lt, data) for i, ts, lt, data in pa.read_pcap(path)]


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = cls.tmp.name
        for name, gen in pg.FIXTURES.items():
            pg.write_pcap(os.path.join(cls.dir, name), gen())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_handshake_fixture(self):
        packets = load(os.path.join(self.dir, "handshake.pcap"))
        flows = pa.collect(packets)
        self.assertEqual(len(flows), 1)
        flow = next(iter(flows.values()))
        self.assertAlmostEqual(flow.handshake_rtt(), 0.0008, places=6)
        syn = flow._handshake["syn"]
        opts = dict((o[0], o[1]) for o in syn.tcp.options if o[0] in ("MSS", "WSCALE"))
        self.assertEqual(opts["MSS"], 1460)
        self.assertEqual(opts["WSCALE"], 7)
        self.assertEqual(syn.tcp.seq, 1000)
        self.assertEqual(flow._handshake["synack"].tcp.seq, 7000)
        self.assertEqual(flow.retransmissions, [])

    def test_retrans_fixture(self):
        packets = load(os.path.join(self.dir, "retrans.pcap"))
        flow = next(iter(pa.collect(packets).values()))
        rex = flow.retransmissions
        self.assertEqual(len(rex), 3)
        self.assertAlmostEqual(rex[0]["since_first"], 1.0, places=3)
        self.assertAlmostEqual(rex[1]["ts"] - rex[0]["ts"], 2.0, places=3)
        self.assertEqual(rex[0]["kind"], "rto")
        self.assertEqual(rex[2]["kind"], "fast-retransmit")
        self.assertGreaterEqual(rex[2]["dup_acks_before"], 3)
        self.assertGreaterEqual(flow.dup_ack_max, 3)

    def test_dns_fixture(self):
        packets = load(os.path.join(self.dir, "dns.pcap"))
        msgs = [p.dns for p in packets if p.dns]
        self.assertEqual(len(msgs), 6)
        resp = msgs[1]
        self.assertTrue(resp.is_response)
        self.assertEqual(resp.txid, 0x1A2B)
        self.assertEqual(resp.questions[0]["name"], "www.example.com")
        self.assertEqual(resp.questions[0]["type"], "A")
        types = [a["type"] for a in resp.answers]
        self.assertEqual(types, ["CNAME", "A"])
        self.assertEqual(resp.answers[0]["value"], "example.com")
        self.assertEqual(resp.answers[1]["value"], "93.184.216.34")
        self.assertEqual(resp.answers[1]["ttl"], 300)
        self.assertEqual(msgs[3].answers[0]["type"], "AAAA")
        self.assertEqual(msgs[3].answers[0]["value"], "2606:2800:220:1:248:1893:25c8:1946")
        self.assertEqual(msgs[5].rcode, "NXDOMAIN")
        self.assertTrue(msgs[0].recursion_desired)
        self.assertTrue(resp.recursion_available)

    def test_vxlan_fixture(self):
        packets = load(os.path.join(self.dir, "vxlan.pcap"))
        vx = [p for p in packets if p.vxlan]
        self.assertEqual(len(vx), 2)
        self.assertEqual(vx[0].vxlan["vni"], 42)
        self.assertEqual(vx[0].vxlan["inner"]["src"], "10.10.0.2")
        self.assertEqual(vx[0].vxlan["inner"]["dst"], "10.10.0.1")
        self.assertEqual(vx[0].vxlan["inner"]["icmp"]["type"], "echo-request")
        self.assertEqual(vx[1].vxlan["inner"]["icmp"]["type"], "echo-reply")
        self.assertEqual(vx[0].udp.dport, 4789)

    def test_cli_json(self):
        path = os.path.join(self.dir, "dns.pcap")
        out = subprocess.run(
            [sys.executable, os.path.join(TOOLS, "pcap_analyze.py"), path, "--dns", "--json"],
            capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        self.assertEqual(len(data["dns_messages"]), 6)
        self.assertEqual(data["dns_messages"][1]["answers"][1]["value"], "93.184.216.34")

    def test_cli_filters(self):
        path = os.path.join(self.dir, "handshake.pcap")
        out = subprocess.run(
            [sys.executable, os.path.join(TOOLS, "pcap_analyze.py"), path,
             "--tcp", "--host", "10.0.0.1", "--port", "80", "--json"],
            capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        for t in data["tcp_packets"]:
            self.assertTrue(t["src"].startswith("10.0.0.1") or t["dst"].startswith("10.0.0.1"))
            self.assertIn(80, (int(t["src"].rsplit(":", 1)[1]), int(t["dst"].rsplit(":", 1)[1])))

    def test_cli_retrans_mode(self):
        path = os.path.join(self.dir, "retrans.pcap")
        out = subprocess.run(
            [sys.executable, os.path.join(TOOLS, "pcap_analyze.py"), path, "--retrans", "--json"],
            capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        self.assertEqual(data["total_retransmissions"], 3)

    def test_bad_file_rejected(self):
        bad = os.path.join(self.dir, "bad.pcap")
        with open(bad, "wb") as fh:
            fh.write(b"not a pcap file at all, definitely not")
        with self.assertRaises(ValueError):
            list(pa.read_pcap(bad))


if __name__ == "__main__":
    unittest.main()
