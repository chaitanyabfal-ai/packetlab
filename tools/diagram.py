#!/usr/bin/env python3
"""Render docs/architecture-diagram.svg (stdlib only, no graphviz)."""

import os
import xml.sax.saxutils as sx

W, H = 1320, 980
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "architecture-diagram.svg")

FONT = "font-family='SFMono-Regular,Consolas,Menlo,monospace'"

parts = []


def esc(s):
    return sx.escape(s)


def text(x, y, s, size=12, bold=False, fill="#1a1a1a", anchor="start"):
    w = " font-weight='bold'" if bold else ""
    parts.append("<text x='%d' y='%d' font-size='%d'%s fill='%s' text-anchor='%s' %s>%s</text>"
                 % (x, y, size, w, fill, anchor, FONT, esc(s)))


def box(x, y, w, h, lines, fill="#ffffff", stroke="#334", title_size=12, pad=8, rx=6):
    parts.append("<rect x='%d' y='%d' width='%d' height='%d' rx='%d' fill='%s' stroke='%s' stroke-width='1.4'/>"
                 % (x, y, w, h, rx, fill, stroke))
    cy = y + pad + title_size - 2
    for i, line in enumerate(lines):
        bold = i == 0
        text(x + pad, cy, line, title_size if bold else 11, bold, "#1a1a1a" if bold else "#333")
        cy += 15


def frame(x, y, w, h, label):
    parts.append("<rect x='%d' y='%d' width='%d' height='%d' rx='10' fill='none' stroke='#889' stroke-width='1.4' stroke-dasharray='7 5'/>"
                 % (x, y, w, h))
    text(x + 10, y + 16, label, 12, True, "#556")


def arrow(x1, y1, x2, y2, label=None, lx=0, ly=0, dashed=False):
    dash = " stroke-dasharray='5 4'" if dashed else ""
    parts.append("<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#234' stroke-width='1.6'%s marker-end='url(#ah)'/>"
                 % (x1, y1, x2, y2, dash))
    if label:
        text((x1 + x2) // 2 + lx, (y1 + y2) // 2 + ly, label, 10, False, "#456")


def elbow(points, label=None, lx=0, ly=0, dashed=False):
    dash = " stroke-dasharray='5 4'" if dashed else ""
    d = "M %d %d " % points[0] + " L ".join("%d %d" % p for p in points[1:])
    parts.append("<path d='%s' fill='none' stroke='#234' stroke-width='1.6'%s marker-end='url(#ah)'/>" % (d, dash))
    if label and len(points) >= 2:
        mx, my = points[len(points) // 2]
        text(mx + lx, my + ly, label, 10, False, "#456")


parts.append("<svg xmlns='http://www.w3.org/2000/svg' width='%d' height='%d' viewBox='0 0 %d %d'>" % (W, H, W, H))
parts.append("<defs><marker id='ah' markerWidth='9' markerHeight='9' refX='8' refY='4.5' orient='auto'>"
             "<path d='M0,0 L9,4.5 L0,9 z' fill='#234'/></marker></defs>")
parts.append("<rect width='%d' height='%d' fill='#fbfcfe'/>" % (W, H))

text(W // 2, 34, "packetlab - architecture: whole picture", 17, True, "#123", "middle")

box(1080, 60, 200, 46, ["Internet / WAN"], fill="#fdecea", stroke="#a33")

frame(20, 96, 1280, 860, "Linux host (packetlab runs here; live labs need root + tcpdump / Docker)")

frame(50, 130, 330, 470, "Observe & analyze toolchain (labs 01-03 + offline)")
box(70, 170, 290, 58, ["Lab drivers 01-03", "curl / http.server / dig", "tc netem (loss in lab 02)"], fill="#e8f1ff")
box(70, 248, 290, 50, ["tcpdump -i lo|eth0 -w *.pcap", "(AF_PACKET kernel tap)"], fill="#e8f1ff")
box(70, 318, 290, 50, ["tools/pcapgen.py -> fixtures/", "synthetic pcaps (offline drills)"], fill="#eef7ee")
box(70, 388, 290, 50, ["tools/pcap_analyze.py", "TCP / DNS / VXLAN decoder + stats"], fill="#fff6e0")
box(70, 458, 290, 50, ["docs/findings-template.md", "+ Wireshark on the same .pcap"], fill="#f3eafd")
box(70, 528, 290, 44, ["Makefile", "test . fixtures . analyze . diagram"], fill="#f0f0f0")
arrow(215, 228, 215, 248)
arrow(215, 298, 215, 318, dashed=True)
arrow(215, 368, 215, 388, "decode")
arrow(215, 438, 215, 458, "report")
arrow(215, 508, 215, 528)

frame(430, 130, 380, 470, "Kernel networking - lab 05 (bridge + NAT)")
box(450, 170, 170, 46, ["netns 'client'", "10.99.0.2/24"], fill="#e6f7f1")
box(450, 236, 170, 42, ["veth pair", "veth0 <-> veth1"], fill="#e6f7f1")
box(450, 298, 170, 42, ["bridge br0", "10.99.0.1/24 (L2 fwd)"], fill="#e6f7f1")
box(450, 360, 170, 42, ["routing table", "+ ip_forward=1 (L3)"], fill="#e6f7f1")
box(450, 422, 170, 48, ["iptables/nftables", "nat POSTROUTING:", "MASQUERADE + conntrack"], fill="#fdeee0")
arrow(535, 216, 535, 236, "L2")
arrow(535, 278, 535, 298)
arrow(535, 340, 535, 360, "route")
arrow(535, 402, 535, 422, "SNAT")
box(660, 170, 130, 90, ["tcpdump on br0", "sees 10.99.0.2,", "client MAC"], fill="#fff", stroke="#789")
box(660, 300, 130, 90, ["tcpdump on uplink", "sees host IP,", "uplink MAC"], fill="#fff", stroke="#789")
arrow(620, 193, 660, 200, dashed=True)
arrow(620, 445, 660, 345, "after NAT", dashed=True)

frame(870, 130, 400, 470, "Docker - lab 04 (networks & tunnels)")
box(890, 170, 170, 44, ["docker swarm init", "(single node ok)"], fill="#e8f1ff")
box(890, 234, 170, 44, ["net-a: bridge net", "br-<id> + containers"], fill="#e8f1ff")
box(890, 298, 170, 44, ["veth -> br-<id>", "plain L2 frames"], fill="#e8f1ff")
box(1080, 234, 170, 44, ["tun0: overlay net", "VXLAN, VNI, UDP 4789"], fill="#f3eafd")
box(1080, 298, 170, 44, ["vxlan device", "encap: eth+ip+udp+vxlan"], fill="#f3eafd")
box(1080, 362, 170, 44, ["tun-a <-> tun-b ping", "seen as outer UDP/4789"], fill="#f3eafd")
arrow(975, 214, 975, 234)
arrow(975, 278, 975, 298)
arrow(1165, 234, 1165, 278, "tunnel")
arrow(1165, 342, 1165, 362)
box(890, 362, 170, 44, ["GRE demo: netns g1/g2", "ip tunnel add mode gre"], fill="#eef7ee")
arrow(1060, 256, 1080, 256, dashed=True)

box(560, 660, 200, 50, ["eth0 - host uplink", "default route"], fill="#fdecea", stroke="#a33")
elbow([(535, 446), (535, 685), (560, 685)], "out of host", lx=-64, ly=-6)
elbow([(975, 342), (975, 640), (700, 640), (700, 660)], "bridge path", lx=8, ly=-8)
elbow([(1165, 406), (1165, 620), (740, 620), (740, 660)], "VXLAN encap on UDP/4789", lx=10, ly=-8)
elbow([(760, 685), (1180, 685), (1180, 106)], "NATed traffic", lx=-70, ly=0)

frame(50, 640, 330, 120, "Tests & offline mode")
box(70, 680, 290, 56, ["tools/test_tools.py", "8 unittests: fixtures -> analyzer", "(no root, no network needed)"], fill="#eef7ee")
arrow(215, 636, 215, 680, "make test", lx=8, ly=-4)

text(660, 790, "Live labs 01-05: sudo ./run.sh | setup.sh | trace.sh | teardown.sh   -   Offline: make fixtures && python3 tools/pcap_analyze.py fixtures/<name>.pcap",
     11, False, "#456", "middle")
text(660, 812, "Packet paths: lab 01/02 on lo (SYN handshake, RTO backoff, fast retransmit) - lab 03 UDP/53 DNS - lab 04 bridge/VXLAN/GRE - lab 05 br0 -> route -> MASQUERADE",
     11, False, "#456", "middle")
text(660, 940, "Regenerate this SVG: make diagram   (tools/diagram.py, stdlib only)", 10, False, "#789", "middle")

parts.append("</svg>")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as fh:
    fh.write("\n".join(parts) + "\n")
print("wrote %s (%d bytes)" % (os.path.normpath(OUT), os.path.getsize(OUT)))
