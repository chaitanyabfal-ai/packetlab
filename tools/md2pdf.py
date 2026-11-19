#!/usr/bin/env python3
"""Render a markdown document to PDF (needs: pip install -r tools/requirements-docs.txt)."""

import argparse
import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def strip_cell_tags(html):
    def clean(m):
        inner = re.sub(r"<[^>]+>", "", m.group(2))
        return m.group(1) + inner + m.group(3)
    return re.sub(r"(<t[dh](?:\s[^>]*)?>)(.*?)(</t[dh]>)", clean, html, flags=re.S)


def font_dirs():
    dirs = [os.path.join(REPO, "assets", "fonts")]
    try:
        import matplotlib
        dirs.append(os.path.join(os.path.dirname(matplotlib.__file__), "mpl-data", "fonts", "ttf"))
    except ImportError:
        pass
    return dirs


def find_font(name):
    for d in font_dirs():
        path = os.path.join(d, name)
        if os.path.exists(path):
            return path
    return None


def load_fonts(pdf):
    regular = find_font("DejaVuSans.ttf")
    if not regular:
        sys.exit("DejaVu fonts not found; expected assets/fonts/ (see tools/md2pdf.py) or matplotlib installed")
    family = "DejaVu"
    pdf.add_font(family, "", regular)
    for style, fname in (("B", "DejaVuSans-Bold.ttf"), ("I", "DejaVuSans-Oblique.ttf"),
                         ("BI", "DejaVuSans-BoldOblique.ttf")):
        path = find_font(fname)
        if path:
            pdf.add_font(family, style, path)
    mono = find_font("DejaVuSansMono.ttf")
    if mono:
        pdf.add_font("DejaVuMono", "", mono)
        bold = find_font("DejaVuSansMono-Bold.ttf")
        if bold:
            pdf.add_font("DejaVuMono", "B", bold)


def build(md_path, out_path, title):
    import markdown
    from fpdf import FPDF, FontFace, TextStyle

    with open(md_path, encoding="utf-8") as fh:
        md_text = fh.read()
    html = markdown.markdown(md_text, extensions=["tables", "fenced_code", "sane_lists"])
    html = html.replace("<hr />", "").replace("<hr>", "")
    html = strip_cell_tags(html)

    class PDF(FPDF):
        def header(self):
            if self.page_no() > 1:
                self.set_font("DejaVu", "", 8)
                self.set_text_color(120)
                self.cell(0, 6, title, align="R")
                self.ln(8)

        def footer(self):
            self.set_y(-14)
            self.set_font("DejaVu", "", 8)
            self.set_text_color(120)
            self.cell(0, 6, "packetlab - %s - page %d" % (title, self.page_no()), align="C")

    pdf = PDF(orientation="P", unit="mm", format="A4")
    pdf.set_margins(18, 16, 18)
    pdf.set_auto_page_break(auto=True, margin=18)
    load_fonts(pdf)
    pdf.set_font("DejaVu", "", 10)
    pdf.add_page()

    dark = (20, 40, 80)
    tag_styles = {
        "h1": TextStyle(color=dark, font_size_pt=20, t_margin=10, b_margin=4),
        "h2": TextStyle(color=dark, font_size_pt=15, t_margin=9, b_margin=3),
        "h3": TextStyle(color=dark, font_size_pt=12.5, t_margin=7, b_margin=2),
        "h4": TextStyle(color=dark, font_size_pt=11, t_margin=6, b_margin=2),
        "p": TextStyle(t_margin=1.5, b_margin=1.5),
        "li": TextStyle(t_margin=0.8, b_margin=0.8),
        "pre": TextStyle(font_family="DejaVuMono", font_size_pt=8, fill_color=(242, 244, 248),
                         l_margin=3, t_margin=2, b_margin=2),
        "code": FontFace(family="DejaVuMono", color=(120, 20, 20)),
        "a": FontFace(color=(0, 60, 180), emphasis="UNDERLINE"),
        "strong": FontFace(emphasis="BOLD"),
        "b": FontFace(emphasis="BOLD"),
        "em": FontFace(emphasis="ITALICS"),
    }
    pdf.write_html("<html><body>%s</body></html>" % html,
                   tag_styles=tag_styles, table_line_separators=True)
    pdf.output(out_path)
    return os.path.getsize(out_path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a markdown file to PDF.")
    ap.add_argument("md", help="input markdown file")
    ap.add_argument("-o", "--out", help="output PDF path (default: <md basename>.pdf next to it)")
    ap.add_argument("--title", help="document title for header/footer (default: first # heading)")
    args = ap.parse_args(argv)
    out = args.out or os.path.splitext(args.md)[0] + ".pdf"
    title = args.title
    if not title:
        with open(args.md, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("# "):
                    title = line[2:].strip()
                    break
    title = title or os.path.basename(args.md)
    size = build(args.md, out, title)
    print("wrote %s (%d bytes)" % (out, size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
