"""Write Vidar's architecture diagrams as standalone SVG files.

Usage:  python make_diagrams.py OUTPUT_DIR

Standard library only. Output is deterministic: the same source produces the
same bytes on every run. Every file carries its own opaque background and a
light/dark palette scoped under a root class unique to that file, so it reads
the same whatever page it is embedded in.

The content is hand-maintained against src/. When the code changes, change the
matching block below and re-run.
"""

from __future__ import annotations

import os
import sys
from xml.sax.saxutils import escape

# ── Metrics ──────────────────────────────────────────────────────────────────
# Estimates for layout checks. Monospace advance is 0.6em; sans is an average.
CHAR_W = {"m": 7.85, "mb": 8.45, "s": 7.5, "sb": 8.1, "h": 9.2, "ti": 12.0}
ROW = 20  # line height for 13px mono / 14px sans

LIGHT = {
    "bg": "#ffffff",
    "edge": "#d1d9e0",
    "ink": "#1f2328",
    "muted": "#59636e",
    "line": "#59636e",
    "box": "#f6f8fa",
    "boxline": "#6e7781",
    "hdr": "#eaeef2",
    "frame": "#8c959f",
    "tbl": "#d6efea",
    "cls": "#dce7f7",
    "ext": "#f5e6c8",
    "proc": "#e7e0f6",
    "note": "#faf2cf",
}
DARK = {
    "bg": "#0d1117",
    "edge": "#3d444d",
    "ink": "#e6edf3",
    "muted": "#9198a1",
    "line": "#9198a1",
    "box": "#151b23",
    "boxline": "#8b949e",
    "hdr": "#212830",
    "frame": "#6e7681",
    "tbl": "#12332e",
    "cls": "#1a2940",
    "ext": "#3a2d13",
    "proc": "#2a2342",
    "note": "#332d13",
}

MONO_STACK = 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace'
SANS_STACK = '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif'


def css(root: str) -> str:
    def rules(p: dict) -> str:
        r = f".{root}"
        return "\n".join(
            [
                f"{r} text {{ font-family: {SANS_STACK}; font-size: 14px; fill: {p['ink']}; }}",
                f"{r} .m {{ font-family: {MONO_STACK}; font-size: 13px; }}",
                f"{r} .mb {{ font-family: {MONO_STACK}; font-size: 14px; font-weight: 700; }}",
                f"{r} .sb {{ font-weight: 600; }}",
                f"{r} .h {{ font-size: 16px; font-weight: 600; }}",
                f"{r} .ti {{ font-size: 22px; font-weight: 600; }}",
                f"{r} .st {{ fill: {p['muted']}; }}",
                f"{r} .it {{ font-style: italic; }}",
                f"{r} .bg {{ fill: {p['bg']}; stroke: {p['edge']}; stroke-width: 1; }}",
                f"{r} .ko {{ fill: {p['bg']}; }}",
                f"{r} .box {{ fill: {p['box']}; stroke: {p['boxline']}; stroke-width: 1.2; }}",
                f"{r} .hdr {{ fill: {p['hdr']}; }}",
                f"{r} .tbl {{ fill: {p['tbl']}; }}",
                f"{r} .cls {{ fill: {p['cls']}; }}",
                f"{r} .ext {{ fill: {p['ext']}; }}",
                f"{r} .proc {{ fill: {p['proc']}; }}",
                f"{r} .note {{ fill: {p['note']}; stroke: {p['boxline']}; stroke-width: 1; }}",
                f"{r} .sep {{ stroke: {p['boxline']}; stroke-width: 1; }}",
                f"{r} .ln {{ stroke: {p['line']}; stroke-width: 1.4; fill: none; }}",
                f"{r} .dash {{ stroke-dasharray: 6 4; }}",
                f"{r} .frame {{ fill: none; stroke: {p['frame']}; stroke-width: 1.3; stroke-dasharray: 8 5; }}",
                f"{r} .sframe {{ fill: none; stroke: {p['frame']}; stroke-width: 1.3; }}",
                f"{r} .life {{ stroke: {p['frame']}; stroke-width: 1.2; stroke-dasharray: 5 5; fill: none; }}",
                f"{r} .act {{ fill: {p['hdr']}; stroke: {p['line']}; stroke-width: 1; }}",
                f"{r} .mkf {{ fill: {p['line']}; stroke: {p['line']}; stroke-width: 1; }}",
                f"{r} .mko {{ fill: none; stroke: {p['line']}; stroke-width: 1.4; }}",
                f"{r} .mkh {{ fill: {p['bg']}; stroke: {p['line']}; stroke-width: 1.4; }}",
                f"{r} .ball {{ fill: {p['bg']}; stroke: {p['line']}; stroke-width: 1.4; }}",
                f"{r} .dot {{ fill: {p['line']}; }}",
                f"{r} .icon {{ fill: {p['box']}; stroke: {p['line']}; stroke-width: 1.1; }}",
            ]
        )

    return (
        "<style>\n"
        + rules(LIGHT)
        + "\n@media (prefers-color-scheme: dark) {\n"
        + rules(DARK)
        + "\n}\n</style>\n"
    )


def f1(v: float) -> str:
    s = f"{v:.1f}"
    return s[:-2] if s.endswith(".0") else s


def text_width(s: str, cls: str) -> float:
    key = cls.split()[0] if cls else "s"
    return len(s) * CHAR_W.get(key, CHAR_W["s"])


class Svg:
    def __init__(self, key: str, width: int, title: str, desc: str):
        self.root = f"vidar-{key}"
        self.w = width
        self.title = title
        self.desc = desc
        self.parts: list[str] = []
        self.warnings: list[str] = []

    def mk(self, name: str) -> str:
        return f"{self.root}-{name}"

    def add(self, s: str) -> None:
        self.parts.append(s)

    def text(self, x, y, s, cls="s", anchor="start", knock=False, limit=None):
        width = text_width(s, cls)
        if limit is not None and width > limit + 0.5:
            self.warnings.append(f"text too wide ({width:.0f} > {limit:.0f}): {s}")
        if anchor == "start":
            x0 = x
        elif anchor == "end":
            x0 = x - width
        else:
            x0 = x - width / 2
        if x0 < 8 or x0 + width > self.w - 8:
            self.warnings.append(f"text outside canvas: {s}")
        if knock:
            self.add(
                f'<rect class="ko" x="{f1(x0 - 4)}" y="{f1(y - 15)}" width="{f1(width + 8)}" height="20"/>'
            )
        c = " ".join(p for p in cls.split() if p != "s")
        ca = f' class="{c}"' if c else ""
        an = f' text-anchor="{anchor}"' if anchor != "start" else ""
        self.add(f'<text x="{f1(x)}" y="{f1(y)}"{ca}{an} xml:space="preserve">{escape(s)}</text>')

    def rect(self, x, y, w, h, cls="box", rx=0):
        r = f' rx="{rx}"' if rx else ""
        self.add(
            f'<rect class="{cls}" x="{f1(x)}" y="{f1(y)}" width="{f1(w)}" height="{f1(h)}"{r}/>'
        )

    def line(self, x1, y1, x2, y2, cls="sep"):
        self.add(f'<line class="{cls}" x1="{f1(x1)}" y1="{f1(y1)}" x2="{f1(x2)}" y2="{f1(y2)}"/>')

    def path(self, pts, cls="ln", end=None, start=None):
        d = "M" + " L".join(f"{f1(x)},{f1(y)}" for x, y in pts)
        me = f' marker-end="url(#{self.mk(end)})"' if end else ""
        ms = f' marker-start="url(#{self.mk(start)})"' if start else ""
        self.add(f'<path class="{cls}" d="{d}"{me}{ms}/>')

    def dot(self, x, y):
        self.add(f'<circle class="dot" cx="{f1(x)}" cy="{f1(y)}" r="3"/>')

    def render(self, height: int) -> str:
        R = self.root
        defs = (
            "<defs>\n"
            f'<marker id="{self.mk("tri")}" viewBox="0 0 16 16" markerWidth="16" markerHeight="16" '
            'refX="15" refY="8" orient="auto" markerUnits="userSpaceOnUse">'
            '<path class="mkh" d="M1,1 L15,8 L1,15 Z"/></marker>\n'
            f'<marker id="{self.mk("open")}" viewBox="0 0 14 14" markerWidth="14" markerHeight="14" '
            'refX="13" refY="7" orient="auto-start-reverse" markerUnits="userSpaceOnUse">'
            '<path class="mko" d="M1,1 L13,7 L1,13"/></marker>\n'
            f'<marker id="{self.mk("filled")}" viewBox="0 0 14 14" markerWidth="14" markerHeight="14" '
            'refX="13" refY="7" orient="auto" markerUnits="userSpaceOnUse">'
            '<path class="mkf" d="M1,1 L13,7 L1,13 Z"/></marker>\n'
            f'<marker id="{self.mk("diamond")}" viewBox="0 0 18 12" markerWidth="18" markerHeight="12" '
            'refX="1" refY="6" orient="auto" markerUnits="userSpaceOnUse">'
            '<path class="mkf" d="M1,6 L9,1 L17,6 L9,11 Z"/></marker>\n'
            "</defs>\n"
        )
        head = (
            f'<svg xmlns="http://www.w3.org/2000/svg" class="{R}" viewBox="0 0 {self.w} {height}" '
            f'width="{self.w}" height="{height}" role="img" aria-labelledby="{R}-title {R}-desc">\n'
            f'<title id="{R}-title">{escape(self.title)}</title>\n'
            f'<desc id="{R}-desc">{escape(self.desc)}</desc>\n'
        )
        bg = f'<rect class="bg" x="0.5" y="0.5" width="{self.w - 1}" height="{height - 1}" rx="14"/>\n'
        return head + css(R) + defs + bg + "\n".join(self.parts) + "\n</svg>\n"


# ── Building blocks ──────────────────────────────────────────────────────────


def header(S: Svg, title: str, subtitle_lines: list[str]) -> int:
    S.text(30, 44, title, "ti")
    y = 70
    for line in subtitle_lines:
        S.text(30, y, line, "s st", limit=S.w - 60)
        y += 20
    return y + 16


def box(S, x, y, w, name, stereo=None, sections=(), tint="cls", name_cls="mb", icon=None, min_h=0):
    """A UML classifier/component box. sections: list of lists of (text, cls).
    A line whose cls is 'pair' carries (left, right) texts in two mono columns."""
    hh = 10 + (ROW if stereo else 0) + ROW + 8
    h = hh
    for sec in sections:
        h += 12 + ROW * len(sec)
    h = max(h, min_h)
    S.rect(x, y, w, h, "box")
    S.rect(x + 0.6, y + 0.6, w - 1.2, hh - 0.6, "hdr " + tint)
    icon_room = 36 if icon else 0
    ty = y + 25
    if stereo:
        S.text(x + 12, ty, stereo, "s st", limit=w - 24 - icon_room)
        ty += ROW
    S.text(x + 12, ty, name, name_cls, limit=w - 24 - icon_room)
    if icon:
        draw_icon(S, icon, x + w - 32, y + 10)
    cy = y + hh
    for sec in sections:
        S.line(x, cy, x + w, cy)
        for i, (t, c) in enumerate(sec):
            by = cy + 6 + 15 + i * ROW
            if c == "pair":
                left, right = t
                S.text(x + 12, by, left, "m", limit=w / 2 - 20)
                S.text(x + w / 2 + 8, by, right, "m", limit=w / 2 - 20)
            else:
                S.text(x + 12, by, t, c, limit=w - 24)
        cy += 12 + ROW * len(sec)
    return h


def draw_icon(S, kind, x, y):
    if kind == "component":
        S.add(f'<rect class="icon" x="{x + 6}" y="{y}" width="16" height="20"/>')
        S.add(f'<rect class="icon" x="{x}" y="{y + 4}" width="11" height="4"/>')
        S.add(f'<rect class="icon" x="{x}" y="{y + 12}" width="11" height="4"/>')
    elif kind == "artifact":
        S.add(
            f'<path class="icon" d="M{x + 2},{y} L{x + 14},{y} L{x + 20},{y + 6} L{x + 20},{y + 22} '
            f'L{x + 2},{y + 22} Z"/>'
        )
        S.add(f'<path class="ln" d="M{x + 14},{y} L{x + 14},{y + 6} L{x + 20},{y + 6}"/>')
    elif kind == "db":
        S.add(
            f'<path class="icon" d="M{x},{y + 4} L{x},{y + 18} A10,4 0 0 0 {x + 20},{y + 18} '
            f'L{x + 20},{y + 4}"/>'
        )
        S.add(f'<ellipse class="icon" cx="{x + 10}" cy="{y + 4}" rx="10" ry="4"/>')
    elif kind == "cloud":
        S.add(
            f'<path class="icon" d="M{x + 4},{y + 18} A6,6 0 0 1 {x + 4},{y + 6} A8,8 0 0 1 '
            f'{x + 18},{y + 4} A6,6 0 0 1 {x + 22},{y + 18} Z"/>'
        )


def node3d(S, x, y, w, h, stereo, name, depth=12, center=False):
    S.add(
        f'<path class="box" d="M{f1(x)},{f1(y)} L{f1(x + depth)},{f1(y - depth)} '
        f"L{f1(x + w + depth)},{f1(y - depth)} L{f1(x + w + depth)},{f1(y + h - depth)} "
        f'L{f1(x + w)},{f1(y + h)} L{f1(x + w)},{f1(y)} Z"/>'
    )
    S.line(x + w, y, x + w + depth, y - depth)
    S.rect(x, y, w, h, "box")
    tx, an = (x + w / 2, "middle") if center else (x + 14, "start")
    S.text(tx, y + 24, stereo, "s st", an, limit=w - 28)
    S.text(tx, y + 44, name, "sb", an, limit=w - 28)


def assembly(S, x, y_from, y_to, label, label_dx=18):
    """Vertical ball-and-socket: requirer above (y_from), provider edge below (y_to)."""
    cy = y_to - 24
    r, R = 7, 12
    S.path([(x, y_to), (x, cy + r)])
    S.add(f'<circle class="ball" cx="{f1(x)}" cy="{f1(cy)}" r="{r}"/>')
    S.path([(x, y_from), (x, cy - R)])
    S.add(f'<path class="ln" d="M{f1(x - R)},{f1(cy)} A{R},{R} 0 0 1 {f1(x + R)},{f1(cy)}"/>')
    S.text(x + label_dx, cy + 5, label, "m")


def legend_box(S, x, y, w, title, rows):
    """rows: list of (sample, text) where sample in {'tri','diamond','open','dash','solid','ball', None}."""
    h = 44 + ROW * len(rows) + 16
    S.rect(x, y, w, h, "note", rx=6)
    S.text(x + 16, y + 28, title, "sb")
    cy = y + 44
    for sample, t in rows:
        by = cy + 15
        tx = x + 16
        if sample:
            lx = x + 16
            if sample == "tri":
                S.path([(lx, by - 5), (lx + 60, by - 5)], "ln", end="tri")
            elif sample == "diamond":
                S.path([(lx, by - 5), (lx + 60, by - 5)], "ln", start="diamond")
            elif sample == "open":
                S.path([(lx, by - 5), (lx + 60, by - 5)], "ln", end="open")
            elif sample == "dash":
                S.path([(lx, by - 5), (lx + 60, by - 5)], "ln dash", end="open")
            elif sample == "filled":
                S.path([(lx, by - 5), (lx + 60, by - 5)], "ln", end="filled")
            elif sample == "assoc":
                S.path([(lx, by - 5), (lx + 60, by - 5)], "ln dash")
            elif sample == "ret":
                S.path([(lx, by - 5), (lx + 60, by - 5)], "ln dash", end="open")
            elif sample == "ball":
                S.path([(lx, by - 5), (lx + 22, by - 5)], "ln")
                S.add(
                    f'<path class="ln" d="M{lx + 22},{by - 17} A12,12 0 0 1 {lx + 22},{by + 7}"/>'
                )
                S.add(f'<circle class="ball" cx="{lx + 26}" cy="{by - 5}" r="7"/>')
                S.path([(lx + 33, by - 5), (lx + 60, by - 5)], "ln")
            tx = x + 92
        S.text(tx, by, t, "s", limit=w - (tx - x) - 16)
        cy += ROW
    return h


def wrap_names(names, width_chars):
    lines, cur = [], ""
    for i, n in enumerate(names):
        piece = n + ("," if i < len(names) - 1 else "")
        if cur and len(cur) + 1 + len(piece) > width_chars:
            lines.append(cur)
            cur = piece
        else:
            cur = (cur + " " + piece) if cur else piece
    if cur:
        lines.append(cur)
    return lines


# ── 1. Data model ────────────────────────────────────────────────────────────


def col(name, typ, rest=""):
    return (f"{name:<21}{typ:<8}{rest}".rstrip(), "m")


def data_model() -> Svg:
    W = 960
    S = Svg(
        "data-model",
        W,
        "Vidar data model",
        "The nine SQLite tables of Vidar with their columns, indexes and foreign keys.",
    )
    y0 = header(
        S,
        "Vidar — data model",
        [
            "The SQLite tables created by src/db.py (SCHEMA, INDEXES and migrations), stored in /data/vidar.db.",
            "Sessions, incidents and the monthly report are derived on read and have no table.",
        ],
    )

    visits_cols = [
        col("id", "INTEGER", "PK AUTOINCREMENT"),
        col("ip", "TEXT", "NOT NULL"),
        col("timestamp", "TEXT", "NOT NULL"),
        col("method", "TEXT"),
        col("path", "TEXT"),
        col("server_port", "INTEGER", "= 0"),
        col("status", "INTEGER"),
        col("bytes_sent", "INTEGER"),
        col("user_agent", "TEXT"),
        col("referer", "TEXT"),
        col("request_time", "REAL"),
        col("ssl_protocol", "TEXT"),
        col("browser", "TEXT", "= ''"),
        col("os", "TEXT", "= ''"),
        col("device", "TEXT", "= ''"),
        col("accept_language", "TEXT", "= ''"),
        col("request_length", "INTEGER", "= 0"),
        col("http_x_forwarded_for", "TEXT", "= ''"),
        col("ssl_cipher", "TEXT", "= ''"),
        col("connection", "INTEGER", "= 0"),
        col("connection_requests", "INTEGER", "= 0"),
        col("limit_req_status", "TEXT", "= ''"),
        col("http_version", "TEXT", "= ''"),
        col("sec_fetch_dest", "TEXT", "= ''"),
        col("sec_fetch_mode", "TEXT", "= ''"),
        col("sec_fetch_site", "TEXT", "= ''"),
        col("accept_encoding", "TEXT", "= ''"),
        col("ssl_session_reused", "TEXT", "= ''"),
        col("created_at", "TEXT", "= CURRENT_TIMESTAMP"),
    ]
    visits_idx = [
        ("idx_visits_ip_timestamp (ip, timestamp)", "m"),
        ("idx_visits_timestamp (timestamp)", "m"),
        ("idx_visits_timestamp_ip (timestamp, ip)", "m"),
        ("idx_visits_status_path (status, path)", "m"),
        ("UNIQUE idx_visits_request_identity", "m"),
        ("  (timestamp, connection, connection_requests)", "m"),
        ("  WHERE connection > 0", "m"),
    ]
    VX, VW = 30, 410
    vh = box(S, VX, y0, VW, "visits", "«table»", [visits_cols, visits_idx], tint="tbl")

    intel_cols = [
        col("ip", "TEXT", "PK"),
        col("country", "TEXT"),
        col("country_code", "TEXT"),
        col("city", "TEXT"),
        col("lat", "REAL"),
        col("lon", "REAL"),
        col("isp", "TEXT"),
        col("org", "TEXT"),
        col("asn", "TEXT"),
        col("is_proxy", "INTEGER", "= 0"),
        col("is_hosting", "INTEGER", "= 0"),
        col("is_mobile", "INTEGER", "= 0"),
        col("reverse_dns", "TEXT", "= ''"),
        col("is_tor", "INTEGER", "= 0"),
        col("dnsbl_listed", "INTEGER", "= 0"),
        col("dnsbl_sources", "TEXT", "= ''"),
        col("fetched_at", "TEXT"),
        col("visitor_class", "TEXT", "= ''"),
        col("classified_at", "TEXT"),
        col("classified_visit_id", "INTEGER", "= 0"),
        col("rdns_checked_at", "TEXT"),
    ]
    IX, IW = 560, 370
    ih = box(
        S,
        IX,
        y0,
        IW,
        "ip_intel",
        "«table»",
        [
            intel_cols,
            [
                ("idx_ip_intel_fetched (fetched_at)", "m"),
                ("idx_ip_intel_visitor_class", "m"),
                ("  (visitor_class)", "m"),
            ],
        ],
        tint="tbl",
    )

    # visits * -- 0..1 ip_intel, logical only
    ay = y0 + 100
    S.path([(VX + VW, ay), (IX, ay)], "ln dash")
    S.text(VX + VW + 8, ay - 8, "*", "m")
    S.text(IX - 8, ay - 8, "0..1", "m", "end")
    mid = (VX + VW + IX) / 2
    S.text(mid, ay + 24, "join on ip;", "s st", "middle")
    S.text(mid, ay + 44, "no FOREIGN", "s st", "middle")
    S.text(mid, ay + 64, "KEY", "s st", "middle")

    # children, stacked under ip_intel, one shared composition spine
    cy = y0 + ih + 50
    spine_x = 505
    diamond_y = y0 + ih - 30
    S.path([(IX, diamond_y), (spine_x, diamond_y)], "ln", start="diamond")
    S.text(IX - 22, diamond_y - 10, "1", "m")
    last_mid = None
    children = [
        ("ip_intel_ports", "port", "INTEGER", "idx_ip_intel_ports_port (port)"),
        ("ip_intel_vulns", "vuln", "TEXT", "idx_ip_intel_vulns_vuln (vuln)"),
        ("ip_intel_cpes", "cpe", "TEXT", "idx_ip_intel_cpes_cpe (cpe)"),
        ("ip_intel_tags", "tag", "TEXT", "idx_ip_intel_tags_tag (tag)"),
        ("ip_intel_hostnames", "hostname", "TEXT", "idx_ip_intel_hostnames_hostname (hostname)"),
    ]
    for name, c, t, idx in children:
        h = box(
            S,
            IX,
            cy,
            IW,
            name,
            "«table»",
            [
                [
                    (f"{'ip':<10}{'TEXT':<9}NOT NULL · PK · FK", "m"),
                    (f"{c:<10}{t:<9}NOT NULL · PK", "m"),
                ],
                [("FK ip → ip_intel(ip) ON DELETE CASCADE", "m"), (idx, "m")],
            ],
            tint="tbl",
        )
        m = cy + 60
        S.path([(spine_x, m), (IX, m)], "ln", end="open")
        S.text(IX - 8, m - 8, "0..*", "m", "end")
        S.dot(spine_x, m)
        last_mid = m
        cy += h + 24
    S.path([(spine_x, diamond_y), (spine_x, last_mid)], "ln")
    right_bottom = cy

    # processor_state and rate_limits under visits
    py = y0 + vh + 50
    keys = [
        ("log_processor   file_offset, file_inode,", "m"),
        ("                file_fingerprint", "m"),
        ("main            classifier_version", "m"),
        ("archive         retention.mode,", "m"),
        ("                retention.rolling_months,", "m"),
        ("                retention.archive_keep_months,", "m"),
        ("                retention.last_run,", "m"),
        ("                archive.pin.<YYYY-MM>", "m"),
        ("backup          backup.last_run", "m"),
        ("queries/intel   rdns_unconfirmed_purged", "m"),
    ]
    ph = box(
        S,
        VX,
        py,
        VW,
        "processor_state",
        "«table»",
        [
            [col("key", "TEXT", "PK"), col("value", "TEXT")],
            [("keys, by the module that writes them", "s st it")] + keys,
        ],
        tint="tbl",
    )
    ry = py + ph + 40
    rh = box(
        S,
        VX,
        ry,
        VW,
        "rate_limits",
        "«table»",
        [
            [
                col("id", "INTEGER", "PK AUTOINCREMENT"),
                col("client_ip", "TEXT", "NOT NULL"),
                col("hit_at", "REAL", "NOT NULL"),
            ],
            [
                ("idx_rate_limits_ip_time (client_ip, hit_at)", "m"),
                ("one row per /api/export hit", "s st"),
            ],
        ],
        tint="tbl",
    )
    left_bottom = ry + rh + 24

    ly = max(left_bottom, right_bottom) + 16
    lh = legend_box(
        S,
        30,
        ly,
        W - 60,
        "Notation",
        [
            (
                "diamond",
                "composition: child rows belong to one ip_intel row and are deleted with it",
            ),
            ("assoc", "logical association with multiplicities; not a foreign key, not enforced"),
            (
                None,
                "Foreign keys are enforced on connections from db.get_conn(), which sets PRAGMA foreign_keys=ON.",
            ),
            (
                None,
                "The five child tables are the only store of Shodan's multi-value fields; upsert_ip_intel()",
            ),
            (None, "rewrites them through _sync_shodan_children()."),
        ],
    )
    return S, ly + lh + 30


# ── 2. Classes ───────────────────────────────────────────────────────────────


def classes():
    W = 960
    S = Svg(
        "classes",
        W,
        "Vidar Python classes",
        "Every class defined under src/ in Vidar, with attributes, methods and relationships.",
    )
    y = header(
        S,
        "Vidar — Python classes",
        [
            "Every class statement under src/ (13). Plain functions, the 12 query modules and the 17 classifier",
            "rules are not classes and appear only in notes. − marks a leading-underscore name.",
        ],
    )

    # BaseSettings <|-- Settings
    bs_h = box(S, 360, y, 240, "BaseSettings", "«external» pydantic_settings", [], tint="ext")
    sy = y + bs_h + 60
    S.path([(480, sy), (480, y + bs_h)], "ln", end="tri")

    groups_left = [
        (
            "paths and database",
            ["log_path", "db_path", "archive_dir", "backup_dir", "db_connection_timeout"],
        ),
        (
            "ingestion",
            [
                "poll_interval_seconds",
                "ingest_existing_backlog",
                "filter_static_assets",
                "filter_internal_ips",
                "static_extensions",
            ],
        ),
        (
            "site-specific (ship blank)",
            ["site_base_url", "static_asset_prefixes", "js_only_path_prefixes"],
        ),
        ("classifier", ["patterns_path", "reclassify_interval_minutes"]),
        ("mode", ["demo_mode"]),
    ]
    groups_right = [
        (
            "enrichment",
            [
                "enrichment_batch_size",
                "enrichment_queue_maxsize",
                "enrichment_cache_ttl_days",
                "shodan_concurrency",
                "shodan_requests_per_minute",
                "shodan_cooldown_seconds",
                "dns_timeout_seconds",
                "dnsbl_enabled",
                "dnsbl_providers",
                "dnsbl_dqs_key",
                "dnsbl_concurrency",
                "tor_cache_ttl_seconds",
            ],
        ),
        (
            "retention and backup",
            [
                "retention_days (deprecated)",
                "archive_restore_days",
                "backup_enabled",
                "backup_keep",
            ],
        ),
        (
            "web and security",
            ["allowed_hosts", "export_rate_limit", "export_rate_limit_window_s", "carto_api_key"],
        ),
        (
            "map marker",
            [
                "server_lat",
                "server_lon",
                "server_city",
                "server_country",
                "server_asn",
                "server_ip",
            ],
        ),
    ]

    def group_lines(groups):
        out = []
        for gname, names in groups:
            out.append((f"{gname} ({len(names)})", "s st it"))
            out.extend((line, "m") for line in wrap_names(names, 50))
            out.append(("", "m"))
        return out[:-1]

    gl, gr = group_lines(groups_left), group_lines(groups_right)
    n = max(len(gl), len(gr))
    SX, SW = 30, 900
    hh = 10 + ROW + ROW + 8
    ops = [
        ("−_blank_is_unset(v)  «field_validator» server_lat, server_lon", "m"),
        ("−_split_csv_providers(v)  «field_validator» the four comma-separated lists", "m"),
        ("model_config: env_prefix '' · env_file from $VIDAR_ENV_FILE, else .env", "m"),
    ]
    module = [("settings = Settings()   ·   unset_site_settings() : list[str]", "m")]
    sh = hh + (12 + ROW * (n + 1)) + (12 + ROW * len(ops)) + (12 + ROW * len(module))
    S.rect(SX, sy, SW, sh, "box")
    S.rect(SX + 0.6, sy + 0.6, SW - 1.2, hh - 0.6, "hdr cls")
    S.text(SX + 12, sy + 25, "config.py", "s st")
    S.text(SX + 12, sy + 45, "Settings", "mb")
    cy = sy + hh
    S.line(SX, cy, SX + SW, cy)
    S.text(
        SX + 12,
        cy + 21,
        "42 fields, grouped by concern (names only; types and defaults: docs/data-reference.md)",
        "s st",
        limit=SW - 24,
    )
    for i, (t, c) in enumerate(gl):
        S.text(SX + 12, cy + 21 + (i + 1) * ROW, t, c, limit=SW / 2 - 24)
    for i, (t, c) in enumerate(gr):
        S.text(SX + SW / 2 + 12, cy + 21 + (i + 1) * ROW, t, c, limit=SW / 2 - 24)
    S.line(SX + SW / 2, cy + 30, SX + SW / 2, cy + 12 + ROW * (n + 1) - 6, "sep")
    cy += 12 + ROW * (n + 1)
    for sec in (ops, module):
        S.line(SX, cy, SX + SW, cy)
        for i, (t, c) in enumerate(sec):
            S.text(SX + 12, cy + 21 + i * ROW, t, c, limit=SW - 24)
        cy += 12 + ROW * len(sec)
    y = sy + sh + 60

    # BaseModel <|-- LogEntry ; Visit ; LogEntry ..> Visit
    LX, LW, VX, VW = 30, 420, 510, 420
    bm_h = box(S, LX + 90, y, 240, "BaseModel", "«external» pydantic", [], tint="ext")
    ly = y + bm_h + 60
    S.path([(LX + 210, ly), (LX + 210, y + bm_h)], "ln", end="tri")
    le = [
        "time : str",
        "remote_addr : str",
        "request : str",
        "status : int",
        "body_bytes_sent : int",
        "http_referer : str = ''",
        "http_user_agent : str = ''",
        "request_time : float = 0.0",
        "ssl_protocol : str = ''",
        "request_method : str = ''",
        "request_uri : str = ''",
        "server_port : int = 0",
        "http_accept_language : str = ''",
        "request_length : int = 0",
        "http_x_forwarded_for : str = ''",
        "ssl_cipher : str = ''",
        "connection : int = 0",
        "connection_requests : int = 0",
        "limit_req_status : str = ''",
        "http_version : str = ''",
        "sec_fetch_dest : str = ''",
        "sec_fetch_mode : str = ''",
        "sec_fetch_site : str = ''",
        "accept_encoding : str = ''",
        "ssl_session_reused : str = ''",
    ]
    le_h = box(
        S,
        LX,
        ly,
        LW,
        "LogEntry",
        "models.py",
        [
            [(a, "m") for a in le],
            [
                ("one nginx JSON log line; field names follow", "s st"),
                ("deploy/nginx-log-format.conf", "m"),
            ],
        ],
    )
    vi = [
        "ip : str",
        "timestamp : str",
        "method : str",
        "path : str",
        "server_port : int",
        "status : int",
        "bytes_sent : int",
        "user_agent : str",
        "referer : str",
        "request_time : float",
        "ssl_protocol : str",
        "browser : str",
        "os : str",
        "device : str",
        "accept_language : str",
        "request_length : int",
        "http_x_forwarded_for : str",
        "ssl_cipher : str",
        "connection : int",
        "connection_requests : int",
        "limit_req_status : str",
        "http_version : str",
        "sec_fetch_dest : str",
        "sec_fetch_mode : str",
        "sec_fetch_site : str",
        "accept_encoding : str",
        "ssl_session_reused : str",
    ]
    vy = y
    v_h = box(
        S,
        VX,
        vy,
        VW,
        "Visit",
        "models.py  «TypedDict» total=True",
        [
            [(a, "m") for a in vi],
            [
                ("REQUIRED_FIELDS = ('ip', 'timestamp')", "m"),
                ("NGINX_ONLY_FIELDS: 4 names", "m"),
                ("PSEUDO_PATHS: 3 pseudo-paths", "m"),
            ],
            [("stored as a visits row by", "s st"), ("queries.visits.insert_visit()", "m")],
        ],
    )
    lb, vb = ly + le_h, vy + v_h
    route_y = max(lb, vb) + 50
    S.path(
        [(LX + LW / 2, lb), (LX + LW / 2, route_y), (VX + VW / 2, route_y), (VX + VW / 2, vb)],
        "ln dash",
        end="open",
    )
    S.text(
        W / 2, route_y + 26, "«maps to»  log_processor.process_entry(entry) : Visit", "m", "middle"
    )
    y = route_y + 70

    # smaller classes, two columns
    def pair_rows(left_boxes, right_boxes, y):
        yl = yr = y
        for fn in left_boxes:
            yl = fn(yl) + 40
        for fn in right_boxes:
            yr = fn(yr) + 40
        return max(yl, yr)

    def evidence(yy):
        return yy + box(
            S,
            LX,
            yy,
            LW,
            "_Evidence",
            "classifier/rules.py  __slots__",
            [
                [
                    (a, "m")
                    for a in [
                        "−row : dict",
                        "−content : int",
                        "−uas : str",
                        "−rdns : str",
                        "−owner : str",
                        "−hosting : bool",
                        "−err_rate : float",
                    ]
                ],
                [("+__init__(row: dict)", "m"), ("+n(key: str) : int", "m")],
                [
                    ("row: one row of evidence_sql._classify_sql()", "s st"),
                    ("_decide(d) walks _RULES (17 rules);", "m"),
                    ("the first verdict wins", "s st"),
                ],
            ],
        )

    def rategate(yy):
        return yy + box(
            S,
            LX,
            yy,
            LW,
            "_RateGate",
            "enricher.py",
            [
                [
                    (a, "m")
                    for a in [
                        "−_interval : float",
                        "−_next_at : float",
                        "−_resume_at : float",
                        "−_lock : asyncio.Lock | None",
                    ]
                ],
                [
                    (a, "m")
                    for a in [
                        "+__init__(per_minute: int)",
                        "+reset() : None",
                        "+in_cooldown() : bool",
                        "+back_off(seconds: float) : None",
                        "+wait() : None   «async»",
                    ]
                ],
                [
                    ("_shodan_gate = _RateGate(", "m"),
                    ("    settings.shodan_requests_per_minute)", "m"),
                ],
            ],
        )

    def signal(yy):
        return yy + box(
            S,
            VX,
            yy,
            VW,
            "Signal",
            "taxonomy.py  «dataclass(frozen=True)»",
            [
                [
                    (a, "m")
                    for a in [
                        "+key : str",
                        "+alias : str",
                        "+label : str",
                        "+sql : str",
                        "+column : str = ''",
                        "+label_short : str = ''",
                        "+tip : tuple[str, str] = ()",
                        "+color_var : str = ''",
                        "+badge : str = ''",
                        "+in_clean : bool = True",
                    ]
                ],
                [
                    ("+condition(prefix='i.', ip_ref='i.ip') : str", "m"),
                    ("+short : str   «property»", "m"),
                ],
                [("SIGNALS : tuple[Signal, ...]", "m")],
            ],
        )

    def behaviour(yy):
        return yy + box(
            S,
            VX,
            yy,
            VW,
            "Behaviour",
            "sessions.py  «NamedTuple»",
            [
                [("+key : str", "m"), ("+label : str", "m"), ("+what : str", "m")],
                [
                    ("BEHAVIOURS: brute-force, enumeration,", "m"),
                    ("  recon, scraping, browsing", "m"),
                ],
            ],
        )

    def check(yy):
        return yy + box(
            S,
            VX,
            yy,
            VW,
            "Check",
            "preflight.py  «dataclass(frozen=True)»",
            [
                [
                    ("+name : str", "m"),
                    ("+status : str", "m"),
                    ("+detail : str", "m"),
                    ("+command : str = ''", "m"),
                ],
            ],
        )

    y = pair_rows([evidence, rategate], [signal, behaviour, check], y)

    # Field <- Term (left) ; Family <- Explained (right)
    fh = box(
        S,
        LX,
        y,
        LW,
        "Field",
        "search.py  «dataclass(frozen=True)»",
        [
            [
                (a, "m")
                for a in [
                    "+name : str",
                    "+label : str",
                    "+source : str  # intel|visit|child",
                    "+match : str",
                    "+columns : tuple[str, ...] = ()",
                    "+aliases : tuple[str, ...] = ()",
                    "+example : str = ''",
                    "+note : str = ''",
                ]
            ],
            [("FIELDS : tuple[Field, ...]", "m")],
        ],
    )
    fah = box(
        S,
        VX,
        y,
        VW,
        "Family",
        "families.py  «NamedTuple»",
        [
            [
                (a, "m")
                for a in [
                    "+key : str",
                    "+title : str",
                    "+what : str",
                    "+why : str",
                    "+check : str",
                    "+fix : str",
                    "+config : tuple[tuple[str, str], ...] = ()",
                ]
            ],
            [("FAMILIES : tuple[tuple[str, Family], ...]", "m")],
        ],
    )
    y2 = y + max(fh, fah) + 80
    th = box(
        S,
        LX,
        y2,
        LW,
        "Term",
        "search.py  «dataclass(frozen=True)»",
        [
            [
                (a, "m")
                for a in [
                    "+raw : str",
                    "+value : str",
                    "+field : Field | None = None",
                    "+match : str = BROAD",
                ]
            ],
            [("+label : str   «property»", "m")],
            [("parse(q) : tuple[list[Term], list[str]]", "m")],
        ],
    )
    eh = box(
        S,
        VX,
        y2,
        VW,
        "Explained",
        "families.py  «NamedTuple»",
        [
            [("+family : Family", "m"), ("+paths : list[str]", "m"), ("+checks : list[str]", "m")],
            [("explain_paths(paths, host) : list[Explained]", "m")],
        ],
    )
    S.path([(LX + 210, y2), (LX + 210, y + fh)], "ln", end="open")
    S.text(LX + 224, y + fh + 30, "field", "m")
    S.text(LX + 224, y2 - 12, "0..1", "m")
    S.path([(VX + 210, y2), (VX + 210, y + fah)], "ln", end="open")
    S.text(VX + 224, y + fah + 30, "family", "m")
    S.text(VX + 224, y2 - 12, "1", "m")
    y = y2 + max(th, eh) + 40

    # Exception <|-- PackError
    exh = box(S, LX + 90, y, 240, "Exception", "«builtin»", [], tint="ext")
    py = y + exh + 60
    pkh = box(S, LX + 90, py, 240, "PackError", "classifier/pack.py", [])
    S.path([(LX + 210, py), (LX + 210, y + exh)], "ln", end="tri")
    y = py + pkh + 40

    lh = legend_box(
        S,
        30,
        y,
        W - 60,
        "Notation",
        [
            ("tri", "generalisation: real Python inheritance"),
            ("open", "navigable association: a typed attribute, multiplicity at the target end"),
            ("dash", "dependency"),
            (
                None,
                "Stereotypes name the Python construct (dataclass, NamedTuple, TypedDict, __slots__).",
            ),
        ],
    )
    return S, y + lh + 30


# ── 3. Components ────────────────────────────────────────────────────────────


def prov(lines):
    return [("«provided»", "s st it")] + [(line, "m") for line in lines]


def req(lines):
    return [("«required»", "s st it")] + [(line, "m") for line in lines]


def components():
    W = 960
    S = Svg(
        "components",
        W,
        "Vidar components",
        "UML component diagram of Vidar's modules, their interfaces and the external services they call.",
    )
    y = header(
        S,
        "Vidar — components",
        [
            "The modules of src/ as components, all in one process (uvicorn src.main:app). «provided» and «required»",
            "compartments name the functions that cross each edge; the arrows show which component uses which.",
        ],
    )
    LX, LW = 70, 380
    RX, RW = 510, 410
    MAIN_LANE, LEFT_LANE, ROUTES_LANE, RIGHT_LANE = 40, 470, 490, 942

    # Row A: browser and CDNs
    bh = box(
        S,
        LX,
        y,
        LW,
        "Operator's browser",
        "«external»",
        [
            [
                ("reaches the dashboard only through", "s"),
                ("ssh -L 8080:localhost:8080 <user>@<host>", "m"),
                ("there is no login; the tunnel is access control", "s st"),
            ],
        ],
        tint="ext",
        name_cls="sb",
        icon="cloud",
        min_h=190,
    )
    uh = box(
        S,
        RX,
        y,
        RW,
        "unpkg.com",
        "«external»",
        [[("leaflet 1.9.4 · leaflet.markercluster 1.5.3", "m")]],
        tint="ext",
        name_cls="sb",
        icon="cloud",
    )
    ch_y = y + uh + 12
    chh = box(
        S,
        RX,
        ch_y,
        RW,
        "{s}.basemaps.cartocdn.com",
        "«external»",
        [[("map tiles; key from CARTO_API_KEY", "m")]],
        tint="ext",
        name_cls="sb",
        icon="cloud",
    )
    S.path([(LX + LW, y + uh / 2), (RX, y + uh / 2)], "ln", end="open")
    S.path([(LX + LW, ch_y + chh / 2), (RX, ch_y + chh / 2)], "ln", end="open")
    y = max(y + bh, ch_y + chh) + 70

    # Row B: main
    MX, MW = 60, 860
    mh = box(
        S,
        MX,
        y,
        MW,
        "main",
        "«component»  src/main.py",
        [
            prov(["HTTP :8080 · app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)"]),
            [
                (
                    "lifespan(): init_db() · _seed_demo() if DEMO_MODE · _init_async_globals() · await warm_caches()",
                    "m",
                ),
                (
                    "tasks: _backfill_task · tail_log · enrichment_worker · _rdns_backfill_task ·",
                    "m",
                ),
                ("       _reclassify_task · _retention_task · _backup_task", "m"),
                (
                    "middleware, outermost first: refuse_unknown_hosts → block_cross_origin_writes →",
                    "m",
                ),
                ("       security_headers → rate_limit_export", "m"),
                ("own endpoints: GET /health · GET /favicon.ico · mount /static", "m"),
            ],
            req(
                [
                    "queries: backfill_visitor_classes · force_reclassify_all · reclassify_stale_ips ·",
                    "       get_state · set_state · count_visits · the export rate-limit queries",
                    "db.run_db · db.get_conn · db.init_db · config",
                ]
            ),
        ],
        tint="proc",
        icon="component",
    )
    assembly(S, LX + LW / 2, y - 70 + 0, y, "HTTP :8080")
    main_bottom = y + mh
    lane_top = y + mh / 2
    S.path([(MX, lane_top), (MAIN_LANE, lane_top)], "ln dash")
    y = main_bottom + 70

    # Left column
    top = y
    ah = box(
        S,
        LX,
        y,
        LW,
        "/logs/access.log",
        "«artifact»",
        [[("nginx JSON access log, read-only mount", "s")]],
        tint="tbl",
        icon="artifact",
    )
    y += ah + 50
    lp_y = y
    lph = box(
        S,
        LX,
        y,
        LW,
        "log_processor",
        "«component»  src/log_processor.py",
        [
            prov(["tail_log(new_ips_queue)"]),
            [("parse_log_line · skip_reason · process_entry", "m")],
            req(
                ["queries: insert_visit · get_state · set_state", "db.run_db · models · ua_parser"]
            ),
        ],
        tint="proc",
        icon="component",
    )
    S.path([(LX + 190, lp_y), (LX + 190, top + ah)], "ln", end="open")
    S.text(LX + 204, lp_y - 18, "reads", "s st")
    y += lph + 70
    en_y = y
    S.path([(LX + 190, lp_y + lph), (LX + 190, en_y)], "ln", end="open")
    S.text(LX + 204, lp_y + lph + 30, "new_ips_queue", "m")
    S.text(LX + 204, lp_y + lph + 50, "(asyncio.Queue)", "s st")
    enh = box(
        S,
        LX,
        y,
        LW,
        "enricher",
        "«component»  src/enricher.py",
        [
            prov(["enrichment_worker(new_ips_queue)", "reverse_dns_backfill() · snapshot()"]),
            [("enrich_batch · _select_batch · _persist_batch", "m")],
            req(
                [
                    "queries: upsert_ip_intel ·",
                    "  set_visitor_class · classify_ip ·",
                    "  mark_enrichment_failed · get_stale_ips …",
                    "db.run_db · httpx.AsyncClient",
                ]
            ),
        ],
        tint="proc",
        icon="component",
    )
    y += enh + 60
    # externals 2x2 grid
    EW, GAP = 186, 8
    ext = [
        ("ip-api.com", ["POST /batch", "plain HTTP"]),
        ("internetdb.shodan.io", ["GET /{ip}", "HTTPS"]),
        ("check.torproject.org", ["GET /torbulkexitlist", "HTTPS · cached 24 h"]),
        ("DNS resolver", ["DNSBL + FCrDNS", "via to_thread"]),
    ]
    ex_top = y
    heights = []
    for i, (name, ls) in enumerate(ext[:2]):
        heights.append(
            box(
                S,
                LX + i * (EW + GAP),
                y,
                EW,
                name,
                "«external»",
                [[(line, "m") for line in ls]],
                tint="ext",
                name_cls="sb",
            )
        )
    row2 = y + max(heights) + 40
    for i, (name, ls) in enumerate(ext[2:]):
        heights.append(
            box(
                S,
                LX + i * (EW + GAP),
                row2,
                EW,
                name,
                "«external»",
                [[(line, "m") for line in ls]],
                tint="ext",
                name_cls="sb",
            )
        )
    cxs = [LX + EW / 2, LX + EW + GAP + EW / 2]
    gap_x = LX + EW + GAP / 2
    b1 = ex_top - 22
    S.path([(gap_x, en_y + enh), (gap_x, row2 - 20)], "ln")
    S.path([(cxs[0], b1), (cxs[1], b1)], "ln")
    S.dot(gap_x, b1)
    for cx in cxs:
        S.path([(cx, b1), (cx, ex_top)], "ln", end="open")
    b2 = row2 - 20
    S.path([(cxs[0], b2), (cxs[1], b2)], "ln")
    S.dot(gap_x, b2)
    for cx in cxs:
        S.path([(cx, b2), (cx, row2)], "ln", end="open")
    y = row2 + max(heights[2:]) + 60
    rt_y = y
    rth = box(
        S,
        LX,
        y,
        LW,
        "retention · archive · backup",
        "«component» ×3  src/",
        [
            prov(["run_retention() · run_backup()", "sweep_abandoned_temps()"]),
            [
                ("archive_month · restore_month · export_month", "m"),
                ("create_snapshot: VACUUM INTO + gzip · prune", "m"),
            ],
            req(
                ["queries: archive_sql · get_state · set_state", "db.get_conn · init_db · vacuum"]
            ),
        ],
        tint="proc",
        icon="component",
    )
    y += rth + 50
    dh = box(
        S,
        LX,
        y,
        LW,
        "/data/archive, /data/backup",
        "«artifact»",
        [[("archive/YYYY-MM.zip", "m"), ("backup/vidar-YYYY-MM-DD.db.gz", "m")]],
        tint="tbl",
        icon="artifact",
    )
    S.path([(LX + 190, rt_y + rth), (LX + 190, y)], "ln", end="open")
    S.text(LX + 204, rt_y + rth + 30, "writes", "s st")
    left_bottom = y + dh

    # main lane: branches to log_processor, enricher, retention (and queries, below)
    for ty in (lp_y + 40, en_y + 40, rt_y + 40):
        S.path([(MAIN_LANE, ty), (LX, ty)], "ln dash", end="open")
        S.dot(MAIN_LANE, ty)
    # left merge lane to queries
    merge_pts = [lp_y + 70, en_y + 70, rt_y + 70]
    for ty in merge_pts:
        S.path([(LX + LW, ty), (LEFT_LANE, ty)], "ln dash")
        S.dot(LEFT_LANE, ty)

    # Right column
    y = top
    rh = box(
        S,
        RX,
        y,
        RW,
        "routes",
        "«component»  src/routes/",
        [
            prov(
                [
                    "dashboard.router: 10 page modules",
                    "api.router: /api/stats, activity, visits,",
                    "  export, decisions",
                ]
            ),
            [
                ("_cache.fetch(work): reads, asyncio.to_thread", "m"),
                ("_cache.write(work): writes, db.run_db", "m"),
                ("_app.templates: Jinja2Templates", "m"),
            ],
            req(
                [
                    "queries: the page queries",
                    "report · families · incidents · sessions",
                    "preflight · enricher.snapshot() · db",
                ]
            ),
        ],
        tint="cls",
        icon="component",
    )
    S.path([(RX + 205, main_bottom), (RX + 205, y)], "ln dash", end="open")
    routes_y = y
    y += rh + 60
    tp_y = y
    tph = box(
        S,
        RX,
        y,
        RW,
        "templates · static",
        "«component»  src/templates/, src/static/",
        [
            [
                ("templates/*.html · templates/macros/*.html", "m"),
                ("static/css · static/js · static/img", "m"),
                ("base.html's inline script carries", "s"),
                ("request.state.csp_nonce", "m"),
            ],
        ],
        tint="cls",
        icon="component",
    )
    S.path([(RX + 205, routes_y + rh), (RX + 205, tp_y)], "ln dash", end="open")
    y += tph + 60
    # derived-on-read package
    pk_y = y
    inner = y + 40
    minis = [
        ("sessions.py", ["SESSION_GAP_SECONDS · BEHAVIOURS", "behaviour_for(session)"]),
        (
            "incidents.py",
            ["SIGNATURE_PATHS · INCIDENT_GAP_SECONDS", "MIN_ADDRESSES · score · score_parts"],
        ),
        ("families.py", ["explain_paths · unexplained_paths"]),
        ("report.py, report_text.py", ["build_report · available_months", "render_markdown"]),
    ]
    for name, ls in minis:
        hh = box(
            S, RX + 14, inner, RW - 28, name, None, [[(line, "m") for line in ls]], tint="proc"
        )
        inner += hh + 12
    pk_h = inner - pk_y + 4
    S.rect(RX, pk_y, RW, pk_h, "frame")
    S.text(RX + 14, pk_y + 26, "«package» derived on read, never stored", "s st")
    S.path(
        [
            (RX + RW, routes_y + 60),
            (RIGHT_LANE, routes_y + 60),
            (RIGHT_LANE, pk_y + 60),
            (RX + RW, pk_y + 60),
        ],
        "ln dash",
        end="open",
    )
    S.path([(RX, routes_y + 60), (ROUTES_LANE, routes_y + 60)], "ln dash")
    right_bottom = pk_y + pk_h

    # queries
    qy = max(left_bottom, right_bottom) + 70
    S.path([(LEFT_LANE, merge_pts[0]), (LEFT_LANE, qy)], "ln dash", end="open")
    S.path([(ROUTES_LANE, routes_y + 60), (ROUTES_LANE, qy)], "ln dash", end="open")
    S.path([(RX + 205, pk_y + pk_h), (RX + 205, qy)], "ln dash", end="open")
    pairs = [
        ("_shared       window, filters, grouping", "stats        the Overview's numbers"),
        ("visits        raw rows · insert_visit", "analysis     charts, facets, exposure"),
        ("visitors      per-IP aggregation", "intel        ip_intel, classes, state"),
        ("aggregations  the /visitors groupings", "archive_sql  the archive's SQL"),
        ("sessions      get_sessions", "decisions    the /api/decisions feed"),
        ("baseline      the median ordinary hour", "incidents    cross-address incidents"),
    ]
    QX, QW = 60, 860
    qh = box(
        S,
        QX,
        qy,
        QW,
        "queries",
        "«component»  src/queries/  (12 subject modules)",
        [
            [
                (
                    "__init__ re-exports every name of the former queries.py, including classifier.classify_ip",
                    "m",
                )
            ],
            [(p, "pair") for p in pairs],
            req(
                [
                    "classifier · sessions · incidents · search · taxonomy · sqltext · validators · config · db.network_of"
                ]
            ),
        ],
        tint="tbl",
        icon="component",
    )
    S.path([(MAIN_LANE, lane_top), (MAIN_LANE, qy + 40), (QX, qy + 40)], "ln dash", end="open")
    y = qy + qh + 70
    clh = box(
        S,
        LX,
        y,
        LW,
        "classifier",
        "«component»  src/classifier/",
        [
            prov(
                [
                    "classify_ip(conn, ip) : str",
                    "explain_classification(conn, ip)",
                    "CLASSIFIER_VERSION",
                ]
            ),
            [
                ("patterns.toml → pack.load() → patterns", "m"),
                ("_classify_sql() → rules._decide()", "m"),
                ("runs its evidence query on the given conn", "s st"),
            ],
            req(["config · models · sqltext"]),
        ],
        tint="proc",
        icon="component",
    )
    dbh = box(
        S,
        RX,
        y,
        RW,
        "db",
        "«component»  src/db.py",
        [
            prov(["get_conn() · run_db(work, *args)", "init_db() · vacuum() · network_of(ip)"]),
            [("SCHEMA · INDEXES · idempotent migrations", "m")],
        ],
        tint="tbl",
        icon="component",
    )
    S.path([(LX + 190, qy + qh), (LX + 190, y)], "ln dash", end="open")
    S.path([(RX + 205, qy + qh), (RX + 205, y)], "ln dash", end="open")
    y2 = y + dbh + 50
    vdh = box(
        S,
        RX,
        y2,
        RW,
        "/data/vidar.db",
        "«artifact»",
        [[("SQLite in WAL mode (+ -wal, -shm)", "s")]],
        tint="tbl",
        icon="db",
    )
    S.path([(RX + 205, y + dbh), (RX + 205, y2)], "ln", end="open")
    y3 = y + clh + 50
    shh = box(
        S,
        LX,
        y3,
        LW,
        "shared modules",
        "«component» ×10  src/",
        [
            [
                ("config · models · taxonomy · search", "m"),
                ("validators · sqltext · ua_parser", "m"),
                ("template_filters · preflight · demo", "m"),
                ("imported widely; those edges are not drawn", "s st"),
            ],
        ],
        tint="cls",
        icon="component",
    )
    y = max(y2 + vdh, y3 + shh) + 40

    lh = legend_box(
        S,
        30,
        y,
        W - 60,
        "Notation",
        [
            ("ball", "provided interface (ball) used through a required one (socket)"),
            ("dash", "«use» dependency; a dot joins several edges that share one line"),
            ("open", "reads from, writes to or calls an artifact or external service"),
            (
                None,
                "Abstracted: retention, archive and backup are one box; ten small modules are 'shared modules'.",
            ),
            (
                None,
                "db.get_conn / db.run_db are also used directly by log_processor, enricher, retention and routes.",
            ),
            (
                None,
                "enrich_batch calls the providers one step after another: ip-api, then Shodan for every IP,",
            ),
            (
                None,
                "then reverse DNS for every IP, then the Tor list, then DNSBL. Each step gathers across IPs.",
            ),
        ],
    )
    return S, y + lh + 30


# ── 4. Deployment ────────────────────────────────────────────────────────────


def deployment():
    W = 960
    S = Svg(
        "deployment",
        W,
        "Vidar deployment",
        "Deployment view of Vidar: hosts, the container, mounts, ports, the SSH tunnel and external services.",
    )
    y = header(
        S,
        "Vidar — deployment",
        [
            "deploy/docker-compose.yml and deploy/Dockerfile as installed by deploy/deploy_remote.sh under /srv/vidar.",
            "Host paths are the compose defaults (NGINX_LOG_DIR, VIDAR_DATA_DIR).",
        ],
    )
    top = y + 14
    # Row 1: three nodes
    node3d(S, 30, top, 290, 290, "«device»", "Operator workstation")
    bh = box(
        S,
        44,
        top + 62,
        262,
        "Browser",
        "«execution environment»",
        [[("http://localhost:8080/", "m")]],
        tint="cls",
        name_cls="sb",
    )
    sh_y = top + 62 + bh + 40
    shh = box(
        S,
        44,
        sh_y,
        262,
        "ssh client",
        None,
        [[("ssh -L 8080:localhost:8080", "m"), ("    <user>@<host>", "m")]],
        tint="proc",
        name_cls="sb",
    )
    S.path([(175, top + 62 + bh), (175, sh_y)], "ln", end="open")

    node3d(S, 350, top, 280, 290, "«external» loaded by the browser", "CDNs")
    uh = box(
        S,
        364,
        top + 62,
        252,
        "unpkg.com",
        None,
        [[("leaflet 1.9.4", "m"), ("leaflet.markercluster 1.5.3", "m")]],
        tint="ext",
        name_cls="sb",
    )
    box(
        S,
        364,
        top + 62 + uh + 16,
        252,
        "basemaps.cartocdn.com",
        None,
        [[("map tiles (CARTO_API_KEY)", "m")]],
        tint="ext",
        name_cls="sb",
    )
    S.path([(306, top + 62 + bh / 2), (364, top + 62 + bh / 2)], "ln", end="open")

    node3d(S, 660, top, 270, 290, "«device», many", "Site visitors")
    S.text(674, top + 90, "people, crawlers and scanners", "s st")
    S.text(674, top + 110, "on the public internet", "s st")
    row1_bottom = top + 290

    # boundary
    by = row1_bottom + 40
    S.path([(20, by), (W - 20, by)], "ln dash")
    S.text(30, by - 10, "public internet", "s st")
    S.text(30, by + 24, "server", "s st")

    # server node
    sx, sy, sw = 30, by + 60, 900
    inner_top = sy + 62
    server_parts_start = len(S.parts)
    sshd_h = box(
        S,
        50,
        inner_top,
        280,
        "sshd",
        "«process» on the host",
        [[("listens :22", "m"), ("accepts the -L forward", "s")]],
        tint="proc",
        name_cls="sb",
    )
    ng_h = box(
        S,
        490,
        inner_top,
        420,
        "nginx",
        "«execution environment»",
        [
            [
                ("host or container — outside this repo", "s st"),
                ("listens :80 / :443", "m"),
                ("log_format json_log", "m"),
                ("deploy/nginx-log-format.conf; UTC timestamps", "s"),
            ]
        ],
        tint="cls",
        name_cls="sb",
    )
    fs_y = inner_top + ng_h + 60
    fs_h = box(
        S,
        490,
        fs_y,
        420,
        "host filesystem",
        "«artifact»",
        [
            [
                ("/srv/nginx/logs/access.log", "m"),
                ("/srv/vidar/data/   vidar.db, archive/, backup/", "m"),
                ("/srv/vidar/.env    plus deploy/, src/, docs/", "m"),
            ]
        ],
        tint="tbl",
        name_cls="sb",
        icon="artifact",
    )
    S.path([(700, inner_top + ng_h), (700, fs_y)], "ln", end="open")
    S.text(714, inner_top + ng_h + 36, "appends", "s st")

    cy = fs_y + fs_h + 80
    cx, cw = 50, 860
    # container
    facts = [
        "service vidar · container_name vidar · image deploy-vidar:latest from deploy/Dockerfile",
        "FROM python:3.12-slim pinned by digest · USER appuser (uid 1000) · WORKDIR /app",
        "read_only · tmpfs /tmp, /var/log, /var/run · cap_drop ALL · no-new-privileges · pids_limit 256",
        "restart unless-stopped · json-file logs 10m × 3 · HEALTHCHECK every 30 s: GET /health",
        "CMD uvicorn src.main:app --host 0.0.0.0 --port 8080",
        "ports 127.0.0.1:${VIDAR_PORT:-8080}:8080 (loopback only)",
        "volumes /logs ← /srv/nginx/logs (ro) · /data ← /srv/vidar/data (rw) · env_file ../.env",
    ]
    loop = [
        ("startup: init_db() · _init_async_globals() · await warm_caches()", "m"),
        ("tail_log              every POLL_INTERVAL_SECONDS (1.0 s), ≤ 1 MB per tick", "m"),
        ("enrichment_worker     batches of ≤ 100 IPs, 4.5 s apart; 5 s when idle", "m"),
        ("_rdns_backfill_task   once at startup", "m"),
        ("_backfill_task        once: force_reclassify_all or backfill_visitor_classes", "m"),
        (
            "_reclassify_task      every RECLASSIFY_INTERVAL_MINUTES (15): reclassify_stale_ips",
            "m",
        ),
        (
            "_retention_task       hourly tick; run_retention() when the last run is ≥ 1 day old",
            "m",
        ),
        ("_backup_task          hourly tick; run_backup() when the last run is ≥ 1 day old", "m"),
        ("requests              refuse_unknown_hosts → block_cross_origin_writes →", "m"),
        ("                      security_headers → rate_limit_export → routes", "m"),
        ("No cron. In DEMO_MODE only _backfill_task starts.", "s st"),
    ]
    threads = [
        (
            "db.run_db             _write_batch · _select_batch · _persist_batch (classify_ip) ·",
            "m",
        ),
        (
            "  (shielded)          the backfill and reclassify passes · rDNS backfill · _cache.write",
            "m",
        ),
        (
            "asyncio.to_thread     _cache.fetch (route reads) · warm_caches · retention and backup",
            "m",
        ),
        (
            "                      get_state reads · run_retention · run_backup · sweep_abandoned_temps",
            "m",
        ),
        (
            "                      _dnsbl_lookup · _reverse_dns_lookup (≤ DNS_TIMEOUT_SECONDS wait)",
            "m",
        ),
    ]
    hh = 10 + ROW + ROW + 8
    lb_h = 10 + ROW * 2 + 8 + 12 + ROW * len(loop)
    th_h = 10 + ROW * 2 + 8 + 12 + ROW * len(threads)
    c_h = hh + 12 + ROW * len(facts) + 16 + lb_h + 20 + th_h + 20
    S.rect(cx, cy, cw, c_h, "box")
    S.rect(cx + 0.6, cy + 0.6, cw - 1.2, hh - 0.6, "hdr proc")
    S.text(cx + 12, cy + 25, "«container»", "s st")
    S.text(cx + 12, cy + 45, "vidar", "mb")
    S.line(cx, cy + hh, cx + cw, cy + hh)
    for i, f in enumerate(facts):
        S.text(cx + 12, cy + hh + 21 + i * ROW, f, "m", limit=cw - 24)
    ly = cy + hh + 12 + ROW * len(facts) + 16
    box(
        S,
        cx + 16,
        ly,
        cw - 32,
        "one asyncio event loop",
        "«process» uvicorn",
        [loop],
        tint="proc",
        name_cls="sb",
    )
    ty = ly + lb_h + 20
    box(
        S,
        cx + 16,
        ty,
        cw - 32,
        "default thread pool",
        "«thread»",
        [threads],
        tint="proc",
        name_cls="sb",
    )

    # edges into the container
    S.path([(190, sy + 62 + sshd_h), (190, cy)], "ln", end="open")
    S.text(204, cy - 40, "TCP 127.0.0.1:8080", "m")
    for x, lab, both in (
        (560, "/logs :ro", False),
        (700, "/data :rw", True),
        (840, "env_file", False),
    ):
        S.path([(x, fs_y + fs_h), (x, cy)], "ln", end="open", start="open" if both else None)
        S.text(x + 12, fs_y + fs_h + 46, lab, "m")
    server_bottom = cy + c_h + 30
    before = len(S.parts)
    node3d(
        S,
        sx,
        sy,
        sw,
        server_bottom - sy,
        "«device»",
        "Server host · Docker Engine + Compose",
        center=True,
    )
    node_parts = S.parts[before:]
    del S.parts[before:]
    S.parts[server_parts_start:server_parts_start] = node_parts

    # SSH and HTTP crossing the boundary
    S.path([(175, sh_y + shh), (175, inner_top)], "ln", end="open")
    S.text(190, by - 10, "SSH :22", "m")
    S.path([(795, row1_bottom), (795, inner_top)], "ln", end="open")
    S.text(780, by - 10, "HTTP :80, HTTPS :443", "m", "end")

    # external providers
    py = server_bottom + 80
    PW = 435
    prov_boxes = [
        ("ip-api.com", ["POST http://ip-api.com/batch", "plain HTTP · ≤ 100 IPs · 4.5 s pacing"]),
        (
            "internetdb.shodan.io",
            ["GET https://internetdb.shodan.io/{ip}", "≤ 10 concurrent · ≤ 600 per minute"],
        ),
        (
            "check.torproject.org",
            ["GET /torbulkexitlist over HTTPS", "cached 24 h · 3 attempts, then 5 min"],
        ),
        (
            "DNS resolver of the container",
            ["DNSBL lookups per DNSBL_PROVIDERS", "FCrDNS: PTR, then forward lookup"],
        ),
    ]
    frame_top = py
    fy = py + 44
    hs = []
    for i, (n, ls) in enumerate(prov_boxes[:2]):
        hs.append(
            box(
                S,
                45 + i * (PW + 0),
                fy,
                PW - 15,
                n,
                "«external»",
                [[(line, "m") for line in ls]],
                tint="ext",
                name_cls="sb",
                icon="cloud",
            )
        )
    fy2 = fy + max(hs) + 44
    for i, (n, ls) in enumerate(prov_boxes[2:]):
        hs.append(
            box(
                S,
                45 + i * (PW + 0),
                fy2,
                PW - 15,
                n,
                "«external»",
                [[(line, "m") for line in ls]],
                tint="ext",
                name_cls="sb",
                icon="cloud",
            )
        )
    frame_h = fy2 + max(hs[2:]) + 50 - frame_top
    S.rect(30, frame_top, 900, frame_h, "frame")
    S.text(
        45,
        frame_top + frame_h - 16,
        "«external» services called one step after another by enrich_batch; only the IP address is sent",
        "s st",
    )
    cxs = [45 + (PW - 15) / 2, 45 + PW + (PW - 15) / 2]
    gx = 45 + PW - 7.5
    j1 = fy - 16
    j2 = fy2 - 16
    S.path([(gx, cy + c_h), (gx, j2)], "ln")
    for j, yy in ((j1, fy), (j2, fy2)):
        S.path([(cxs[0], j), (cxs[1], j)], "ln")
        S.dot(gx, j)
        for c in cxs:
            S.path([(c, j), (c, yy)], "ln", end="open")
    y = frame_top + frame_h + 30
    lh = legend_box(
        S,
        30,
        y,
        900,
        "Reading this view",
        [
            (
                None,
                "3D boxes are UML nodes; the dashed line is the boundary to the public internet.",
            ),
            (None, "Order of the outbound calls: ip-api, Shodan, reverse DNS, Tor list, DNSBL."),
            (
                None,
                "The dashboard has no login: the loopback-only port plus the SSH tunnel is the access control,",
            ),
            (None, "and ALLOWED_HOSTS is checked before any route runs."),
            (
                None,
                "vidar shares no Docker network with nginx; the coupling is the read-only log mount and its format.",
            ),
        ],
    )
    return S, y + lh + 30


# ── 5. Sequences ─────────────────────────────────────────────────────────────


class Seq:
    def __init__(self, key, title, desc, heading, subtitle, lifelines, width=1000):
        self.S = Svg(key, width, title, desc)
        self.heading, self.subtitle = heading, subtitle
        self.lifelines = lifelines  # list of (key, stereo, name, x)
        self.X = {k: x for k, _, _, x in lifelines}
        self.steps = []

    def call(self, a, b, *label):
        self.steps.append(("call", a, b, list(label)))

    def ret(self, a, b, *label):
        self.steps.append(("ret", a, b, list(label)))

    def send(self, a, b, *label):
        self.steps.append(("send", a, b, list(label)))

    def self_(self, a, *label):
        self.steps.append(("self", a, a, list(label)))

    def frame(self, kind, cond, a, b):
        self.steps.append(("fstart", a, b, [kind, cond]))

    def end(self):
        self.steps.append(("fend", None, None, []))

    def build(self, notes):
        S = self.S
        W = S.w
        y = header(S, self.heading, self.subtitle)
        head_y = y
        y = head_y + 52 + 30
        rows, frames, stack = [], [], []
        for kind, a, b, label in self.steps:
            if kind == "fstart":
                y += 6
                stack.append((a, b, label[0], label[1], y, len(stack)))
                y += 40
            elif kind == "fend":
                f = stack.pop()
                y += 8
                frames.append((f, y))
                y += 22
            elif kind == "self":
                rows.append((kind, a, b, label, y))
                y += max(38, 20 * len(label) + 14) + 16
            else:
                y += 20 * len(label)
                rows.append((kind, a, b, label, y))
                y += 22
        body_bottom = y + 10

        for _key, stereo, name, x in self.lifelines:
            w = max(text_width(name, "mb"), text_width(stereo, "s")) + 20
            S.rect(x - w / 2, head_y, w, 52, "box hdr")
            S.text(x, head_y + 21, stereo, "s st", "middle")
            S.text(x, head_y + 42, name, "mb", "middle")
            S.path([(x, head_y + 52), (x, body_bottom)], "life")

        for (a, b, kind, cond, fy, depth), fy2 in frames:
            pad = 62 - depth * 12
            x1, x2 = self.X[a] - pad, self.X[b] + pad
            if x2 > W - 12:
                x2 = W - 12
            S.rect(x1, fy, x2 - x1, fy2 - fy, "sframe")
            lw = len(kind) * 9 + 22
            S.add(
                f'<path class="box hdr" d="M{f1(x1)},{f1(fy)} L{f1(x1 + lw)},{f1(fy)} L{f1(x1 + lw)},{f1(fy + 14)} '
                f'L{f1(x1 + lw - 8)},{f1(fy + 24)} L{f1(x1)},{f1(fy + 24)} Z"/>'
            )
            S.text(x1 + 7, fy + 17, kind, "mb")
            cw = text_width(f"[{cond}]", "m")
            if x1 + lw + 10 + cw > x2 - 6:
                S.warnings.append(f"frame condition overflows: {cond}")
            S.text(x1 + lw + 10, fy + 17, f"[{cond}]", "m", knock=True)

        for kind, a, b, label, yy in rows:
            xa, xb = self.X[a], self.X[b]
            if kind == "self":
                wmax = max(text_width(t, "m") for t in label)
                side = 1 if xa + 50 + wmax <= W - 16 else -1
                ex = xa + 36 * side
                S.rect(xa - 4, yy - 4, 8, 26, "act")
                S.path(
                    [(xa + 4 * side, yy), (ex, yy), (ex, yy + 18), (xa + 5 * side, yy + 18)],
                    "ln",
                    end="filled",
                )
                for i, t in enumerate(label):
                    tx = ex + 10 * side
                    S.text(
                        tx,
                        yy + 14 + i * 20,
                        t if side > 0 else t.strip(),
                        "m",
                        "start" if side > 0 else "end",
                        knock=True,
                    )
                continue
            dirn = 1 if xb > xa else -1
            cls = "ln dash" if kind == "ret" else "ln"
            marker = "filled" if kind == "call" else "open"
            if kind == "call":
                S.rect(xb - 4, yy - 3, 8, 16, "act")
            S.path([(xa + 4 * dirn, yy), (xb - 5 * dirn, yy)], cls, end=marker)
            wmax = max((text_width(t, "m") for t in label), default=0)
            lx = min(xa, xb) + 12
            if lx + wmax > W - 16:
                lx = W - 16 - wmax
            for i, t in enumerate(label):
                S.text(lx, yy - 9 - (len(label) - 1 - i) * 20, t, "m", knock=True)

        y = body_bottom + 30
        lh = legend_box(
            S,
            30,
            y,
            W - 60,
            "Notation",
            [
                (
                    "filled",
                    "call the caller waits for (awaited coroutine, or a blocking call in a thread)",
                ),
                ("open", "asynchronous send: the caller does not wait for a reply"),
                ("ret", "return"),
            ]
            + [(None, n) for n in notes],
        )
        return S, y + lh + 30


def sequence_ingest():
    q = Seq(
        "sequence-ingest",
        "Vidar ingestion sequence",
        "UML sequence: a new nginx log line becomes a visits row and its IP is queued for enrichment.",
        "Vidar — ingestion: log line to visit",
        [
            "tail_log() is an asyncio task; blocking SQLite work runs in a worker thread through db.run_db,",
            "so the event loop keeps serving while a batch is written.",
        ],
        [
            ("nginx", "«external»", "nginx", 85),
            ("log", "«artifact»", "access.log", 215),
            ("tail", "«asyncio task»", "tail_log()", 350),
            ("queue", "«asyncio.Queue»", "new_ips_queue", 495),
            ("thread", "«thread»", "worker thread", 640),
            ("queries", "«component»", "queries", 790),
            ("db", "«artifact»", "SQLite", 925),
        ],
    )
    q.frame("loop", "every POLL_INTERVAL_SECONDS (1.0 s)", "nginx", "db")
    q.send("nginx", "log", "append a JSON line")
    q.call("tail", "log", "_read_batch(fh, offset)", "reads at most 1 MB")
    q.ret("log", "tail", "raw_lines, new_offset")
    q.call("tail", "thread", "await db.run_db(_write_batch, lines, …)", "to_thread + shield")
    q.call("thread", "db", "db.get_conn(): one transaction")
    q.frame("loop", "each line", "thread", "db")
    q.self_("thread", "parse_log_line(line)", "  : LogEntry | None")
    q.self_(
        "thread", "skip_reason(entry)", "  internal or invalid IP,", "  static asset, health check"
    )
    q.self_("thread", "process_entry(entry)", "  : Visit")
    q.call("thread", "queries", "insert_visit(conn, **visit)")
    q.call("queries", "db", "INSERT INTO visits")
    q.end()
    q.call(
        "thread", "queries", "set_state(conn, …) ×3", "file_offset, file_inode, file_fingerprint"
    )
    q.call("queries", "db", "INSERT … ON CONFLICT", "(key) DO UPDATE")
    q.call("thread", "db", "COMMIT on exit;", "ROLLBACK keeps the offset")
    q.ret("thread", "tail", "(unparseable, invalid_ips, non_utc,", " batch_ips, first_keys)")
    q.frame("opt", "IP not yet in seen_ips", "tail", "thread")
    q.send(
        "tail",
        "queue",
        "await wait_for(queue.put(ip), 1.0 s)",
        "skipped when the queue stays full",
    )
    q.end()
    q.end()
    return q.build(
        [
            "seen_ips remembers up to 50 000 addresses per process; the enricher still drops IPs whose intel is fresh.",
            "Rotation, truncation and the first-start read position are handled in tail_log and not shown.",
        ]
    )


def sequence_enrich():
    q = Seq(
        "sequence-enrich",
        "Vidar enrichment sequence",
        "UML sequence: the enrichment worker looks up a batch of IPs step by step, then classifies them.",
        "Vidar — enrichment and classification",
        [
            "enrichment_worker() is an asyncio task. enrich_batch runs its provider steps one after another;",
            "inside a step, asyncio.gather runs one lookup per IP concurrently.",
        ],
        [
            ("worker", "«asyncio task»", "enrichment_worker()", 105),
            ("http", "«external»", "HTTP providers", 285),
            ("dns", "«external»", "DNS resolver", 420),
            ("thread", "«thread»", "worker thread", 550),
            ("queries", "«component»", "queries", 690),
            ("classifier", "«component»", "classifier", 815),
            ("db", "«artifact»", "SQLite", 930),
        ],
    )
    q.frame("loop", "while True", "worker", "db")
    q.self_("worker", "new_ips_queue.get_nowait()", "  until 100 IPs or empty")
    q.call("worker", "thread", "await run_db(_select_batch, pending)")
    q.call("thread", "queries", "get_unenriched_ips ·", "get_stale_ips · get_ip_intel_bulk")
    q.ret("thread", "worker", "to_enrich")
    q.call("worker", "http", "1  POST http://ip-api.com/batch")
    q.ret("http", "worker", "JSON list; X-Rl, X-Ttl")
    q.frame("par", "gather: one per IP", "worker", "dns")
    q.call("worker", "http", "2  GET https://internetdb.shodan.io/{ip}")
    q.ret("http", "worker", "dict | None")
    q.end()
    q.frame("par", "gather: one per IP", "worker", "dns")
    q.call("worker", "dns", "3  to_thread(_reverse_dns_lookup)", "gethostbyaddr, then getaddrinfo")
    q.ret("dns", "worker", "confirmed name | ''")
    q.end()
    q.frame("opt", "cached list older than 24 h", "worker", "dns")
    q.call("worker", "http", "4  GET https://check.torproject.org/", "torbulkexitlist")
    q.ret("http", "worker", "exit-node set")
    q.end()
    q.frame("opt", "DNSBL_ENABLED; gather per IP", "worker", "dns")
    q.call("worker", "dns", "5  to_thread(_dnsbl_lookup)", "per DNSBL_PROVIDERS zone")
    q.ret("dns", "worker", "listed | not | None")
    q.end()
    q.self_("worker", "stamp fetched_at on every row")
    q.call("worker", "thread", "await run_db(_persist_batch, …)")
    q.frame("loop", "each result", "thread", "db")
    q.call("thread", "queries", "upsert_ip_intel(conn, intel)")
    q.call("queries", "db", "INSERT … ON CONFLICT", "+ child tables")
    q.call("thread", "classifier", "classify_ip(conn, ip)")
    q.call("classifier", "db", "_classify_sql()")
    q.self_(
        "classifier", "_apply_priority_chain(row)", "→ _decide(): first of", "   17 rules wins"
    )
    q.ret("classifier", "thread", "'group/class'")
    q.call("thread", "queries", "set_visitor_class(conn, ip, label)")
    q.call("queries", "db", "UPDATE ip_intel")
    q.end()
    q.call("thread", "db", "COMMIT on get_conn() exit")
    q.ret("thread", "worker")
    q.self_("worker", "await asyncio.sleep(4.5)")
    q.end()
    return q.build(
        [
            "HTTP providers: ip-api.com, internetdb.shodan.io and check.torproject.org, drawn as one lifeline.",
            "IPs ip-api rejects are recorded with mark_enrichment_failed and classified the same way.",
            "classify_ip is imported through the queries package, which re-exports the classifier.",
        ]
    )


def sequence_request():
    q = Seq(
        "sequence-request",
        "Vidar request sequence",
        "UML sequence: a dashboard GET through the middleware stack, the aggregate cache and Jinja rendering.",
        "Vidar — a dashboard request (GET /)",
        [
            "Middleware runs outermost first. Route handlers read the database only inside _cache.fetch,",
            "which moves the work to a worker thread with its own connection.",
        ],
        [
            ("browser", "«external»", "Browser", 70),
            ("mw", "«middleware» ×4", "main.py", 200),
            ("route", "«route»", "overview()", 345),
            ("jinja", "«component»", "Jinja2Templates", 505),
            ("thread", "«thread»", "worker thread", 665),
            ("queries", "«component»", "queries", 800),
            ("db", "«artifact»", "SQLite", 925),
        ],
    )
    q.call("browser", "mw", "GET /  Host: localhost:8080")
    q.self_("mw", "refuse_unknown_hosts:", "  host must be in ALLOWED_HOSTS, else 400")
    q.self_("mw", "block_cross_origin_writes:", "  GET is not a write, pass")
    q.self_("mw", "security_headers:", "  request.state.csp_nonce = token_urlsafe(16)")
    q.self_("mw", "rate_limit_export:", "  path is not /api/export, call_next")
    q.call("mw", "route", "overview(request, …)")
    q.call("route", "thread", "await _cache.fetch(_load)", "asyncio.to_thread, own get_conn()")
    q.call(
        "thread", "queries", "get_stats · get_daily_kpis", "(60 s cache) · get_visitor_ip_counts"
    )
    q.call("queries", "db", "SELECT …")
    q.ret("thread", "route", "stats, kpis, counts, prev_visits")
    q.call("route", "thread", "await asyncio.to_thread(_attention_items)")
    q.ret("thread", "route", "attention")
    q.call("route", "jinja", "TemplateResponse(request,", "'overview.html', ctx)")
    q.self_(
        "jinja",
        "render base.html: inline <script>",
        "  gets request.state.csp_nonce;",
        "  attention_count(), earliest_date()",
        "  read caches",
    )
    q.ret("jinja", "route", "response")
    q.self_("route", "_remember_range(): range cookie")
    q.ret("route", "mw", "response")
    q.self_(
        "mw",
        "security_headers adds nosniff,",
        "  X-Frame-Options DENY,",
        "  Referrer-Policy no-referrer,",
        "  Content-Security-Policy with nonce",
    )
    q.ret("mw", "browser", "200 text/html")
    return q.build(
        [
            "Writes (Settings POSTs) use _cache.write, which runs through db.run_db and then refreshes the caches.",
            "Other pages follow the same shape with their own queries and template.",
        ]
    )


# ── Main ─────────────────────────────────────────────────────────────────────

DIAGRAMS = [
    ("data-model.svg", data_model),
    ("classes.svg", classes),
    ("components.svg", components),
    ("architecture.svg", deployment),
    ("sequence-ingest.svg", sequence_ingest),
    ("sequence-enrich.svg", sequence_enrich),
    ("sequence-request.svg", sequence_request),
]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    out = argv[1]
    os.makedirs(out, exist_ok=True)
    problems = 0
    for filename, build in DIAGRAMS:
        svg, height = build()
        for w in svg.warnings:
            print(f"{filename}: {w}", file=sys.stderr)
            problems += 1
        with open(os.path.join(out, filename), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(svg.render(int(height)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
