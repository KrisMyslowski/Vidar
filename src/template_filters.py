"""Jinja2 template filters for the dashboard.

Sections:
  Formatting   — dates, bytes, response time, language
  List/Badge   — comma-list truncation with +N badge, tag-colored badges
  CPE          — CPE string parsing (OS and service entries)
  Path         — scanner/probe path tooltips
  Registration — register_filters() wires everything onto the Jinja2 env
"""

from __future__ import annotations

from datetime import datetime

import jinja2
from markupsafe import Markup, escape

# Shodan tag colours. Deliberately its own palette, not the signal one: these are
# Shodan's words about the *host* ("tor", "vpn", "proxy" = this box runs one), while
# --sig-tor/--sig-proxy describe our own verdict about the *visitor*. Same words,
# different claims, so they do not share a hue.
_TAG_COLORS: dict[str, str] = {
    "scanner": "badge-red",
    "honeypot": "badge-yellow",
    "tor": "badge-yellow",
    "vpn": "badge-yellow",
    "proxy": "badge-yellow",
}

_PATH_TIPS: dict[str, tuple[str, str]] = {
    "wp-admin": (
        "WordPress admin panel.",
        "Automated scan for unprotected installations.",
    ),
    "wp-login": (
        "WordPress login page.",
        "Brute-force or credential-stuffing target.",
    ),
    ".env": (
        "Environment config file.",
        "Scanned for leaked credentials and API keys.",
    ),
    ".git": (
        "Git repository files.",
        "Probed for source code exposure.",
    ),
    "xmlrpc": (
        "WordPress XML-RPC.",
        "Vector for brute force and DDoS amplification.",
    ),
    "phpinfo": (
        "PHP info page.",
        "Reveals server config, PHP version, loaded modules.",
    ),
    "cgi-bin": (
        "Legacy CGI scripts.",
        "Probed for remote code execution.",
    ),
    "etc/passwd": (
        "Unix password file.",
        "Path traversal / directory escape attempt.",
    ),
    "etc/shadow": (
        "Unix shadow file.",
        "Path traversal for password hash extraction.",
    ),
    "install.php": (
        "CMS install script.",
        "Probed for unfinished or exposed installations.",
    ),
    ".sh": (
        "Shell script.",
        "Probed for command execution opportunities.",
    ),
    "binary payload": (
        "Non-HTTP binary data on HTTP port.",
        "TLS-on-plain or scanner handshake.",
    ),
    "handshake": (
        "TLS handshake on plain HTTP port.",
        "Misconfigured client or protocol scanner.",
    ),
    "phpmyadmin": (
        "phpMyAdmin panel.",
        "Probed for unauthenticated database access.",
    ),
    "admin": (
        "Generic admin path.",
        "Automated scan for exposed admin interfaces.",
    ),
    "backup": (
        "Backup file probe.",
        "Scanning for exposed database or site backups.",
    ),
    "config": (
        "Config file probe.",
        "Scanning for exposed configuration files.",
    ),
    "setup": (
        "Setup script.",
        "Probed for unprotected installation endpoints.",
    ),
}


# ── Formatting ───────────────────────────────────────────────────────────────


def fmtdate(value: str) -> str:
    """Convert ISO timestamp to YYYY-MM-DD HH:MM.

    ISO order, not dd.mm.yy. The dashboard is English-only, and day-first with a
    two-digit year is both the wrong convention for it and genuinely ambiguous
    against M/D for the first twelve days of any month. It also disagreed with
    everything it sits beside: the custom-range date inputs, the `2026-08` month
    keys on Storage, and the log's own $time_iso8601.
    """
    if not value:
        return ""
    if value == "—":
        return "—"
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, AttributeError):
        return value


def fmtbytes(value) -> str:
    """Convert bytes to human-readable format.

    None is an em dash, not 0 B. A missing measurement rendered as a measured
    zero is the mistake the Incidents header and the Storage columns each state
    for themselves — and it reached the page: Exposure's "Largest" tile is a
    MAX() over no rows, and reported 0 B as if it had weighed something. A real
    zero-byte response is still 0 B.
    """
    if value is None:
        return "—"
    if not value:
        return "0 B"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def fmtresptime(value) -> str:
    """Format response time as human-readable (ms or s)."""
    if value is None:
        return "—"
    v = float(value)
    if v < 1:
        return f"{v * 1000:.0f} ms"
    return f"{v:.2f} s"


def primarylang(value: str) -> str:
    """Extract primary language tag from Accept-Language header."""
    if not value:
        return ""
    if value == "—":
        return "—"
    lang = value.split(",")[0].split(";")[0].strip()
    return lang or ""


# ── List / Badge ─────────────────────────────────────────────────────────────


def fmtpct(value) -> str:
    """A share as a percentage: `0.1` becomes `0.1 %`, None an em dash.

    `%g` rather than a fixed width, so a whole number does not carry a `.0` it
    did not measure. None is not 0: a month with no addresses has no
    composition, and `0 %` would state something the data does not.
    """
    if value is None:
        return "—"
    try:
        return f"{float(value):g} %"
    except (TypeError, ValueError):
        return str(value)


def fmtpoints(value) -> str:
    """A share's movement in percentage points, signed: `-0.1 pt`, `±0`.

    Points, not percent. A share falling from 0.2 to 0.1 is 0.1 points and also
    a halving; only one of those two readings belongs beside a column of shares,
    and the unit is what says which.
    """
    if value is None:
        return "—"
    try:
        value = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{value:+g} pt" if value else "±0"


def fmtnum(value) -> str:
    """Thousands-separated integer (1,234) for count columns and stat cards.

    Non-numeric input passes through unchanged; None renders as an em dash.
    """
    if value is None:
        return "—"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def csv_items(value, cls: str = "badge-muted") -> list[dict]:
    """Split a comma-joined value into chip dicts for the overflow_cell macro.

    Each item is {'label': <value>, 'cls': <badge class>, 'tip': ''}. Used for
    the plain data columns (Port / Browser / OS / Shodan) so they render as
    uniform chips and collapse dynamically via overflow.js.
    """
    parts = [p.strip() for p in str(value or "").split(",") if p.strip()]
    # tip = the value itself, so a chip that gets ellipsised still reveals its
    # full text on hover (badges with label-help carry no underline).
    return [{"label": p, "cls": cls, "tip": p} for p in parts]


def badge_list(csv: str, style_map=None, default: str = "badge-muted") -> Markup:
    """Render a comma-separated string as a row of colored badge spans.

    style_map: dict mapping lowercase value → CSS class; None uses _TAG_COLORS.
    default: CSS class for values not in style_map.
    """
    if not csv:
        return Markup("—")
    parts = [p.strip() for p in csv.split(",") if p.strip()]
    if not parts:
        return Markup("—")
    sm = _TAG_COLORS if style_map is None else style_map
    badges = [
        f'<span class="badge {sm.get(p.lower(), default)}">{escape(p)}</span>' for p in parts
    ]
    return Markup(" ".join(badges))


# ── CPE ──────────────────────────────────────────────────────────────────────


def parse_cpe(value: str) -> str:
    """Convert raw CPE string to human-readable name.

    cpe:/o:debian:debian_linux      → Debian Linux
    cpe:2.3:o:debian:debian_linux   → Debian Linux
    cpe:/a:openbsd:openssh:9.2p1    → OpenSSH 9.2p1
    """
    if not value:
        return ""
    # Handle both CPE 2.2 (cpe:/) and CPE 2.3 (cpe:2.3:) formats
    if value.startswith("cpe:2.3:"):
        parts = value[8:].split(":")
    elif value.startswith("cpe:/"):
        parts = value[5:].split(":")
    else:
        return value

    if len(parts) < 2:
        return value
    if len(parts) == 2:
        return parts[1].replace("_", " ").title()
    product = parts[2].replace("_", " ").title()
    version = parts[3] if len(parts) > 3 else ""
    return f"{product} {version}".strip()


def cpe_os(value: str) -> Markup:
    """Extract and format OS entries (cpe:/o:... or cpe:2.3:o:...) from a
    comma-separated CPE string."""
    if not value:
        return Markup("—")
    items = [
        parse_cpe(c.strip())
        for c in value.split(",")
        if c.strip().startswith(("cpe:/o:", "cpe:2.3:o:"))
    ]
    return Markup(escape(", ".join(items))) if items else Markup("—")


def cpe_services(value: str) -> Markup:
    """Extract and format application entries (cpe:/a:... or cpe:2.3:a:...) from
    a comma-separated CPE string."""
    if not value:
        return Markup("—")
    items = [
        parse_cpe(c.strip())
        for c in value.split(",")
        if c.strip().startswith(("cpe:/a:", "cpe:2.3:a:"))
    ]
    return Markup(escape(", ".join(items))) if items else Markup("—")


def fmtduration(seconds) -> str:
    """A span of time, at the precision the log can actually support.

    nginx logs $time_iso8601, which resolves to the second, so "0 s" means
    "inside one second" and not "instant". Above that the unit steps up rather
    than the number growing: a monitoring client polling every ten minutes never
    opens a gap wide enough to end its session, so a single session legitimately
    spans the whole retention window — 7 776 000 s is a correct answer nobody
    can read, and "90 d" is the same answer.
    """
    if seconds is None:
        return "—"
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return "—"
    if total < 120:
        return f"{total} s"
    if total < 7200:
        return f"{total // 60} min"
    if total < 172800:
        return f"{total // 3600} h"
    return f"{total // 86400} d"


def path_tip(path: str) -> tuple[str, str]:
    """The (what, how) pair for a known scanner or probe path, or an empty pair.

    The entries were single strings joined by an em dash — "WordPress admin panel
    — automated scan for unprotected installations" — which is the What/How pair
    written out by hand. Splitting them at the dash is a separation, not a
    rewrite: the left half names the path, the right half says why anyone asks
    for it.
    """
    lower = path.lower()
    # Sort by key length descending so more-specific keys (e.g. "wp-admin") win over
    # shorter substrings (e.g. "admin") when both would match.
    for key in sorted(_PATH_TIPS, key=len, reverse=True):
        if key in lower:
            return _PATH_TIPS[key]
    return ("", "")


def inline_code(text: str) -> Markup:
    """Prose with `backticked` spans turned into <code>, everything else escaped.

    src/families.py explains config snippets in running text — a deny rule, a
    curl command — and a backtick rendered as a backtick reads as markdown that
    failed to render. This is not a markdown parser and must not become one:
    one construct, applied to constants this repository owns.

    Escaping happens per segment rather than on the result, so a family whose
    text contains a literal < is still safe inside the <code> as well as
    outside it.
    """
    return Markup(
        "".join(
            f"<code>{escape(part)}</code>" if i % 2 else str(escape(part))
            for i, part in enumerate(text.split("`"))
        )
    )


# ── Registration ─────────────────────────────────────────────────────────────


def register_filters(env: jinja2.Environment) -> None:
    """Register all dashboard Jinja2 filters on the given environment."""
    env.filters["fmtdate"] = fmtdate
    env.filters["fmtbytes"] = fmtbytes
    env.filters["fmtresptime"] = fmtresptime
    env.filters["fmtnum"] = fmtnum
    env.filters["fmtpct"] = fmtpct
    env.filters["fmtpoints"] = fmtpoints
    env.filters["primarylang"] = primarylang
    env.filters["badge_list"] = badge_list
    env.filters["csv_items"] = csv_items
    env.filters["cpe_os"] = cpe_os
    env.filters["cpe_services"] = cpe_services
    env.filters["parse_cpe"] = parse_cpe
    env.filters["fmtduration"] = fmtduration
    env.filters["path_tip"] = path_tip
    env.filters["inline_code"] = inline_code
