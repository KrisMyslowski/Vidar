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
    """Convert ISO timestamp to dd.mm.yy HH:MM."""
    if not value:
        return ""
    if value == "—":
        return "—"
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime("%d.%m.%y %H:%M")
    except (ValueError, AttributeError):
        return value


def fmtbytes(value) -> str:
    """Convert bytes to human-readable format."""
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


# ── Registration ─────────────────────────────────────────────────────────────


def register_filters(env: jinja2.Environment) -> None:
    """Register all dashboard Jinja2 filters on the given environment."""
    env.filters["fmtdate"] = fmtdate
    env.filters["fmtbytes"] = fmtbytes
    env.filters["fmtresptime"] = fmtresptime
    env.filters["fmtnum"] = fmtnum
    env.filters["primarylang"] = primarylang
    env.filters["badge_list"] = badge_list
    env.filters["csv_items"] = csv_items
    env.filters["cpe_os"] = cpe_os
    env.filters["cpe_services"] = cpe_services
    env.filters["parse_cpe"] = parse_cpe
    env.filters["path_tip"] = path_tip
