"""The two entry points that need a database connection.

classify_ip() answers "what is this IP"; explain_classification() answers the
same question with the evidence behind it, for the visitor detail page. Both run
the same query and the same chain — they differ only in how much they report.
"""

from __future__ import annotations

import sqlite3

from ..config import settings
from .evidence_sql import _classify_params, _classify_sql
from .rules import _apply_priority_chain, _decisive_rule


def _js_prefixes() -> tuple[str, ...]:
    """The JS-fetch prefixes as the statement and its parameters both need them.

    Read once per classification and handed to both halves, so the statement's
    placeholder count and the parameter dict are built from the same value even
    if the setting changes between two classifications."""
    return tuple(settings.js_only_path_prefixes)


def explain_classification(conn: sqlite3.Connection, ip: str) -> list[dict]:
    """Ordered evidence for one IP's class: the deciding rule, then the context.

    The first entry is the rule that assigned the class; the rest are facts that
    describe the visitor without changing its identity (network origin, blocklist
    hits, exposure). Purely read-only — it never writes a class.
    """
    prefixes = _js_prefixes()
    row = conn.execute(_classify_sql(prefixes), _classify_params(ip, prefixes)).fetchone()
    if row is None:
        return []
    d = dict(row)
    _, text, source = _decisive_rule(d)
    evidence = [{"text": text, "source": source, "decisive": True}]

    total = d.get("total") or 0
    if (d.get("browser_navigate") or 0) == 0 and total:
        evidence.append(
            {
                "text": f"No Sec-Fetch navigation headers on any of {total:,} requests",
                "source": "headers",
                "decisive": False,
            }
        )
    redirects = total - (d.get("content_requests") or 0)
    if redirects > 0:
        evidence.append(
            {
                "text": f"{redirects:,} of those never got past the HTTP→HTTPS redirect",
                "source": "behaviour",
                "decisive": False,
            }
        )
    if d.get("dnsbl_listed"):
        sources = conn.execute("SELECT dnsbl_sources FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
        listed = (sources[0] if sources else "") or "blocklists"
        evidence.append({"text": f"Listed on {listed}", "source": "dnsbl", "decisive": False})
    if d.get("is_hosting"):
        evidence.append(
            {
                "text": "Hosting/cloud IP — a datacenter range, not a consumer connection",
                "source": "ip-api",
                "decisive": False,
            }
        )
    if d.get("is_proxy"):
        evidence.append({"text": "Flagged as proxy or VPN", "source": "ip-api", "decisive": False})
    if d.get("is_tor"):
        evidence.append({"text": "IP is a Tor exit node", "source": "tor-list", "decisive": False})
    if d.get("tags"):
        counts = conn.execute(
            "SELECT (SELECT COUNT(*) FROM ip_intel_ports WHERE ip = ?),"
            "       (SELECT COUNT(*) FROM ip_intel_vulns WHERE ip = ?)",
            (ip, ip),
        ).fetchone()
        ports, vulns = (counts[0] or 0, counts[1] or 0) if counts else (0, 0)
        parts = [f"Shodan tags: {d['tags']}"]
        if ports:
            parts.append(f"{ports} open port(s)")
        if vulns:
            parts.append(f"{vulns} known CVE(s)")
        evidence.append({"text": ", ".join(parts), "source": "shodan", "decisive": False})
    return evidence


def classify_ip(conn: sqlite3.Connection, ip: str) -> str:
    """Classify an IP into the visitor taxonomy. Returns a category/subcategory string."""
    prefixes = _js_prefixes()
    row = conn.execute(_classify_sql(prefixes), _classify_params(ip, prefixes)).fetchone()
    if row is None:
        return "unknown"
    return _apply_priority_chain(dict(row))
