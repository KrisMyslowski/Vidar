"""The Overview's numbers: the tiles, the top-N lists and the findings list."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

from ..classifier import _scanner_path_match
from ._shared import (
    _EXCLUDED_BROWSERS,
    _EXCLUDED_OSES,
    _VISITOR_GROUP_CASE,
    _VISITOR_GROUP_ORDER,
    _date_conditions,
    seen_in_window,
    visit_window,
)

# How many entries each Overview "Top" list carries. The block is a tabbed
# single panel, so depth costs no vertical space until a tab is opened.
_TOP_N = 10


def _aggregate_referrer_domains(rows: list, limit: int = _TOP_N) -> list[dict]:
    """Aggregate raw (referer, count) rows into domain-level counts."""
    counts: dict[str, int] = {}
    for r in rows:
        try:
            domain = urlparse(r["referer"]).netloc or r["referer"]
        except Exception:
            domain = r["referer"]
        counts[domain] = counts.get(domain, 0) + r["count"]
    return [
        {"domain": d, "count": c}
        for d, c in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    ]


def get_stats(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> dict:
    """Dashboard overview statistics: totals, top countries/IPs/pages.

    Every figure is scoped to the [since, until] window — the Overview header
    names a range and each tile below it has to answer for that range. The
    per-IP figures (country total, class breakdown) count IPs seen in the
    window, via seen_in_window().
    """
    # Date bounds are string-compared against nginx $time_iso8601 timestamps,
    # which must therefore be UTC. True for the default container (no TZ set);
    # a non-UTC TZ on the host would skew the window by the local offset.
    win, wp = visit_window(since, until)
    # Same window against the aliased column, for the two queries that join.
    # Taken as a pair rather than reusing `wp` next to a differently-built
    # fragment: the params happen to match today, and that is not a guarantee.
    vwin, vwp = visit_window(since, until, "v.timestamp")
    seen, sp = seen_in_window("ip_intel.ip", since, until)
    seen_where = f" WHERE {seen}" if seen else ""

    total = conn.execute(f"SELECT COUNT(*) FROM visits WHERE 1=1{win}", wp).fetchone()[0]
    unique = conn.execute(f"SELECT COUNT(DISTINCT ip) FROM visits WHERE 1=1{win}", wp).fetchone()[
        0
    ]

    top_countries = [
        dict(r)
        for r in conn.execute(
            f"""SELECT i.country, i.country_code, COUNT(*) as count
               FROM visits v JOIN ip_intel i ON v.ip = i.ip
               WHERE 1=1{vwin}
               GROUP BY i.country_code ORDER BY count DESC LIMIT {_TOP_N}""",
            vwp,
        ).fetchall()
    ]
    total_countries = conn.execute(
        f"""SELECT COUNT(DISTINCT country_code) FROM ip_intel
            WHERE country_code != ''{f' AND {seen}' if seen else ''}""",
        sp,
    ).fetchone()[0]
    top_ips = [
        dict(r)
        for r in conn.execute(
            f"""SELECT v.ip, COUNT(*) as count, i.visitor_class, i.country_code
               FROM visits v
               LEFT JOIN ip_intel i ON v.ip = i.ip
               WHERE 1=1{vwin}
               GROUP BY v.ip ORDER BY count DESC LIMIT {_TOP_N}""",
            vwp,
        ).fetchall()
    ]
    top_pages = [
        dict(r)
        for r in conn.execute(
            f"""SELECT path, COUNT(*) as count FROM visits
               WHERE path != ''{win}
               GROUP BY path ORDER BY count DESC LIMIT {_TOP_N}""",
            wp,
        ).fetchall()
    ]

    raw_refs = conn.execute(
        f"""SELECT referer, COUNT(*) as count FROM visits
           WHERE referer != '' AND referer != '-'{win}
           GROUP BY referer ORDER BY count DESC LIMIT 200""",
        wp,
    ).fetchall()
    top_referrers = _aggregate_referrer_domains(raw_refs)

    error_count = conn.execute(
        f"SELECT COUNT(*) FROM visits WHERE status >= 400{win}", wp
    ).fetchone()[0]
    error_rate = round(error_count / total * 100, 1) if total else 0.0

    avg_response_time = (
        conn.execute(
            f"SELECT AVG(request_time) FROM visits WHERE request_time > 0{win}", wp
        ).fetchone()[0]
        or 0.0
    )
    avg_response_time = round(avg_response_time, 3)

    total_bandwidth = (
        conn.execute(f"SELECT SUM(bytes_sent) FROM visits WHERE 1=1{win}", wp).fetchone()[0] or 0
    )

    https_count = conn.execute(
        f"""SELECT COUNT(*) FROM visits
            WHERE ssl_protocol IS NOT NULL AND ssl_protocol != ''{win}""",
        wp,
    ).fetchone()[0]
    https_rate = round(https_count / total * 100, 1) if total else 0.0

    # "Exactly one request" is a property of the window, not of all time: an IP
    # that came back next month did not bounce *this* month.
    bounce_count = conn.execute(
        f"""SELECT COUNT(*) FROM (
                SELECT ip FROM visits WHERE 1=1{win} GROUP BY ip HAVING COUNT(*) = 1
            )""",
        wp,
    ).fetchone()[0]
    bounce_rate = round(bounce_count / unique * 100, 1) if unique else 0.0

    excluded_browsers = tuple(_EXCLUDED_BROWSERS)
    top_browsers = [
        dict(r)
        for r in conn.execute(
            f"SELECT browser, COUNT(*) as count FROM visits"
            f" WHERE browser NOT IN ({','.join('?' * len(excluded_browsers))}){win}"
            f" GROUP BY browser ORDER BY count DESC LIMIT {_TOP_N}",
            (*excluded_browsers, *wp),
        ).fetchall()
    ]

    excluded_oses = tuple(_EXCLUDED_OSES)
    top_oses = [
        dict(r)
        for r in conn.execute(
            f"SELECT os, COUNT(*) as count FROM visits"
            f" WHERE os NOT IN ({','.join('?' * len(excluded_oses))}){win}"
            f" GROUP BY os ORDER BY count DESC LIMIT {_TOP_N}",
            (*excluded_oses, *wp),
        ).fetchall()
    ]

    breakdown_rows = conn.execute(
        f"""SELECT {_VISITOR_GROUP_CASE} AS grp,
               COUNT(*) AS ip_count
           FROM ip_intel{seen_where}
           GROUP BY grp
           ORDER BY {_VISITOR_GROUP_ORDER}""",
        sp,
    ).fetchall()
    visitor_class_breakdown = [dict(r) for r in breakdown_rows]

    return {
        "total_visits": total,
        "unique_ips": unique,
        "total_countries": total_countries,
        "top_countries": top_countries,
        "top_ips": top_ips,
        "top_pages": top_pages,
        "top_referrers": top_referrers,
        "top_browsers": top_browsers,
        "top_oses": top_oses,
        "error_rate": error_rate,
        "bounce_rate": bounce_rate,
        "https_rate": https_rate,
        "avg_response_time": avg_response_time,
        "total_bandwidth": total_bandwidth,
        "visitor_class_breakdown": visitor_class_breakdown,
    }


def get_attention_items(conn: sqlite3.Connection) -> list[dict]:
    """Things worth looking at right now, for the Overview's "Needs attention".

    Each item is one finding with a link to the view that shows it in full. Items
    only appear when they actually have something to report, so the list (and the
    nav counter derived from it) is never padded.

    Note on "new threats": ip_intel has no first-classified timestamp, so "new"
    means *first seen* today — MIN(timestamp) over that IP's visits.
    """
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%dT00:00:00")
    six_h = (now - timedelta(hours=6)).isoformat()
    d1 = (now - timedelta(days=1)).isoformat()
    d7 = (now - timedelta(days=7)).isoformat()
    items: list[dict] = []

    # 1. The IP nginx is currently throttling hardest.
    row = conn.execute(
        """SELECT ip, COUNT(*) AS events,
                  SUM(CASE WHEN limit_req_status = 'REJECTED' THEN 1 ELSE 0 END) AS rejected
           FROM visits
           WHERE limit_req_status IN ('DELAYED', 'REJECTED') AND timestamp >= ?
           GROUP BY ip ORDER BY events DESC LIMIT 1""",
        (six_h,),
    ).fetchone()
    if row and row["events"]:
        # The finding triggers on rate-limit *events* (DELAYED or REJECTED), so
        # it must report those — naming only the rejected count produced
        # "IP — 0 rejected in the last 6 h" whenever nginx merely throttled.
        rejected = row["rejected"] or 0
        detail = f" ({rejected:,} rejected)" if rejected else ""
        items.append(
            {
                "tag": "Rate limit",
                "text": f"{row['ip']} — {row['events']:,} rate-limited in 6 h{detail}",
                "value": row["events"],
                "signal": "threats",
                "href": f"/visitors/{row['ip']}",
            }
        )

    # 2. Threat IPs whose first request ever arrived today.
    row = conn.execute(
        """SELECT COUNT(*) FROM (
               SELECT v.ip FROM visits v JOIN ip_intel i ON v.ip = i.ip
               WHERE i.visitor_class LIKE 'threats/%'
               GROUP BY v.ip HAVING MIN(v.timestamp) >= ?
           )""",
        (today,),
    ).fetchone()
    if row and row[0]:
        items.append(
            {
                "tag": "New",
                "text": (
                    f"{row[0]:,} threat {'IP' if row[0] == 1 else 'IPs'} "
                    "seen here for the first time today"
                ),
                "value": row[0],
                "signal": "threats",
                "href": "/visitors?class=threats",
            }
        )

    # 3. The CVE present on the most visiting hosts.
    row = conn.execute(
        """SELECT vuln, COUNT(DISTINCT ip) AS hosts FROM ip_intel_vulns
           GROUP BY vuln ORDER BY hosts DESC, vuln LIMIT 1"""
    ).fetchone()
    if row and row["hosts"]:
        items.append(
            {
                "tag": "CVE",
                "text": (
                    f"{row['vuln']} on {row['hosts']:,} exposed "
                    f"{'host' if row['hosts'] == 1 else 'hosts'}"
                ),
                "value": row["hosts"],
                "signal": "dnsbl",
                "href": f"/exposure?vuln={quote(row['vuln'])}",
            }
        )

    # 4. Tor traffic today against its own 7-day baseline.
    row = conn.execute(
        """SELECT SUM(CASE WHEN v.timestamp >= ? THEN 1 ELSE 0 END) AS today,
                  SUM(CASE WHEN v.timestamp >= ? AND v.timestamp < ? THEN 1 ELSE 0 END) AS prev
           FROM visits v JOIN ip_intel i ON v.ip = i.ip
           WHERE i.is_tor = 1""",
        (today, d7, today),
    ).fetchone()
    if row and (row["today"] or 0) > 0 and (row["prev"] or 0) > 0:
        daily_avg = row["prev"] / 7
        factor = row["today"] / daily_avg if daily_avg else 0
        if factor >= 2:
            items.append(
                {
                    "tag": "Tor",
                    "text": f"Tor traffic {factor:.0f}× above the 7-day average",
                    "value": row["today"],
                    "signal": "tor",
                    "href": "/visitors?signal=is_tor",
                }
            )

    # 5. The probe path the most distinct IPs are asking for *right now*.
    # Bounded to the last day: a finding is a snapshot, not a 90-day total. The
    # date bound also lets idx_visits_timestamp carry the query — the LIKE chain
    # below can never use an index, so without it this is a full table scan.
    row = conn.execute(
        f"""SELECT path, COUNT(DISTINCT ip) AS ips, COUNT(*) AS hits
            FROM visits WHERE timestamp >= ? AND ({_scanner_path_match('path')})
            GROUP BY path ORDER BY ips DESC, hits DESC LIMIT 1""",
        (d1,),
    ).fetchone()
    if row and row["ips"]:
        items.append(
            {
                "tag": "Probe",
                "text": (
                    f"{row['path']} requested by {row['ips']:,} distinct "
                    f"{'IP' if row['ips'] == 1 else 'IPs'} today"
                ),
                "value": row["hits"],
                "signal": "hosting",
                "href": f"/visitors?group=path&q={quote(row['path'])}",
            }
        )

    return items


def get_visitor_ip_counts(
    conn: sqlite3.Connection,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, int]:
    """Flat dict mapping both full class strings and group prefixes to unique IP counts.

    e.g. {'humans/browser-direct': 12, 'humans': 67, 'bots': 3320, ...}
    Used by the filter bar to show counts on group headers and subclass chips.

    Counted over `visits`, not over `ip_intel`: the chips sit next to a table
    that counts IPs seen in the chosen window, and a plain group-by on ip_intel
    answered a different question — every IP ever classified, whatever the range
    said. The chip read as a filtered number because everything around it was
    one, so 274 threat IPs stood next to a day with 11,629 threat requests.

    LEFT JOIN, so an IP that has visits but no intel yet still counts, folded
    into `unknown` exactly as _apply_class_filter folds it.
    """
    conditions, params = _date_conditions(date_from, date_to, "v.timestamp")
    rows = conn.execute(
        f"""SELECT i.visitor_class AS visitor_class, COUNT(DISTINCT v.ip) AS cnt
            FROM visits v
            LEFT JOIN ip_intel i ON i.ip = v.ip
            WHERE {' AND '.join(['1=1', *conditions])}
            GROUP BY i.visitor_class""",
        params,
    ).fetchall()
    counts: dict[str, int] = {}
    group_totals: dict[str, int] = {}
    for r in rows:
        cls, cnt = r["visitor_class"], r["cnt"]
        counts[cls] = cnt
        # An unenriched or failed row carries '' (or NULL). _apply_class_filter folds
        # those into `unknown`, so the counter has to as well — otherwise the Unknown
        # chip shows fewer IPs than clicking it lists, while `all` still counts them.
        grp = cls.split("/")[0] if cls and "/" in cls else (cls or "unknown")
        group_totals[grp] = group_totals.get(grp, 0) + cnt
    counts.update(group_totals)
    counts["all"] = sum(group_totals.values())
    return counts
