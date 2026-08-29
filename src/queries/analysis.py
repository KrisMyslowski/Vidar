"""Everything a chart or a facet reads: geo markers, timelines, the heatmap,
the identity x signal matrix, and the Shodan exposure surface."""

from __future__ import annotations

import sqlite3

from ..taxonomy import CLEAN_SIGNAL_COLUMNS, GROUPS_WITH_UNKNOWN, SIGNALS
from ._shared import (
    _THREAT_FLAGS_SQL,
    _VISITOR_GROUP_CASE,
    _VISITOR_GROUP_ORDER,
    _VISITOR_GROUP_SUMS,
    SHODAN_CHILD_COLUMNS,
    SHODAN_CHILD_TABLES,
    SHODAN_CHILDREN,
    _apply_class_filter,
    _apply_date_filter,
    _apply_signal_filter,
    _apply_visitor_search,
    _date_conditions,
    _date_where,
    _shodan_agg_select,
    _signal_condition,
    _status_band_sums,
    seen_in_window,
    visit_window,
)


def get_geo_data(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    country: str | None = None,
    min_visits: int = 0,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
) -> tuple[list[dict], dict]:
    """Return (markers, geo_stats) for the /geo route.

    markers: every enriched IP with lat/lon, all intel columns,
             visit_count, and visitor_class.
    geo_stats keys: total_ips, total_countries, proxy_count, tor_count,
                    hosting_count, dnsbl_count, clean_count, mobile_count,
                    and per-group counts (humans_count, bots_count, …).
    """
    marker_query = """
        SELECT i.ip, i.lat, i.lon, i.country, i.country_code, i.city,
               i.isp, i.asn, i.is_proxy, i.is_hosting, i.is_mobile,
               i.is_tor, i.dnsbl_listed, i.visitor_class, COUNT(v.id) as visit_count,
               EXISTS (SELECT 1 FROM ip_intel_tags t WHERE t.ip = i.ip) AS has_tags
        FROM ip_intel i
        JOIN visits v ON v.ip = i.ip
        WHERE i.lat != 0 AND i.lon != 0"""
    marker_params: list = []
    marker_query, marker_params = _apply_class_filter(marker_query, marker_params, class_filter)
    marker_query, marker_params = _apply_signal_filter(marker_query, marker_params, signal_filter)
    if country:
        marker_query += " AND i.country_code = ?"
        marker_params.append(country)
    marker_query, marker_params = _apply_date_filter(
        marker_query, marker_params, date_from, date_to
    )
    # Same search the table applies, so panning the map shows the same selection.
    marker_query, marker_params = _apply_visitor_search(marker_query, marker_params, q)
    marker_query += " GROUP BY i.ip"
    if min_visits > 0:
        marker_query += f" HAVING COUNT(v.id) >= {int(min_visits)}"
    rows = conn.execute(marker_query, marker_params).fetchall()
    markers = [dict(r) for r in rows]

    geo_stats = {
        "total_ips": len(markers),
        "total_countries": len({m["country_code"] for m in markers if m["country_code"]}),
        # One count per signal that is a column on the marker row. Counted in
        # Python rather than SQL because the markers are already in memory.
        **{
            f"{s.alias}_count": sum(1 for m in markers if m[s.column]) for s in SIGNALS if s.column
        },
        # Same definition as _no_signals_sql(): Shodan tags count against clean.
        "clean_count": sum(
            1 for m in markers if not any(m[c] for c in CLEAN_SIGNAL_COLUMNS) and not m["has_tags"]
        ),
    }
    grp_counts: dict[str, int] = {}
    for m in markers:
        grp = (m.get("visitor_class") or "unknown").split("/")[0] or "unknown"
        grp_counts[grp] = grp_counts.get(grp, 0) + 1
    # A group the taxonomy does not know (a class left over from an older
    # classifier version) falls out here rather than inventing a key: the map
    # legend renders exactly these five.
    geo_stats.update({f"{g}_count": grp_counts.get(g, 0) for g in GROUPS_WITH_UNKNOWN})
    return markers, geo_stats


# How many characters of an ISO timestamp identify one bucket:
# "2026-08-05" (day) vs "2026-08-05T14" (hour).
_BUCKET_WIDTH = {"day": 10, "hour": 13}


def get_activity_timeline(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    bucket: str = "day",
    q: str | None = None,
) -> list[dict]:
    """Return [{day, total, humans, bots, automated, threats, unknown}] for the activity chart.

    class_filter/signal_filter narrow it the same way they narrow the visitor
    tables, so /visitors?view=timeline shows the selection the other views show.

    bucket="hour" cuts the timestamp one level finer; the chart asks for it once
    a reader has zoomed in far enough that days are single points. The key stays
    `day` either way — it is the bucket's label, and every caller reads it as
    one. Anything but a known bucket falls back to days rather than reaching the
    SQL, which is why the width comes from a lookup and not from the argument.
    """
    width = _BUCKET_WIDTH.get(bucket, _BUCKET_WIDTH["day"])
    conditions, params = _date_conditions(since, until, column="v.timestamp")
    query = "WHERE 1=1" + ("".join(f" AND {c}" for c in conditions))
    query, params = _apply_class_filter(query, params, class_filter)
    query, params = _apply_signal_filter(query, params, signal_filter)
    # Search selects visitors, so the chart shows those visitors' activity over
    # time — the same selection the table and the map show.
    query, params = _apply_visitor_search(query, params, q)
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT substr(v.timestamp,1,{width}) as day,
                       COUNT(*) as total,
                       {_VISITOR_GROUP_SUMS}
               FROM visits v LEFT JOIN ip_intel i ON v.ip = i.ip
               {query}
               GROUP BY day ORDER BY day""",
            params,
        ).fetchall()
    ]


def get_hourly_heatmap(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    q: str | None = None,
) -> list[dict]:
    """Visit counts per (weekday, hour) cell for the traffic-rhythm heatmap.

    Returns [{dow, hr, total, humans, bots, automated, threats, unknown}] for
    non-empty cells — the per-group split drives the heatmap's own group toggle,
    mirroring the activity chart's series. dow follows SQLite strftime ('%w'):
    0 = Sunday … 6 = Saturday. Timestamps are UTC.

    Takes the same class/signal/search filters as get_activity_timeline, and for
    the same reason: both sit on /visitors?view=timeline, where every other view
    answers for the current selection. A heatmap that stayed all-time beside a
    filtered chart would be two answers to one question, and the reader has no
    way to tell which one is which.
    """
    conditions, params = _date_conditions(since, until, column="v.timestamp")
    query = "WHERE 1=1" + ("".join(f" AND {c}" for c in conditions))
    query, params = _apply_class_filter(query, params, class_filter)
    query, params = _apply_signal_filter(query, params, signal_filter)
    query, params = _apply_visitor_search(query, params, q)
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT CAST(strftime('%w', v.timestamp) AS INTEGER) AS dow,
                       CAST(strftime('%H', v.timestamp) AS INTEGER) AS hr,
                       COUNT(*) AS total,
                       {_VISITOR_GROUP_SUMS}
               FROM visits v LEFT JOIN ip_intel i ON v.ip = i.ip
               {query}
               GROUP BY dow, hr""",
            params,
        ).fetchall()
    ]


def get_rate_limit_timeline(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Rate-limit events per day, split into rejected and delayed.

    Feeds the day-column chart in the Analysis Rate Limiting block; the same
    shape as get_activity_timeline so both use the stacked_bars block.
    """
    where, params = _date_where(since, until, column="timestamp")
    and_ = " AND " if where else " WHERE "
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT substr(timestamp,1,10) AS day,
                       COUNT(*) AS total,
                       SUM(CASE WHEN limit_req_status = 'REJECTED' THEN 1 ELSE 0 END) AS rejected,
                       SUM(CASE WHEN limit_req_status = 'DELAYED'  THEN 1 ELSE 0 END) AS delayed
                FROM visits {where}{and_}limit_req_status IN ('DELAYED', 'REJECTED')
                GROUP BY day ORDER BY day""",
            params,
        ).fetchall()
    ]


def get_status_timeline(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Per-day status-class counts [{day, s2xx, s3xx, s4xx, s5xx}] for the
    stacked status-mix chart on /visitors/analysis."""
    where, params = _date_where(since, until)
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT substr(timestamp, 1, 10) AS day,
                       {_status_band_sums()}
               FROM visits {where}
               GROUP BY day ORDER BY day""",
            params,
        ).fetchall()
    ]


def get_daily_kpis(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Per-day visits/errors/bytes for the overview KPI sparklines, oldest first.

    Scoped to the window the page is showing, so the sparkline under a tile
    covers the same days as the number above it. The route calls this a second
    time for the preceding window of equal length to build the delta.
    """
    win, params = visit_window(since, until)
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT substr(timestamp, 1, 10) AS day,
                      COUNT(*) AS visits,
                      SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors,
                      COALESCE(SUM(bytes_sent), 0) AS bytes
               FROM visits WHERE 1=1{win}
               GROUP BY day ORDER BY day""",
            params,
        ).fetchall()
    ]


def get_identity_signal_matrix(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Identity group x network/reputation signal counts — the 4.1 two-dimension view.

    One row per taxonomy group (canonical order) with the IP count carrying each signal,
    plus mobile / clean (no-signal) counts and the group total. Cells deep-link to
    /visitors?class=<group>&signal=<signal>; column sums reproduce the overall signal
    counts, so nothing is lost versus the old standalone signal cards.

    Counts the IPs seen in the window (seen_in_window); the cells link into
    /visitors, and a cell that offers more IPs than the list behind it is worse
    than no cell.
    """
    seen, params = seen_in_window("ip_intel.ip", since, until)
    where = f" WHERE {seen}" if seen else ""
    # Every signal the registry knows — the matrix has one column per signal.
    signal_cols = ",\n                       ".join(
        f"COALESCE(SUM(CASE WHEN {_signal_condition(s, '', 'ip_intel.ip')}"
        f" THEN 1 ELSE 0 END), 0) AS {s.alias}"
        for s in SIGNALS
    )
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT {_VISITOR_GROUP_CASE} AS grp,
                       {signal_cols},
                       COUNT(*)                       AS total
                FROM ip_intel{where}
                GROUP BY grp
                ORDER BY {_VISITOR_GROUP_ORDER}""",
            params,
        ).fetchall()
    ]


def get_analysis_data(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> dict:
    """Return all analysis data for the /visitors/analysis route.

    since/until scope every visits-based widget. The enriched-IP total (counts)
    stays all-time: ip_intel is current enrichment state, not per-visit history."""
    counts = dict(conn.execute("SELECT COUNT(*) as total FROM ip_intel").fetchone())

    d_conds, d_params = _date_conditions(since, until)
    d_and = "".join(f" AND {c}" for c in d_conds)
    d_where, _ = _date_where(since, until)

    status_dist = dict(
        conn.execute(f"SELECT {_status_band_sums()} FROM visits {d_where}", d_params).fetchone()
    )

    rl_row = conn.execute(
        f"""
        SELECT COUNT(*) as rl_total,
               SUM(CASE WHEN DATE(timestamp) = DATE('now') THEN 1 ELSE 0 END) as rl_today,
               SUM(CASE WHEN limit_req_status = 'REJECTED' THEN 1 ELSE 0 END) as rl_rejected,
               SUM(CASE WHEN limit_req_status = 'DELAYED'  THEN 1 ELSE 0 END) as rl_delayed
        FROM visits WHERE limit_req_status IN ('DELAYED', 'REJECTED'){d_and}
    """,
        d_params,
    ).fetchone()
    rl_stats = (
        dict(rl_row)
        if rl_row
        else {"rl_total": 0, "rl_today": 0, "rl_rejected": 0, "rl_delayed": 0}
    )

    rl_top_ips = [
        dict(r)
        for r in conn.execute(
            f"""
        SELECT ip, COUNT(*) as rl_count,
               SUM(CASE WHEN limit_req_status = 'REJECTED' THEN 1 ELSE 0 END) as rejected
        FROM visits WHERE limit_req_status IN ('DELAYED', 'REJECTED'){d_and}
        GROUP BY ip ORDER BY rl_count DESC LIMIT 10
    """,
            d_params,
        ).fetchall()
    ]

    bs_row = conn.execute(
        f"""
        SELECT COUNT(*) as total_visits,
               SUM(CASE WHEN sec_fetch_dest = '' THEN 1 ELSE 0 END) as no_sec_fetch,
               SUM(CASE WHEN device = 'Bot' THEN 1 ELSE 0 END) as bot_device_count,
               COUNT(DISTINCT CASE WHEN device = 'Bot' THEN ip END) as bot_ips
        FROM visits {d_where}
    """,
        d_params,
    ).fetchone()
    bot_signals = (
        dict(bs_row)
        if bs_row
        else {"total_visits": 0, "no_sec_fetch": 0, "bot_device_count": 0, "bot_ips": 0}
    )

    status_timeline = get_status_timeline(conn, since=since, until=until)

    # HTTP versions + unusual methods are rendered as charts (low cardinality) — no paging.
    http_version_dist = get_http_version_dist(conn, since=since, until=until)
    unusual_methods = get_unusual_methods(conn, since=since, until=until)

    return {
        "counts": counts,
        "status_dist": status_dist,
        "rl_stats": rl_stats,
        "rl_top_ips": rl_top_ips,
        "bot_signals": bot_signals,
        "status_timeline": status_timeline,
        "http_version_dist": http_version_dist,
        "unusual_methods": unusual_methods,
    }


def get_http_version_dist(
    conn: sqlite3.Connection, since: str | None = None, until: str | None = None
) -> list[dict]:
    """HTTP protocol versions seen in flagged traffic (low cardinality — rendered as a chart)."""
    d_conds, d_params = _date_conditions(since, until, column="v.timestamp")
    d_and = "".join(f" AND {c}" for c in d_conds)
    return [
        dict(r)
        for r in conn.execute(
            f"""
        SELECT http_version, COUNT(*) as count
        FROM visits v JOIN ip_intel i ON v.ip=i.ip
        WHERE ({_THREAT_FLAGS_SQL})
          AND http_version != ''{d_and}
        GROUP BY http_version ORDER BY count DESC
    """,
            d_params,
        ).fetchall()
    ]


# "Has any Shodan exposure" — checked against the normalized child tables (4.3).
# Each EXISTS is its own scope, so they can all use the same alias; a per-table
# letter only looked meaningful.
_SHODAN_HOST_FILTER = " OR ".join(
    f"EXISTS (SELECT 1 FROM {table} x WHERE x.ip = ip_intel.ip)"
    for table, _col, _name in SHODAN_CHILDREN
)


def _shodan_value_filters(
    port: int | None,
    vuln: str | None,
    tag: str | None,
    ip_ref: str = "ip_intel.ip",
    since: str | None = None,
    until: str | None = None,
) -> tuple[list[str], list]:
    """Build AND-EXISTS clauses for optional per-value Shodan filters (4.3).

    ip_ref is the column the EXISTS clauses correlate against, so the same
    filters apply to the host table (ip_intel.ip) and to the facet counts
    (ip_intel_<child>.ip) — facets and table then share one filter state.

    The date window rides along here for the same reason: one place, and the
    host table, its count and all three facets are scoped together. Without a
    window it adds nothing, so an unwindowed call is byte-for-byte the query it
    always was — which matters, because an enriched IP whose visits were
    archived away must not vanish from an unscoped view.
    """
    clauses: list[str] = []
    params: list = []
    seen, seen_params = seen_in_window(ip_ref, since, until)
    if seen:
        clauses.append(seen)
        params.extend(seen_params)
    if port is not None:
        clauses.append(
            f"EXISTS (SELECT 1 FROM ip_intel_ports p WHERE p.ip = {ip_ref} AND p.port = ?)"
        )
        params.append(port)
    if vuln:
        clauses.append(
            f"EXISTS (SELECT 1 FROM ip_intel_vulns v WHERE v.ip = {ip_ref} AND v.vuln = ?)"
        )
        params.append(vuln)
    if tag:
        clauses.append(
            f"EXISTS (SELECT 1 FROM ip_intel_tags t WHERE t.ip = {ip_ref} AND t.tag = ?)"
        )
        params.append(tag)
    return clauses, params


def get_shodan_hosts(
    conn: sqlite3.Connection,
    page: int = 1,
    limit: int = 25,
    port: int | None = None,
    vuln: str | None = None,
    tag: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """IPs with Shodan InternetDB exposure data, optionally filtered by port/vuln/tag.

    Vuln/tag hosts surface first. `visit_count` counts inside the window too —
    a row that is listed *because* it was seen in the range must not report a
    number from outside it.
    """
    offset = (page - 1) * limit
    extra, params = _shodan_value_filters(port, vuln, tag, since=since, until=until)
    where = " AND ".join([f"({_SHODAN_HOST_FILTER})", *extra])
    count_win, count_params = visit_window(since, until, "v.timestamp")
    return [
        dict(r)
        for r in conn.execute(
            f"""
        SELECT ip, country, country_code, fetched_at, visitor_class,
               (SELECT COUNT(*) FROM visits v
                WHERE v.ip = ip_intel.ip{count_win}) AS visit_count,
               {_shodan_agg_select("ip_intel.ip")}
        FROM ip_intel
        WHERE {where}
        ORDER BY EXISTS (SELECT 1 FROM ip_intel_vulns v WHERE v.ip = ip_intel.ip) DESC,
                 EXISTS (SELECT 1 FROM ip_intel_tags t WHERE t.ip = ip_intel.ip) DESC, ip
        LIMIT ? OFFSET ?
    """,
            # SELECT-clause parameters bind before the WHERE clause's.
            (*count_params, *params, limit, offset),
        ).fetchall()
    ]


def count_shodan_hosts(
    conn: sqlite3.Connection,
    port: int | None = None,
    vuln: str | None = None,
    tag: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> int:
    extra, params = _shodan_value_filters(port, vuln, tag, since=since, until=until)
    where = " AND ".join([f"({_SHODAN_HOST_FILTER})", *extra])
    row = conn.execute(f"SELECT COUNT(*) FROM ip_intel WHERE {where}", params).fetchone()
    return row[0] if row else 0


def _top_child(
    conn: sqlite3.Connection,
    table: str,
    col: str,
    limit: int,
    port: int | None = None,
    vuln: str | None = None,
    tag: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Top values of a Shodan child table by host count. table/col are literals only.

    The port/vuln/tag filters narrow the *hosts* the values are counted over, so
    the Exposure facets always describe the same host set the table shows.
    """
    # Both names go straight into the statement, so both are checked against the
    # registry rather than trusted — and the pairing is checked too, since a
    # valid table with another table's column would still build. Raised, not
    # asserted — `python -O` strips assertions (see _assert_identifier).
    if table not in SHODAN_CHILD_TABLES:
        raise ValueError(f"unknown child table: {table!r}")
    if SHODAN_CHILD_COLUMNS[table] != col:
        raise ValueError(f"{col!r} is not the value column of {table!r}")
    extra, params = _shodan_value_filters(
        port, vuln, tag, ip_ref=f"{table}.ip", since=since, until=until
    )
    where = f" WHERE {' AND '.join(extra)}" if extra else ""
    return [
        {"value": r[0], "ip_count": r[1]}
        for r in conn.execute(
            f"SELECT {col} AS value, COUNT(DISTINCT ip) AS ip_count "
            f"FROM {table}{where} GROUP BY {col} ORDER BY ip_count DESC, {col} LIMIT ?",
            (*params, limit),
        ).fetchall()
    ]


def get_top_ports(
    conn: sqlite3.Connection,
    limit: int = 15,
    port: int | None = None,
    vuln: str | None = None,
    tag: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Most common open ports among the hosts matching the active filter."""
    return _top_child(
        conn, "ip_intel_ports", "port", limit, port, vuln, tag, since=since, until=until
    )


def get_top_vulns(
    conn: sqlite3.Connection,
    limit: int = 15,
    port: int | None = None,
    vuln: str | None = None,
    tag: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Most common CVEs among the hosts matching the active filter."""
    return _top_child(
        conn, "ip_intel_vulns", "vuln", limit, port, vuln, tag, since=since, until=until
    )


def get_top_tags(
    conn: sqlite3.Connection,
    limit: int = 15,
    port: int | None = None,
    vuln: str | None = None,
    tag: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Most common Shodan tags among the hosts matching the active filter."""
    return _top_child(
        conn, "ip_intel_tags", "tag", limit, port, vuln, tag, since=since, until=until
    )


def get_unusual_methods(
    conn: sqlite3.Connection,
    limit: int = 12,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Non-standard HTTP methods (low cardinality — rendered as a chart)."""
    d_conds, d_params = _date_conditions(since, until)
    d_and = "".join(f" AND {c}" for c in d_conds)
    return [
        dict(r)
        for r in conn.execute(
            f"""
        SELECT method, COUNT(*) as count, COUNT(DISTINCT ip) as unique_ips
        FROM visits WHERE method NOT IN ('GET', 'HEAD', 'POST', 'OPTIONS') AND method != ''{d_and}
        GROUP BY method ORDER BY count DESC LIMIT ?
    """,
            [*d_params, limit],
        ).fetchall()
    ]
