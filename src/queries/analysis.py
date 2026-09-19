"""Everything a chart or a facet reads: geo markers, timelines, the heatmap,
the identity x signal matrix, and the Shodan exposure surface."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta
from fnmatch import fnmatch
from urllib.parse import unquote

from ..classifier.patterns import _CONVENTION_404_PATTERNS
from ..config import settings
from ..taxonomy import CLEAN_SIGNAL_COLUMNS, GROUPS_WITH_UNKNOWN, SIGNALS
from ._shared import (
    _THREAT_FLAGS_SQL,
    _VISITOR_GROUP_CASE,
    _VISITOR_GROUP_IP_COUNTS,
    _VISITOR_GROUP_ORDER,
    _VISITOR_GROUP_SUMS,
    SHODAN_CHILD_COLUMNS,
    SHODAN_CHILD_TABLES,
    SHODAN_CHILDREN,
    _apply_class_filter,
    _apply_date_filter,
    _apply_drill_filters,
    _apply_min_visits,
    _apply_seen_filter,
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
    seen: str | None = None,
) -> tuple[list[dict], dict]:
    """Return (markers, geo_stats) for the /geo route.

    markers: every enriched IP with lat/lon, all intel columns,
             visit_count, and visitor_class.
    geo_stats keys: total_ips, total_countries, proxy_count, tor_count,
                    hosting_count, dnsbl_count, clean_count, mobile_count,
                    and per-group counts (humans_count, bots_count, …).

    Two of those are load-bearing and the rest are not, which is worth writing
    down before somebody deletes the lot as dead. `total_ips` is the map
    header's denominator — the header counts the viewport, and zoomed in there
    is otherwise nothing saying what fraction of the selection that is.
    `clean_count` is not rendered at all: it anchors the cross-check that the
    map and the `clean` filter agree on what clean means, a definition that has
    disagreed with itself before over whether Shodan tags count against it.
    Everything else here is computed and unread — the map's selection panel
    counts the same things in the browser, scoped to the viewport, which is the
    more useful scoping.
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
    marker_query, marker_params = _apply_seen_filter(marker_query, marker_params, seen, date_from)
    # Same search the table applies, so panning the map shows the same selection.
    marker_query, marker_params = _apply_visitor_search(
        marker_query, marker_params, q, date_from, date_to
    )
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
    seen: str | None = None,
    drill: dict | None = None,
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
    return _timeline(
        conn,
        "COUNT(*) as total, " + _VISITOR_GROUP_SUMS,
        since,
        until,
        class_filter,
        signal_filter,
        bucket,
        q,
        seen,
        drill,
    )


def get_visitor_timeline(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    bucket: str = "day",
    q: str | None = None,
    seen: str | None = None,
    drill: dict | None = None,
) -> list[dict]:
    """The same shape over distinct addresses instead of requests.

    Identical columns to get_activity_timeline, so one chart renders both — and
    identical filters, so both answer for the selection the page has set. What
    changes is the question: how many *addresses* were here, rather than how
    many requests they made. Six thousand requests from three addresses is a
    scanner and three thousand addresses making two each is a crawl, and the
    request count alone cannot separate them.

    Under the New selection this is the count that reads directly: how many
    addresses arrived here for the first time, per bucket.

    **These do not add up across buckets.** An address that visits on two days
    is counted in both. The range's own distinct total is a different question,
    and the filter chips answer it — nothing here presents a sum.
    """
    return _timeline(
        conn,
        "COUNT(DISTINCT v.ip) as total, " + _VISITOR_GROUP_IP_COUNTS,
        since,
        until,
        class_filter,
        signal_filter,
        bucket,
        q,
        seen,
        drill,
    )


def _timeline(
    conn: sqlite3.Connection,
    select: str,
    since: str | None,
    until: str | None,
    class_filter: list[str] | None,
    signal_filter: list[str] | None,
    bucket: str,
    q: str | None,
    seen: str | None,
    drill: dict | None = None,
) -> list[dict]:
    """One bucketed timeline. `select` decides what is counted, nothing else.

    The two callers differ in one pivot and in nothing else. Kept as one body
    so a filter added to one cannot be missing from the other — which is how
    two charts on one page start describing two different selections.
    """
    width = _BUCKET_WIDTH.get(bucket, _BUCKET_WIDTH["day"])
    conditions, params = _date_conditions(since, until, column="v.timestamp")
    query = "WHERE 1=1" + ("".join(f" AND {c}" for c in conditions))
    query, params = _apply_class_filter(query, params, class_filter)
    query, params = _apply_signal_filter(query, params, signal_filter)
    # Search selects visitors, so the chart shows those visitors' activity over
    # time — the same selection the table and the map show.
    query, params = _apply_visitor_search(query, params, q, since, until)
    query, params = _apply_seen_filter(query, params, seen, since)
    # A copy: both charts are handed the same dict, and popping min_visits out
    # of the caller's would leave the second one unfiltered by it.
    drill = dict(drill or {})
    min_visits = drill.pop("min_visits", 0)
    query, params = _apply_drill_filters(query, params, **drill)
    # Last, and given the chain above: the bar has to be cleared by the traffic
    # the page is showing, not by everything the address ever did.
    query, params = _apply_min_visits(query, params, min_visits, query, list(params))
    rows = [
        dict(r)
        for r in conn.execute(
            f"""SELECT substr(v.timestamp,1,{width}) as day, {select}
               FROM visits v LEFT JOIN ip_intel i ON v.ip = i.ip
               {query}
               GROUP BY day ORDER BY day""",
            params,
        ).fetchall()
    ]
    return _fill_gaps(rows, bucket, since, until)


# A ceiling on generated buckets, so a pathological window cannot make this
# produce a list nothing can draw. `pick_bucket` keeps hours to a few days and
# days to whatever the retention window holds, so nothing real approaches it.
_MAX_BUCKETS = 5000


def _fill_gaps(rows: list[dict], bucket: str, since: str | None, until: str | None) -> list[dict]:
    """Put the silent buckets back, as explicit zeros.

    GROUP BY returns only buckets that have rows, and the chart positions points
    by index — so a day with no traffic was not drawn as zero, it was not drawn
    at all, and the two neighbours either side of it closed up. On the reference
    month, `class=humans` over 90 days returned six buckets spanning 27 days: an
    eleven-day silence and a one-day silence were given the same width, and a
    continuous line was drawn across three weeks in which no person visited.

    An axis that is not linear in time cannot answer the one question the chart
    exists for. Filling here rather than in the drawing code keeps it true for
    every caller, /api/activity included.

    An empty result stays empty. A window with no traffic at all is not a flat
    line at zero — it is nothing to draw, and the page says so in words.
    """
    if not rows:
        return rows
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    fmt = "%Y-%m-%dT%H" if bucket == "hour" else "%Y-%m-%d"

    def _parse(key: str) -> datetime:
        return datetime.strptime(key, fmt)

    # The window's own bounds where it has them, so a quiet start or end of the
    # range is visible as quiet rather than cropped away. `until` is inclusive
    # of its whole day, which is what the last hour is for.
    #
    # Nothing here parses a timestamp it has not been handed by SQLite's substr,
    # and a row whose timestamp is not a timestamp would take the whole page
    # down with a 500 rather than draw one bad point. The same trap emptied
    # every Overview finding once, from get_hourly_baseline. Unfilled is the
    # right failure: the chart draws what it drew before this function existed.
    try:
        first = _parse(since[:10] + ("T00" if bucket == "hour" else "")) if since else None
        last = _parse(until[:10] + ("T23" if bucket == "hour" else "")) if until else None
        start = min(_parse(rows[0]["day"]), first) if first else _parse(rows[0]["day"])
        end = max(_parse(rows[-1]["day"]), last) if last else _parse(rows[-1]["day"])
    except (ValueError, TypeError):
        return rows

    zero = {k: 0 for k in rows[0] if k != "day"}
    present = {r["day"]: r for r in rows}
    out: list[dict] = []
    moment = start
    while moment <= end and len(out) < _MAX_BUCKETS:
        key = moment.strftime(fmt)
        out.append(present.get(key) or {"day": key, **zero})
        moment += step
    return out


def get_hourly_heatmap(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    q: str | None = None,
    seen: str | None = None,
    drill: dict | None = None,
) -> list[dict]:
    """Visit counts per (weekday, hour) cell for the traffic-rhythm heatmap.

    Returns [{dow, hr, total}] for non-empty cells. dow follows SQLite strftime
    ('%w'): 0 = Sunday … 6 = Saturday. Timestamps are UTC.

    The total and nothing else. It carried a per-group split for the toggle
    above the grid, which was removed when the page's own group chips took that
    job — five SUM() aggregates per cell, computed on every render and read by
    nothing, and a docstring still describing the control they fed.

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
    query, params = _apply_visitor_search(query, params, q, since, until)
    query, params = _apply_seen_filter(query, params, seen, since)
    drill = dict(drill or {})
    min_visits = drill.pop("min_visits", 0)
    query, params = _apply_drill_filters(query, params, **drill)
    query, params = _apply_min_visits(query, params, min_visits, query, list(params))
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT CAST(strftime('%w', v.timestamp) AS INTEGER) AS dow,
                       CAST(strftime('%H', v.timestamp) AS INTEGER) AS hr,
                       COUNT(*) AS total
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


def count_intel_in_window(
    conn: sqlite3.Connection, since: str | None = None, until: str | None = None
) -> int:
    """Addresses with intel that were seen inside the window — the denominator of
    "X of Y IPs enriched", scoped like its numerator."""
    seen, params = seen_in_window("ip_intel.ip", since, until)
    row = conn.execute(
        f"SELECT COUNT(*) FROM ip_intel{f' WHERE {seen}' if seen else ''}", params
    ).fetchone()
    return row[0]


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


# ── What the site gave away ──────────────────────────────────────────────────
# The other direction. Everything above describes visitors; this describes what
# they got. Attackers name the operator's attack surface every day by asking for
# it, and the answers are already in `visits` — nothing new is collected.


# A visitor class whose members only fetch what is linked, listed in robots.txt
# or announced in a sitemap. If none of them ever retrieved a path successfully,
# that path is not part of the discoverable site — which is the whole signal.
#
# `automated/*` and `unknown` are deliberately not benign: a headless browser on
# a datacentre range proves nothing about a path being legitimate, and treating
# it as proof would hide exactly the findings this looks for.
# One benign address is not a pattern. Requiring two is what stops a single
# misclassification from hiding a leak: the address that fetched `//%2eDS_Store`
# was a headless browser under v5 and a referred human under v6, and with a veto
# of one the whole finding disappeared on reclassification — 31 addresses of
# evidence overruled by one verdict that had just changed its mind.
#
# Two independent benign addresses is evidence the path belongs to the site.
# `/` has 223 of them against 2 699 probers; `/.DS_Store` has one, at most.
_BENIGN_ADDRESSES_FOR_SITE = 2

_BENIGN_CLASSES = (
    "humans/browser-direct",
    "humans/browser-internal-nav",
    "humans/browser-referred",
    "bots/search-crawlers",
    "bots/ai-crawlers",
    "bots/seo-tools",
)


def get_exposures(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
    findings_only: bool = True,
) -> list[dict]:
    """Paths that answered 2xx and that no benign visitor ever asked for.

    Three decisions, each of which was wrong in an earlier draft and was
    corrected against a live log:

    **2xx, not "not an error".** Reading success as `status < 400` counted the
    HTTP→HTTPS redirect: 158 531 of the prober traffic on the reference log is a
    301, which would have reported every probe as a hit. A security finding that
    cries wolf costs more trust than it earns.

    **Query strings are excluded.** A static server ignores them, so `/?phpinfo=-1`
    returns the homepage with 200 and a scanner concludes its probe worked. 125
    distinct paths on the reference log are that one phenomenon, and listing them
    as 125 exposures would bury the one real finding. See get_probe_echo().

    **Convention paths are not findings** — the same list the 404 ratio uses.
    `/.well-known/acme-challenge/…` is fetched by nobody but a certificate
    authority, which is the exact shape of a finding and the exact opposite of
    one. That test now runs once, in the fold, against the decoded path: doing
    it in SQL as well only ever caught the spellings the fold would have caught
    anyway, and it hid the true figures from get_served_paths — `/robots.txt`
    came back as one request instead of 452, because only its percent-encoded
    spelling had slipped past the LIKE.

    **The benign test runs on the resource, not on the spelling.** It used to
    run per raw path in SQL, which made a finding depend on how each individual
    request happened to be written: one visitor of `//%2eDS_Store` was
    reclassified from a headless browser to a human by v6, that spelling dropped
    out, and the same file went from 31 addresses to 30 while staying listed
    under another spelling. A count that moves because one visitor was judged
    differently is not a count. Spellings fold first; the question "did anything
    benign ever fetch this" is then asked once, of the resource.

    **And "ever" means ever, not "within the selected range".** The counts are
    windowed — that is what the range tabs are for — but the benign test is not,
    because a path does not stop being part of the site on a quiet day. Both
    inside one window it read `/` as a finding on the 24 h range: 42 addresses,
    one of them benign, one short of the threshold. The site's own homepage,
    reported as something the server gave away.

    **Only the benign test reads ip_intel.** The counts inner-joined it once,
    long after the benign test had moved into the CTE, so the join did nothing
    but drop every address the rate-limited enricher had not reached yet: a
    fresh burst of probers stayed invisible, and the row disagreed with its own
    side panel. No verdict yet is not a benign verdict.
    """
    conds, params = _date_conditions(since, until, column="v.timestamp")
    where = "".join(f" AND {c}" for c in conds)
    benign = ", ".join("?" for _ in _BENIGN_CLASSES)
    rows = [
        dict(r)
        for r in conn.execute(
            f"""
        WITH benign_ever AS (
            SELECT v.path AS path, COUNT(DISTINCT v.ip) AS benign_ips
            FROM visits v
            JOIN ip_intel i ON i.ip = v.ip
            WHERE v.status BETWEEN 200 AND 299
              AND i.visitor_class IN ({benign})
            GROUP BY v.path
        )
        SELECT v.path,
               COUNT(DISTINCT v.ip) AS ips,
               COUNT(*)             AS hits,
               MIN(v.timestamp)     AS first_seen,
               MAX(v.timestamp)     AS last_seen,
               MAX(v.bytes_sent)    AS bytes_sent,
               COALESCE(b.benign_ips, 0) AS benign_ips
        FROM visits v
        LEFT JOIN benign_ever b ON b.path = v.path
        WHERE v.status BETWEEN 200 AND 299
          AND v.path NOT LIKE '%?%'
          {where}
        GROUP BY v.path
        ORDER BY ips DESC, hits DESC
    """,
            # Bound in the order the placeholders appear in the text, and the
            # CTE is the first thing in it, so the benign list binds ahead of
            # the window in the outer WHERE. get_probe_echo() below has the two
            # the other way round and therefore binds them the other way round.
            # Reversed, this still runs: the window gets a class name,
            # `v.timestamp >= 'bots/…'` matches no timestamp, and the page is
            # empty under every range while every test that passes no window
            # keeps passing.
            [*_BENIGN_CLASSES, *params],
        ).fetchall()
    ]
    return _fold_encodings(rows, findings_only, conn=conn, where=where, params=params)


def get_served_paths(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Everything this server handed out, findings and site pages alike.

    The same query and the same fold as get_exposures, without the last step —
    the benign threshold. Findings are the rows below it; these are all of them,
    each carrying `is_finding`.

    One result set rather than a second query, and the page splits it. Both
    routes already state the reason for that: a number queried twice can
    disagree with itself, and here the two blocks sit one above the other where
    a disagreement would be plainly visible.

    On the reference month this is seven rows — the homepage, index.html, four
    content pages and `/.DS_Store` — which is what makes the split worth showing
    at all. The findings table says "1 path"; it does not say one of how many.
    """
    return get_exposures(conn, since, until, findings_only=False)


def _recount_folded(
    conn: sqlite3.Connection, spellings: list[str], where: str, params: list
) -> tuple[int, int]:
    """Distinct addresses over several spellings of one path, and benign ones.

    A distinct count does not survive being added up. Two spellings each fetched
    by 30 addresses are not 60 addresses — anything that tried both is in both
    figures — and the column that shows this says "distinct". The sum was also
    what decided Site from Finding: two spellings with one benign address each
    summed to the threshold and marked a path as part of the site on the
    strength of one visitor counted twice.

    Asked only of the groups that actually folded, which is a handful of rows.
    The window applies to the addresses the way it applies everywhere on this
    page; the benign count is unwindowed, because "ever" means ever — the same
    split get_exposures makes between its two queries.
    """
    marks = ",".join("?" for _ in spellings)
    benign = ",".join("?" for _ in _BENIGN_CLASSES)
    ips = conn.execute(
        f"""SELECT COUNT(DISTINCT v.ip) FROM visits v
            WHERE v.status BETWEEN 200 AND 299 AND v.path IN ({marks}){where}""",
        [*spellings, *params],
    ).fetchone()[0]
    benign_ips = conn.execute(
        f"""SELECT COUNT(DISTINCT v.ip) FROM visits v
            JOIN ip_intel i ON i.ip = v.ip
            WHERE v.status BETWEEN 200 AND 299 AND v.path IN ({marks})
              AND i.visitor_class IN ({benign})""",
        [*spellings, *_BENIGN_CLASSES],
    ).fetchone()[0]
    return ips, benign_ips


def _fold_encodings(
    rows: list[dict],
    findings_only: bool = True,
    conn: sqlite3.Connection | None = None,
    where: str = "",
    params: list | None = None,
) -> list[dict]:
    """Collapse percent-encoded spellings of one path, and drop the harmless ones.

    Without this the reference log reports eight findings where there is one.
    `/.DS_Store`, `/%2eDS_Store` and `//%2eDS_Store` are the same 6 148-byte file
    reached three ways; `/robots%2etxt` is robots.txt, which the convention list
    would have excluded had it been spelled normally; and `//`, `/./`, `/%2f`
    are path-normalisation probes that get the homepage back.

    Seven rows of noise around one real finding is how a security feature stops
    being read. Decoding is what separates them: the variants fold into their
    decoded form, and anything whose decoded form is a path benign visitors
    fetch, or a convention path, is not a finding at all.
    """
    folded: dict[str, dict] = {}
    for row in rows:
        canonical = _canonical_path(row["path"])
        seen = folded.get(canonical)
        if seen is None:
            folded[canonical] = {**row, "path": canonical, "spellings": {row["path"]}}
            continue
        seen["ips"] += row["ips"]
        seen["hits"] += row["hits"]
        seen["benign_ips"] += row["benign_ips"]
        seen["spellings"].add(row["path"])
        seen["bytes_sent"] = max(seen["bytes_sent"], row["bytes_sent"])
        seen["last_seen"] = max(seen["last_seen"], row["last_seen"])
        seen["first_seen"] = min(seen["first_seen"], row["first_seen"])
    # The two counts above were added up across spellings, which is right for
    # requests and wrong for addresses — see _recount_folded. Corrected before
    # the threshold below reads benign_ips, not after.
    if conn is not None:
        for row in folded.values():
            if len(row["spellings"]) > 1:
                row["ips"], row["benign_ips"] = _recount_folded(
                    conn, sorted(row["spellings"]), where, params or []
                )
    # Now, and only now, ask the question — of the resource, once. The answer is
    # recorded on every row rather than used to drop rows, because the page shows
    # both sides of it: what was handed out, and which of it nothing legitimate
    # asked for. `findings_only` keeps get_exposures' own contract.
    #
    # A convention path and a fragment the site's own JavaScript fetches are not
    # findings — but they *are* things this server hands out, and a list of what
    # it hands out that omits robots.txt and four content pages would be a
    # stranger answer than either. They are marked rather than dropped, and only
    # the findings view filters on it.
    for row in folded.values():
        row["is_site"] = _is_convention_path(row["path"]) or _is_site_fragment(row["path"])
        row["is_finding"] = not row["is_site"] and row["benign_ips"] < _BENIGN_ADDRESSES_FOR_SITE
    out = sorted(
        (r for r in folded.values() if r["is_finding"] or not findings_only),
        key=lambda r: (-r["ips"], -r["hits"]),
    )
    for row in out:
        row["spellings"] = sorted(row["spellings"])
    return out


def get_exposure_detail(
    conn: sqlite3.Connection,
    spellings: list[str],
    since: str | None = None,
    until: str | None = None,
) -> dict:
    """Everything one finding's own requests can be asked, for the side panel.

    The findings table carries aggregates and nothing else — a count of
    addresses, a count of requests, two timestamps and a maximum byte size.
    That is enough to list a finding and not enough to decide anything about
    it, which is what the panel is for.

    **Keyed on spellings, not on the path.** A finding is the fold of every
    percent-encoded way the same resource was asked for, so `/.DS_Store` is
    `/.DS_Store` and `/%2eDS_Store` together. Matching the canonical path alone
    would answer for a subset of the row it claims to describe.

    **The window is the page's, but the served/not-served question is not.**
    Whether a 404 ever came back for these spellings decides whether the file is
    still on disk, and that is the one fact worth knowing regardless of which
    range the reader happens to have picked — so it is asked unwindowed. The
    counts beside it stay windowed, like everything else on the page.
    """
    if not spellings:
        return {}
    marks = ", ".join("?" for _ in spellings)
    conds, params = _date_conditions(since, until, column="v.timestamp")
    where = "".join(f" AND {c}" for c in conds)
    served = " AND v.status BETWEEN 200 AND 299"

    def one(select: str, extra: str = "", args: list | None = None) -> list[dict]:
        return [
            dict(r)
            for r in conn.execute(
                f"""SELECT {select} FROM visits v LEFT JOIN ip_intel i ON i.ip = v.ip
                    WHERE v.path IN ({marks}){served}{where}{extra}""",
                [*spellings, *params, *(args or [])],
            ).fetchall()
        ]

    answers = one(
        "v.status AS status, v.server_port AS port, COUNT(*) AS hits,"
        " MIN(v.bytes_sent) AS min_bytes, MAX(v.bytes_sent) AS max_bytes",
        " GROUP BY v.status, v.server_port ORDER BY hits DESC",
    )
    classes = one(
        "COALESCE(NULLIF(i.visitor_class, ''), 'unknown') AS visitor_class,"
        " COUNT(DISTINCT v.ip) AS ips",
        " GROUP BY 1 ORDER BY ips DESC",
    )
    clients = one(
        "COALESCE(NULLIF(v.user_agent, ''), '') AS user_agent, v.method AS method,"
        " COUNT(*) AS hits",
        " GROUP BY 1, 2 ORDER BY hits DESC LIMIT 8",
    )
    origins = one(
        "COALESCE(i.asn, '') AS asn, COALESCE(i.org, '') AS org,"
        " COALESCE(i.country_code, '') AS country_code, COUNT(DISTINCT v.ip) AS ips",
        " GROUP BY 1, 2, 3 ORDER BY ips DESC LIMIT 8",
    )
    signals = one(
        "COUNT(DISTINCT CASE WHEN i.is_hosting THEN v.ip END) AS hosting,"
        " COUNT(DISTINCT CASE WHEN i.is_proxy THEN v.ip END) AS proxy,"
        " COUNT(DISTINCT CASE WHEN i.is_tor THEN v.ip END) AS tor,"
        " COUNT(DISTINCT CASE WHEN i.dnsbl_listed THEN v.ip END) AS dnsbl"
    )
    per_address = one(
        "COUNT(DISTINCT v.ip) AS ips, COUNT(*) AS hits,"
        " MIN(v.timestamp) AS first_seen, MAX(v.timestamp) AS last_seen"
    )
    # Unwindowed, and the only unwindowed thing here: a 404 after the last 200
    # means the file is gone, and that answer must not depend on the range.
    refused = conn.execute(
        f"""SELECT COUNT(*) AS n, MAX(timestamp) AS last FROM visits
            WHERE path IN ({marks}) AND status = 404""",
        spellings,
    ).fetchone()
    # What else those addresses asked this server for. It reframes a finding
    # from "nine people wanted this file" to "nine scanners walked a list and
    # this was one entry", which is usually what it is.
    #
    # In two steps, and both halves of that matter. Written as one statement with
    # `v.ip IN (SELECT ip FROM visits WHERE … AND v.status BETWEEN 200 AND 299)`
    # the status term binds to the *outer* v — an accidental correlation that
    # filtered the wrong rows and answered 26 paths where the truth is 2 358.
    # It also took 32 seconds against 101 413 visits, because SQLite re-ran the
    # subquery per row; the address list is nine entries, so binding it is one
    # millisecond.
    fetchers = [
        r[0]
        for r in conn.execute(
            f"SELECT DISTINCT ip FROM visits WHERE path IN ({marks})"
            " AND status BETWEEN 200 AND 299",
            spellings,
        )
    ]
    if fetchers:
        ip_marks = ", ".join("?" for _ in fetchers)
        context = conn.execute(
            f"""SELECT COUNT(DISTINCT path) AS paths, COUNT(*) AS hits FROM visits
                WHERE ip IN ({ip_marks}) AND path NOT IN ({marks})""",
            [*fetchers, *spellings],
        ).fetchone()
    else:
        context = {"paths": 0, "hits": 0}

    totals = per_address[0] if per_address else {}
    return {
        "answers": answers,
        "classes": classes,
        "clients": clients,
        "origins": origins,
        "signals": signals[0] if signals else {},
        "refused": {"hits": refused["n"], "last": refused["last"]},
        "context": {"paths": context["paths"], "hits": context["hits"]},
        "ips": totals.get("ips") or 0,
        "hits": totals.get("hits") or 0,
        "first_seen": totals.get("first_seen"),
        "last_seen": totals.get("last_seen"),
    }


def _canonical_path(path: str) -> str:
    """One spelling per resource.

    Percent-decoding folds `/%2eDS_Store` onto `/.DS_Store`; collapsing repeated
    slashes and a bare `/./` folds the normalisation probes onto what they
    actually reached. Both are the same file asked for in a way that looks
    different in a log.
    """
    decoded = unquote(path)
    return re.sub(r"/{2,}", "/", decoded).replace("/./", "/")


def _is_convention_path(path: str) -> bool:
    """The same list the 404 ratio uses, applied to an already-decoded path."""
    lowered = path.lower()
    return any(fnmatch(lowered, p.replace("%", "*")) for p in _CONVENTION_404_PATTERNS)


def _is_site_fragment(path: str) -> bool:
    """A path the site's own JavaScript fetches, and therefore not a finding.

    JS_ONLY_PATH_PREFIXES already names them — the classifier reads a fetch of
    one as browser evidence. A path fetched by the page is part of the site as
    published; it only looks like a finding because no crawler follows a link
    that does not exist in the HTML, which is the one test this page applies.
    The reference deployment reported a real content page this way.

    Empty unless configured, so a deployment that has not named its prefixes
    loses nothing here.
    """
    return any(path.startswith(prefix) for prefix in settings.js_only_path_prefixes)


def get_probe_echo(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
) -> dict:
    """How often a probe URL got a 200 that means nothing.

    Not an exposure — the opposite of one. A static server serves the path and
    ignores the query, so `/?rest_route=/wp/v2/users/` returns the homepage and
    a scanner reads that as a working WordPress endpoint. Worth reporting
    because it explains why the same probes keep arriving, and because an
    operator who sees "200" in their own log should know what it did not mean.

    Counted as one fact with a number, never as a list of findings.
    """
    conds, params = _date_conditions(since, until, column="v.timestamp")
    where = "".join(f" AND {c}" for c in conds)
    benign = ", ".join("?" for _ in _BENIGN_CLASSES)
    row = conn.execute(
        f"""
        SELECT COUNT(*) AS urls, SUM(ips) AS ips FROM (
            SELECT v.path, COUNT(DISTINCT v.ip) AS ips
            FROM visits v
            LEFT JOIN ip_intel i ON i.ip = v.ip
            WHERE v.status BETWEEN 200 AND 299
              AND v.path LIKE '%?%'
              {where}
            GROUP BY v.path
            HAVING SUM(CASE WHEN i.visitor_class IN ({benign}) THEN 1 ELSE 0 END) = 0
        )
    """,
        [*params, *_BENIGN_CLASSES],
    ).fetchone()
    return {"urls": row[0] or 0, "ips": row[1] or 0}
