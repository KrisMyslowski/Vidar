"""The four groupings of /visitors: network, country, client, path.

Each get_*/count_* pair differs only in the dimension it groups by and the sort
keys it accepts, so both run through _exec_agg_rows / _exec_agg_count with the
shared per-row breakdown columns.

get_neighbourhood() is not one of those tables but belongs to the same
machinery: it asks the breakdown of one address's peers rather than of every
group, and reads the same columns so the bar on the detail page and the bars in
the tables mean the same thing.
"""

from __future__ import annotations

import sqlite3
from typing import Sequence

from .. import search
from ..db import network_of
from ..taxonomy import GROUPS_WITH_UNKNOWN, SIGNALS
from ..validators import valid_order
from ._shared import (
    _STATUS_CLASS_SQL,
    _apply_class_filter,
    _apply_date_filter,
    _apply_seen_filter,
    _apply_signal_filter,
    _group_match,
    _like,
    _like_escape,
    _prefix_visit_cols,
    _signal_condition,
    _status_band_sums,
    _term_sql,
)

# Per-row class-group + signal distinct-IP breakdown, shared by every aggregation
# table (Networks, Countries, Clients, Paths). Mirrors the unified legend: the same
# five identity groups and four network/reputation signals, counted per aggregate row.
_AGG_GROUP_IP_COUNTS = ",\n    ".join(
    f"COUNT(DISTINCT CASE WHEN {_group_match(g, 'i.visitor_class')} THEN v.ip END) AS {g}_ips"
    for g in GROUPS_WITH_UNKNOWN
)


# One distinct-IP count per signal, aliased `<signal alias>_ips`. The
# mix-bar macro reads the same aliases off the registry, so the bar and the query
# describe the same six things by construction.
_AGG_SIGNAL_IP_COUNTS = ",\n    ".join(
    f"COUNT(DISTINCT CASE WHEN {_signal_condition(s, 'i.', 'v.ip')} THEN v.ip END)"
    f" AS {s.alias}_ips"
    for s in SIGNALS
)


_AGG_BREAKDOWN_SELECT = f"""
    COUNT(DISTINCT v.ip) AS unique_ips,
    COUNT(v.id) AS visits,
    MAX(v.timestamp) AS last_seen,
    {_AGG_GROUP_IP_COUNTS},
    {_AGG_SIGNAL_IP_COUNTS}
"""


# Sort whitelists per aggregation table; anything unmapped falls back to "visits".
# The route derives its own key sets from these — see _AGG_SORTS in dashboard.py.
NETWORKS_SORT_MAP: dict[str, str] = {
    "asn": "i.asn",
    "org": "org",
    "unique_ips": "unique_ips",
    "visits": "visits",
    "last_seen": "last_seen",
}


COUNTRIES_SORT_MAP: dict[str, str] = {
    "country": "country",
    "country_code": "i.country_code",
    "unique_ips": "unique_ips",
    "visits": "visits",
    "last_seen": "last_seen",
}


CLIENTS_SORT_MAP: dict[str, str] = {
    "browser": "v.browser",
    "os": "v.os",
    "device": "v.device",
    "unique_ips": "unique_ips",
    "visits": "visits",
    "last_seen": "last_seen",
}


PATHS_SORT_MAP: dict[str, str] = {
    "path": "v.path",
    "unique_ips": "unique_ips",
    "visits": "visits",
    "last_seen": "last_seen",
}


def _exec_agg_rows(
    conn: sqlite3.Connection,
    dim_select: str,
    group_by: str,
    where: str,
    sort_map: dict[str, str],
    *,
    page: int,
    limit: int,
    sort: str,
    order: str,
    class_filter: list[str] | None,
    signal_filter: list[str] | None,
    date_from: str | None,
    date_to: str | None,
    extra_where: str = "",
    extra_params: Sequence = (),
    seen: str | None = None,
) -> list[dict]:
    """Run a GROUP BY aggregation over visits⋈ip_intel with the shared class/signal/
    date legend filters and the unified breakdown columns. `where` is a complete
    condition (selecting non-null dimensions); filters are appended as AND clauses.
    `extra_where`/`extra_params` inject table-specific conditions before the shared
    filters (placeholder order: extra → class → signal → date)."""
    sort_col = sort_map.get(sort, "visits")
    order_dir = valid_order(order)
    offset = (page - 1) * limit
    params: list = list(extra_params)
    query = (
        f"SELECT {dim_select}, {_AGG_BREAKDOWN_SELECT}"
        f" FROM visits v LEFT JOIN ip_intel i ON v.ip = i.ip WHERE {where}{extra_where}"
    )
    query, params = _apply_class_filter(query, params, class_filter)
    query, params = _apply_signal_filter(query, params, signal_filter)
    query, params = _apply_date_filter(query, params, date_from, date_to)
    query, params = _apply_seen_filter(query, params, seen, date_from)
    # The group key breaks ties, for the reason get_visitors_grouped gives.
    query += f" GROUP BY {group_by} ORDER BY {sort_col} {order_dir}, {group_by} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return [dict(r) for r in conn.execute(query, params).fetchall()]


def _exec_agg_count(
    conn: sqlite3.Connection,
    group_by: str,
    where: str,
    *,
    class_filter: list[str] | None,
    signal_filter: list[str] | None,
    date_from: str | None,
    date_to: str | None,
    extra_where: str = "",
    extra_params: Sequence = (),
    seen: str | None = None,
) -> int:
    """Count distinct aggregation groups for pagination (mirrors _exec_agg_rows filters)."""
    params: list = list(extra_params)
    query = (
        f"SELECT COUNT(*) FROM (SELECT 1"
        f" FROM visits v LEFT JOIN ip_intel i ON v.ip = i.ip WHERE {where}{extra_where}"
    )
    query, params = _apply_class_filter(query, params, class_filter)
    query, params = _apply_signal_filter(query, params, signal_filter)
    query, params = _apply_date_filter(query, params, date_from, date_to)
    query, params = _apply_seen_filter(query, params, seen, date_from)
    query += f" GROUP BY {group_by})"
    row = conn.execute(query, params).fetchone()
    return row[0] if row else 0


_NETWORKS_DIM = (
    "i.asn, MAX(i.org) AS org, MAX(i.isp) AS isp,"
    " COUNT(DISTINCT i.country_code) AS country_count"
)


_NETWORKS_WHERE = "i.asn IS NOT NULL AND i.asn != ''"


_COUNTRIES_DIM = "i.country_code, MAX(i.country) AS country"


_COUNTRIES_WHERE = "i.country_code IS NOT NULL AND i.country_code != ''"


_CLIENTS_DIM = (
    "NULLIF(v.browser,'') AS browser, NULLIF(v.os,'') AS os, NULLIF(v.device,'') AS device"
)


_CLIENTS_WHERE = "(v.browser != '' OR v.os != '' OR v.device != '')"


_PATHS_DIM = f"v.path,\n{_status_band_sums('v.status')}"


_PATHS_WHERE = "v.path != ''"


# Free-text search spans per aggregation table (?q= matches any of these columns)
_NETWORKS_Q_COLS = ("i.org", "i.isp", "i.asn")


_COUNTRIES_Q_COLS = ("i.country", "i.country_code")


_CLIENTS_Q_COLS = ("v.browser", "v.os", "v.device")


_PATHS_Q_COLS = ("v.path", "v.user_agent")


def _agg_q_filter(q: str | None, columns: Sequence[str]) -> tuple[str, list]:
    """Free-text filter for the aggregation tables.

    Same parsed terms as the visitor list, but applied inline — before GROUP BY.
    That is deliberate here: on `?group=path&q=ua:curl` the question is "what did
    curl fetch", so the row's counts should describe the matching traffic. See
    data-reference.md §4.4.

    `columns` is the table's own broad-search span, used for terms that name no
    field; a term that does name one is matched against that field wherever the
    query can reach it.
    """
    terms, _ = search.parse(q)
    clauses: list[str] = []
    params: list = []
    for term in terms:
        if term.match == search.BROAD:
            ors = " OR ".join(_like(c) for c in columns)
            clauses.append(f"({ors})")
            params.extend([f"%{_like_escape(term.value)}%"] * len(columns))
            continue
        intel, intel_params, visit, visit_params = _term_sql(term, "v.ip")
        parts, term_params = [], []
        if intel:
            parts.append(intel)
            term_params.extend(intel_params)
        if visit:
            # Inline, so the visits columns need their alias back.
            parts.append(_prefix_visit_cols(visit))
            term_params.extend(visit_params)
        if not parts:
            continue
        clauses.append("(" + " OR ".join(parts) + ")")
        params.extend(term_params)
    if not clauses:
        return "", []
    return " AND " + " AND ".join(clauses), params


def _paths_extra_filters(q: str | None, status: str | None) -> tuple[str, list]:
    """Paths-specific extra WHERE: free-text over path AND user-agent (so "wget"
    matches CLI-tool traffic) plus a status class."""
    extra_where, extra_params = _agg_q_filter(q, _PATHS_Q_COLS)
    if status:
        extra_where += _STATUS_CLASS_SQL.get(status, "")
    return extra_where, extra_params


def get_networks(
    conn: sqlite3.Connection,
    page: int = 1,
    limit: int = 50,
    sort: str = "visits",
    order: str = "DESC",
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    seen: str | None = None,
) -> list[dict]:
    """Visitors grouped by network (ASN): one row per autonomous system.
    `q` searches org + ISP + ASN."""
    extra_where, extra_params = _agg_q_filter(q, _NETWORKS_Q_COLS)
    return _exec_agg_rows(
        conn,
        _NETWORKS_DIM,
        "i.asn",
        _NETWORKS_WHERE,
        NETWORKS_SORT_MAP,
        page=page,
        limit=limit,
        sort=sort,
        order=order,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


def count_networks(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    seen: str | None = None,
) -> int:
    """Count distinct networks (ASNs). Used for pagination."""
    extra_where, extra_params = _agg_q_filter(q, _NETWORKS_Q_COLS)
    return _exec_agg_count(
        conn,
        "i.asn",
        _NETWORKS_WHERE,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


def get_countries(
    conn: sqlite3.Connection,
    page: int = 1,
    limit: int = 50,
    sort: str = "visits",
    order: str = "DESC",
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    seen: str | None = None,
) -> list[dict]:
    """Visitors grouped by country: one row per country code.
    `q` searches country name + code."""
    extra_where, extra_params = _agg_q_filter(q, _COUNTRIES_Q_COLS)
    return _exec_agg_rows(
        conn,
        _COUNTRIES_DIM,
        "i.country_code",
        _COUNTRIES_WHERE,
        COUNTRIES_SORT_MAP,
        page=page,
        limit=limit,
        sort=sort,
        order=order,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


def count_countries(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    seen: str | None = None,
) -> int:
    """Count distinct countries. Used for pagination."""
    extra_where, extra_params = _agg_q_filter(q, _COUNTRIES_Q_COLS)
    return _exec_agg_count(
        conn,
        "i.country_code",
        _COUNTRIES_WHERE,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


def get_clients(
    conn: sqlite3.Connection,
    page: int = 1,
    limit: int = 50,
    sort: str = "visits",
    order: str = "DESC",
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    seen: str | None = None,
) -> list[dict]:
    """Visitors grouped by client: one row per Browser/OS/Device combination.
    `q` searches browser + OS + device."""
    extra_where, extra_params = _agg_q_filter(q, _CLIENTS_Q_COLS)
    return _exec_agg_rows(
        conn,
        _CLIENTS_DIM,
        "v.browser, v.os, v.device",
        _CLIENTS_WHERE,
        CLIENTS_SORT_MAP,
        page=page,
        limit=limit,
        sort=sort,
        order=order,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


def count_clients(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    seen: str | None = None,
) -> int:
    """Count distinct Browser/OS/Device combinations. Used for pagination."""
    extra_where, extra_params = _agg_q_filter(q, _CLIENTS_Q_COLS)
    return _exec_agg_count(
        conn,
        "v.browser, v.os, v.device",
        _CLIENTS_WHERE,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


def get_paths(
    conn: sqlite3.Connection,
    page: int = 1,
    limit: int = 50,
    sort: str = "visits",
    order: str = "DESC",
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    status: str | None = None,
    seen: str | None = None,
) -> list[dict]:
    """Visitors grouped by request path: one row per path with a status-code mix.
    `q` searches path + user-agent; `status` narrows to a 2xx-5xx class."""
    extra_where, extra_params = _paths_extra_filters(q, status)
    return _exec_agg_rows(
        conn,
        _PATHS_DIM,
        "v.path",
        _PATHS_WHERE,
        PATHS_SORT_MAP,
        page=page,
        limit=limit,
        sort=sort,
        order=order,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


def count_paths(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    status: str | None = None,
    seen: str | None = None,
) -> int:
    """Count distinct request paths. Used for pagination."""
    extra_where, extra_params = _paths_extra_filters(q, status)
    return _exec_agg_count(
        conn,
        "v.path",
        _PATHS_WHERE,
        class_filter=class_filter,
        signal_filter=signal_filter,
        date_from=date_from,
        date_to=date_to,
        extra_where=extra_where,
        extra_params=extra_params,
        seen=seen,
    )


# ── The neighbourhood of one address ─────────────────────────────────────────


# A plurality is not a character; a majority is. Below this the bar is the whole
# answer and no sentence is offered — "26 of 59 are humans" reads as a verdict
# on the range when the other 33 are spread across four groups.
_DOMINANT_SHARE = 0.5

# And a majority of two is not a majority of anything. The share alone let
# "1 of 1 are Bots" onto the page, which is one data point wearing the grammar
# of a finding — the same mistake as a bar over nothing, one level up. Below
# five peers the bar and the count stand on their own and say how thin they are.
_DOMINANT_MIN_PEERS = 5


def get_neighbourhood(conn: sqlite3.Connection, ip: str) -> list[dict]:
    """What Vidar has already judged next to this address, by /24 and by ASN.

    The cold-start problem: a verdict needs history, and a first request has
    none. An address has neighbours from the first request though, and those
    have been judged — "40 addresses seen from this /24, 38 of them probers" is
    an orientation the address itself cannot give.

    No new data and no new provider: `ip_intel` already holds every judgement,
    and net() derives the /24 or /64 from the address. See db.network_of().

    Peers are selected from `ip_intel` first, and the visit rows are then
    reached through it — the other way round means running net() over every
    visit row rather than over one row per address.

    Two scopes, returned in the order they narrow: the /24 is the range one
    customer holds, the ASN is the operator behind it. Either can be absent —
    an unenriched address has no ASN, and an address whose neighbourhood Vidar
    has never seen has no /24 row. The caller shows what it gets; a scope with
    no peers is left out rather than shown as a zero, because "0 of 0 are
    probers" is a bar that reads as evidence and is not one.
    """
    own = conn.execute("SELECT asn, org FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
    network = network_of(ip)
    # net() is a Python function, so `net(ip) = net(?)` can use no index and ran
    # over every row of ip_intel on every detail page. An IPv4 /24 is a text
    # prefix — "203.0.113." — which the primary key can seek to ('/' sorts right
    # after '.'), and net() then confirms only what the seek found. IPv6 text is
    # not a prefix of its /64 (2001:db8::1, 2001:0db8:0:0::2), so it keeps the scan.
    # By the parsed family, not by a "." in the text: ::ffff:192.0.2.1 has one
    # and is IPv6, whose /64 no IPv4 prefix describes.
    if network and network.endswith("/24"):
        prefix = ip.rsplit(".", 1)[0] + "."
        peers_sql = (
            "SELECT ip FROM ip_intel WHERE ip >= ? AND ip < ? AND net(ip) = net(?) AND ip != ?"
        )
        peers_params = (prefix, prefix[:-1] + "/", ip, ip)
    else:
        peers_sql = "SELECT ip FROM ip_intel WHERE net(ip) = net(?) AND ip != ?"
        peers_params = (ip, ip)
    scopes = (
        ("network", network, peers_sql, peers_params),
        (
            "asn",
            (own["asn"] if own else "") or "",
            "SELECT ip FROM ip_intel WHERE asn = ? AND ip != ?",
            ((own["asn"] if own else ""), ip),
        ),
    )
    out = []
    for scope, label, peers_sql, params in scopes:
        if not label:
            continue
        row = conn.execute(
            f"""
            SELECT {_AGG_BREAKDOWN_SELECT}
            FROM visits v
            JOIN ip_intel i ON i.ip = v.ip
            WHERE v.ip IN ({peers_sql})
        """,
            params,
        ).fetchone()
        if row and row["unique_ips"]:
            group, count = _dominant_group(row)
            out.append(
                {
                    "scope": scope,
                    "label": label,
                    "org": (own["org"] if own else "") if scope == "asn" else "",
                    "dominant_group": group,
                    "dominant_ips": count,
                    **dict(row),
                }
            )
    return out


def _dominant_group(row: sqlite3.Row) -> tuple[str, int]:
    """The identity group holding a majority of these addresses, or ('', 0).

    An address can only be in one group, so the counts partition the peers and
    at most one can pass. That is what makes the sentence sayable at all.
    """
    if row["unique_ips"] < _DOMINANT_MIN_PEERS:
        return "", 0
    counts = {g: row[f"{g}_ips"] or 0 for g in GROUPS_WITH_UNKNOWN}
    group = max(counts, key=lambda g: counts[g])
    if counts[group] > row["unique_ips"] * _DOMINANT_SHARE:
        return group, counts[group]
    return "", 0
