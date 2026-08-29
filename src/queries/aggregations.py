"""The four groupings of /visitors: network, country, client, path.

Each get_*/count_* pair differs only in the dimension it groups by and the sort
keys it accepts, so both run through _exec_agg_rows / _exec_agg_count with the
shared per-row breakdown columns.
"""

from __future__ import annotations

import sqlite3
from typing import Sequence

from .. import search
from ..taxonomy import GROUPS_WITH_UNKNOWN, SIGNALS
from ..validators import valid_order
from ._shared import (
    _STATUS_CLASS_SQL,
    _apply_class_filter,
    _apply_date_filter,
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
    query += f" GROUP BY {group_by} ORDER BY {sort_col} {order_dir} LIMIT ? OFFSET ?"
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
    )


def count_networks(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
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
    )


def count_countries(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
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
    )


def count_clients(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
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
    )


def count_paths(
    conn: sqlite3.Connection,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    status: str | None = None,
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
    )
