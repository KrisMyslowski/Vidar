"""Per-IP aggregation — the /visitors table, the detail page, one IP's requests.

The row builder and the count share one query shape (_exec_visitor_rows /
_exec_visitor_count) so the table and its pager can never disagree about what
they are counting.
"""

from __future__ import annotations

import sqlite3

from ..validators import valid_order
from ._shared import (
    _VISITOR_GROUPED_SELECT,
    VISITOR_REQUEST_SORT_MAP,
    VISITOR_SORT_MAP,
    _apply_class_filter,
    _apply_date_filter,
    _apply_drilldown_filters,
    _apply_signal_filter,
    _apply_visitor_search,
    _shodan_agg_select,
)


def _exec_visitor_rows(
    conn: sqlite3.Connection,
    from_where: str,
    params: list,
    page: int,
    limit: int,
    sort: str,
    order: str,
    country_filter: str | None,
    ip_filter: str | None,
    class_filter: list[str] | None,
    signal_filter: list[str] | None,
    min_visits: int,
    date_from: str | None,
    date_to: str | None,
    *,
    apply_class: bool = True,
    port_filter: int | None = None,
    asn_filter: str | None = None,
    path_filter: str | None = None,
    browser_filter: str | None = None,
    q: str | None = None,
) -> list[dict]:
    """Build and execute a grouped-visitor SELECT query."""
    sort_col = VISITOR_SORT_MAP.get(sort, "last_seen")
    order_dir = valid_order(order)
    offset = (page - 1) * limit
    query = f"SELECT {_VISITOR_GROUPED_SELECT} {from_where}"
    if country_filter:
        query += " AND i.country_code = ?"
        params.append(country_filter)
    if ip_filter:
        # Exact match — the route validates with valid_ip(), so only complete IPs
        # arrive here (keeps the filter consistent and free of LIKE wildcards).
        query += " AND v.ip = ?"
        params.append(ip_filter)
    if port_filter:
        query += " AND v.server_port = ?"
        params.append(port_filter)
    query, params = _apply_drilldown_filters(
        query, params, asn_filter, path_filter, browser_filter
    )
    query, params = _apply_visitor_search(query, params, q)
    if apply_class:
        query, params = _apply_class_filter(query, params, class_filter)
    query, params = _apply_signal_filter(query, params, signal_filter)
    query, params = _apply_date_filter(query, params, date_from, date_to)
    having = f" HAVING COUNT(v.id) >= {int(min_visits)}" if min_visits and min_visits > 0 else ""
    query += f" GROUP BY v.ip{having} ORDER BY {sort_col} {order_dir} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return [dict(r) for r in conn.execute(query, params).fetchall()]


def _exec_visitor_count(
    conn: sqlite3.Connection,
    from_where: str,
    params: list,
    country_filter: str | None,
    ip_filter: str | None,
    class_filter: list[str] | None,
    signal_filter: list[str] | None,
    min_visits: int,
    date_from: str | None,
    date_to: str | None,
    *,
    apply_class: bool = True,
    port_filter: int | None = None,
    asn_filter: str | None = None,
    path_filter: str | None = None,
    browser_filter: str | None = None,
    q: str | None = None,
) -> int:
    """Build and execute a grouped-visitor COUNT query for pagination."""
    having = f" HAVING COUNT(v.id) >= {int(min_visits)}" if min_visits and min_visits > 0 else ""
    query = f"SELECT COUNT(*) FROM (SELECT v.ip {from_where}"
    if country_filter:
        query += " AND i.country_code = ?"
        params.append(country_filter)
    if ip_filter:
        # Exact match — mirrors _exec_visitor_rows (route validates via valid_ip()).
        query += " AND v.ip = ?"
        params.append(ip_filter)
    if port_filter:
        query += " AND v.server_port = ?"
        params.append(port_filter)
    query, params = _apply_drilldown_filters(
        query, params, asn_filter, path_filter, browser_filter
    )
    query, params = _apply_visitor_search(query, params, q)
    if apply_class:
        query, params = _apply_class_filter(query, params, class_filter)
    query, params = _apply_signal_filter(query, params, signal_filter)
    query, params = _apply_date_filter(query, params, date_from, date_to)
    query += f" GROUP BY v.ip{having})"
    row = conn.execute(query, params).fetchone()
    return row[0] if row else 0


_FW_ALL = "FROM visits v LEFT JOIN ip_intel i ON v.ip = i.ip WHERE 1=1"


def get_visitors_grouped(
    conn: sqlite3.Connection,
    page: int = 1,
    limit: int = 50,
    sort: str = "last_seen",
    order: str = "DESC",
    country_filter: str | None = None,
    ip_filter: str | None = None,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    min_visits: int = 0,
    date_from: str | None = None,
    date_to: str | None = None,
    port_filter: int | None = None,
    asn_filter: str | None = None,
    path_filter: str | None = None,
    browser_filter: str | None = None,
    q: str | None = None,
) -> list[dict]:
    """Fetch visitors grouped by IP: one row per unique IP with aggregated stats.

    `q` searches the IP itself, its network/geo intel, and any path, user-agent,
    browser or OS it ever presented."""
    return _exec_visitor_rows(
        conn,
        _FW_ALL,
        [],
        page,
        limit,
        sort,
        order,
        country_filter,
        ip_filter,
        class_filter,
        signal_filter,
        min_visits,
        date_from,
        date_to,
        port_filter=port_filter,
        asn_filter=asn_filter,
        path_filter=path_filter,
        browser_filter=browser_filter,
        q=q,
    )


def count_visitors_grouped(
    conn: sqlite3.Connection,
    country_filter: str | None = None,
    ip_filter: str | None = None,
    class_filter: list[str] | None = None,
    signal_filter: list[str] | None = None,
    min_visits: int = 0,
    date_from: str | None = None,
    date_to: str | None = None,
    port_filter: int | None = None,
    asn_filter: str | None = None,
    path_filter: str | None = None,
    browser_filter: str | None = None,
    q: str | None = None,
) -> int:
    """Count distinct visitor IPs. Used for pagination in grouped view."""
    return _exec_visitor_count(
        conn,
        _FW_ALL,
        [],
        country_filter,
        ip_filter,
        class_filter,
        signal_filter,
        min_visits,
        date_from,
        date_to,
        port_filter=port_filter,
        asn_filter=asn_filter,
        path_filter=path_filter,
        browser_filter=browser_filter,
        q=q,
    )


def get_visitor_detail(conn: sqlite3.Connection, ip: str) -> dict | None:
    """Get enrichment info + aggregated stats for a single IP."""
    row = conn.execute(
        """SELECT v.ip,
                  MIN(v.timestamp) as first_seen,
                  MAX(v.timestamp) as last_seen,
                  COUNT(v.id) as visit_count,
                  COUNT(DISTINCT v.path) as unique_pages,
                  -- Server ports this IP actually connected to. Not the same
                  -- thing as Shodan's open_ports below: this is what it did
                  -- here, that is what the host exposes to the internet.
                  GROUP_CONCAT(DISTINCT NULLIF(v.server_port, 0)) as ports,
                  GROUP_CONCAT(DISTINCT v.user_agent) as user_agents,
                  GROUP_CONCAT(DISTINCT NULLIF(v.browser, '')) as browsers,
                  GROUP_CONCAT(DISTINCT NULLIF(v.os, '')) as oses,
                  GROUP_CONCAT(DISTINCT NULLIF(v.device, '')) as devices,
                  ROUND(AVG(v.request_time), 3) as avg_response_time,
                  SUM(v.bytes_sent) as total_bandwidth,
                  GROUP_CONCAT(DISTINCT NULLIF(v.accept_language, '')) as accept_languages,
                  ROUND(AVG(NULLIF(v.request_length, 0)), 0) as avg_request_length,
                  MAX(v.request_length) as max_request_length,
                  SUM(CASE WHEN v.limit_req_status IN ('DELAYED','REJECTED')
                           THEN 1 ELSE 0 END) as rate_limit_events,
                  SUM(CASE WHEN v.status BETWEEN 400 AND 499
                           THEN 1 ELSE 0 END) as err_4xx,
                  GROUP_CONCAT(DISTINCT NULLIF(v.ssl_cipher, '')) as ssl_ciphers,
                  GROUP_CONCAT(DISTINCT NULLIF(v.http_x_forwarded_for, '')) as xff_headers,
                  GROUP_CONCAT(DISTINCT NULLIF(v.sec_fetch_dest, '')) as sec_fetch_dests,
                  GROUP_CONCAT(DISTINCT NULLIF(v.sec_fetch_mode, '')) as sec_fetch_modes,
                  GROUP_CONCAT(DISTINCT NULLIF(v.sec_fetch_site, '')) as sec_fetch_sites,
                  GROUP_CONCAT(DISTINCT NULLIF(v.http_version, '')) as http_versions,
                  ROUND(
                    SUM(CASE WHEN v.sec_fetch_dest != '' THEN 1 ELSE 0 END) * 1.0 / COUNT(*), 2
                  ) as sec_fetch_rate,
                  i.country, i.country_code, i.city, i.lat, i.lon,
                  i.isp, i.org, i.asn,
                  i.visitor_class,
                  i.is_proxy, i.is_hosting, i.is_mobile,
                  i.is_tor, i.dnsbl_listed, i.dnsbl_sources,
                  i.reverse_dns,
                  i.fetched_at,
                  """
        + _shodan_agg_select("i.ip")
        + """
           FROM visits v
           LEFT JOIN ip_intel i ON v.ip = i.ip
           WHERE v.ip = ?
           GROUP BY v.ip""",
        (ip,),
    ).fetchone()
    return dict(row) if row else None


def get_visitor_requests(
    conn: sqlite3.Connection,
    ip: str,
    page: int = 1,
    limit: int = 100,
    sort: str = "timestamp",
    order: str = "DESC",
) -> list[dict]:
    """Get paginated requests for a single IP with optional server-side sorting.

    `sort` must be one of the safe keys defined in `VISITOR_REQUEST_SORT_MAP`.
    """
    offset = (page - 1) * limit
    sort_col = VISITOR_REQUEST_SORT_MAP.get(sort, "timestamp")
    order_dir = valid_order(order)

    sql = f"""SELECT timestamp, method, path, status, bytes_sent,
                  server_port,
                  user_agent, referer, request_time, ssl_protocol,
                  browser, os, device, accept_language,
                  request_length, http_x_forwarded_for, ssl_cipher,
                  connection_requests, limit_req_status,
                  http_version, sec_fetch_dest, sec_fetch_mode, sec_fetch_site,
                  accept_encoding, ssl_session_reused
           FROM visits
           WHERE ip = ?
           ORDER BY {sort_col} {order_dir}
           LIMIT ? OFFSET ?"""
    rows = conn.execute(sql, (ip, limit, offset)).fetchall()
    return [dict(r) for r in rows]
