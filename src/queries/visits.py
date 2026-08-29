"""The raw visit rows: one insert, one paginated read, one export stream."""

from __future__ import annotations

import sqlite3
from typing import Iterator

from ..validators import valid_order
from ._shared import VISIT_SORT_MAP, _apply_visit_filters


def insert_visit(
    conn: sqlite3.Connection,
    ip: str,
    timestamp: str,
    method: str = "",
    path: str = "",
    server_port: int = 0,
    status: int = 0,
    bytes_sent: int = 0,
    user_agent: str = "",
    referer: str = "",
    request_time: float = 0.0,
    ssl_protocol: str = "",
    browser: str = "",
    os: str = "",
    device: str = "",
    accept_language: str = "",
    request_length: int = 0,
    http_x_forwarded_for: str = "",
    ssl_cipher: str = "",
    connection: int = 0,
    connection_requests: int = 0,
    limit_req_status: str = "",
    http_version: str = "",
    sec_fetch_dest: str = "",
    sec_fetch_mode: str = "",
    sec_fetch_site: str = "",
    accept_encoding: str = "",
    ssl_session_reused: str = "",
) -> int:
    """Insert a single visit record. Returns the new row ID, or 0 if it was a
    duplicate the log had already told us about.

    OR IGNORE against idx_visits_request_identity: nginx's $connection and
    $connection_requests number a request uniquely for the life of the process,
    so re-reading a stretch of log — a restored database beside a surviving
    file, a re-run with INGEST_EXISTING_BACKLOG — recognises what it has already
    stored instead of counting it twice. The index is partial, so a log without
    the field is inserted as before and nothing is deduplicated on a guess.
    """
    cur = conn.execute(
        """INSERT OR IGNORE INTO visits
              (ip, timestamp, method, path, server_port, status, bytes_sent,
               user_agent, referer, request_time, ssl_protocol,
               browser, os, device, accept_language,
               request_length, http_x_forwarded_for, ssl_cipher,
               connection, connection_requests, limit_req_status,
               http_version, sec_fetch_dest, sec_fetch_mode, sec_fetch_site,
               accept_encoding, ssl_session_reused)
           VALUES (?, ?, ?, ?, ?, ?, ?,
                   ?, ?, ?, ?,
                   ?, ?, ?, ?,
                   ?, ?, ?,
                   ?, ?, ?,
                   ?, ?, ?, ?,
                   ?, ?)""",
        (
            ip,
            timestamp,
            method,
            path,
            server_port,
            status,
            bytes_sent,
            user_agent,
            referer,
            request_time,
            ssl_protocol,
            browser,
            os,
            device,
            accept_language,
            request_length,
            http_x_forwarded_for,
            ssl_cipher,
            connection,
            connection_requests,
            limit_req_status,
            http_version,
            sec_fetch_dest,
            sec_fetch_mode,
            sec_fetch_site,
            accept_encoding,
            ssl_session_reused,
        ),
    )
    # rowcount, not lastrowid: an ignored duplicate leaves lastrowid pointing at
    # whatever this connection inserted last, which would report a row that was
    # never written.
    return cur.lastrowid if cur.rowcount else 0


def get_visits(
    conn: sqlite3.Connection,
    page: int = 1,
    limit: int = 50,
    sort: str = "timestamp",
    order: str = "DESC",
    ip_filter: str | None = None,
    country_filter: str | None = None,
) -> list[dict]:
    """Fetch paginated visits with optional IP/country filters. Joins ip_intel for geo data."""
    sort_col = VISIT_SORT_MAP.get(sort, "v.timestamp")
    order_dir = valid_order(order)
    offset = (page - 1) * limit

    query = """
        SELECT v.*, i.country, i.country_code, i.city, i.isp,
               i.is_proxy, i.is_hosting, i.is_mobile
        FROM visits v
        LEFT JOIN ip_intel i ON v.ip = i.ip
        WHERE 1=1
    """
    params: list = []
    query, params = _apply_visit_filters(query, params, ip_filter, country_filter)

    query += f" ORDER BY {sort_col} {order_dir} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def count_visits(
    conn: sqlite3.Connection,
    ip_filter: str | None = None,
    country_filter: str | None = None,
) -> int:
    """Count visits matching the given filters. Used for pagination totals."""
    query = """
        SELECT COUNT(*) FROM visits v
        LEFT JOIN ip_intel i ON v.ip = i.ip
        WHERE 1=1
    """
    params: list = []
    query, params = _apply_visit_filters(query, params, ip_filter, country_filter)
    row = conn.execute(query, params).fetchone()
    return row[0] if row else 0


def stream_visits_for_export(
    conn: sqlite3.Connection,
    from_date: str | None = None,
    to_date: str | None = None,
) -> Iterator[dict]:
    """Yield all visits (joined with ip_intel geo data) for export, newest first.

    Fetches in chunks of 1000 to avoid materializing the entire result set.
    Dates are inclusive YYYY-MM-DD bounds; to_date covers the full day.
    """
    query = """
        SELECT v.*, i.country, i.country_code, i.city, i.isp,
               i.is_proxy, i.is_hosting, i.is_mobile
        FROM visits v
        LEFT JOIN ip_intel i ON v.ip = i.ip
        WHERE 1=1
    """
    params: list = []
    if from_date:
        query += " AND v.timestamp >= ?"
        params.append(from_date)
    if to_date:
        query += " AND v.timestamp < date(substr(?, 1, 10), '+1 day')"
        params.append(to_date)
    query += " ORDER BY v.timestamp DESC"

    cursor = conn.execute(query, params)
    while True:
        rows = cursor.fetchmany(1000)
        if not rows:
            break
        for row in rows:
            yield dict(row)
