"""The SQL half of the monthly archive — reading a month out, putting one back.

The file half (zips, meta.json, pins) is src/archive.py, which owns no SQL.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable, Iterator

from ._shared import _assert_identifier, _shodan_agg_select
from .intel import set_visitor_class, upsert_ip_intel

# A month is the archive unit, and `timestamp` is an ISO-8601 string starting
# with YYYY-MM (nginx $time_iso8601), so substr(timestamp, 1, 7) *is* the month.
# No date parsing, and the index on timestamp still serves the LIKE prefix.


def get_visit_months(conn: sqlite3.Connection) -> list[dict]:
    """Every month present in visits, oldest first, with its row and IP counts."""
    return [
        dict(r)
        for r in conn.execute(
            """SELECT substr(timestamp, 1, 7) AS month,
                      COUNT(*)                AS visits,
                      COUNT(DISTINCT ip)      AS ips
               FROM visits
               GROUP BY month
               ORDER BY month"""
        ).fetchall()
    ]


def stream_visits_for_month(conn: sqlite3.Connection, month: str) -> Iterator[dict]:
    """Yield one month's visits verbatim, oldest first, in chunks of 1000.

    Deliberately `v.*` with no join: the archive has to restore to exactly what
    was here, and geo columns from ip_intel are carried separately (they belong
    to the IP, not to the visit).
    """
    cursor = conn.execute(
        "SELECT * FROM visits WHERE substr(timestamp, 1, 7) = ? ORDER BY id",
        (month,),
    )
    while True:
        rows = cursor.fetchmany(1000)
        if not rows:
            break
        for row in rows:
            yield dict(row)


def get_intel_for_month(conn: sqlite3.Connection, month: str) -> list[dict]:
    """ip_intel for every IP seen in `month`, Shodan children folded back in.

    An IP active across three months is stored in all three archives. That
    duplication is the point: each archive has to restore on its own.
    """
    return [
        dict(r)
        for r in conn.execute(
            """SELECT i.*, """
            + _shodan_agg_select("i.ip")
            + """
               FROM ip_intel i
               WHERE i.ip IN (
                   SELECT DISTINCT ip FROM visits WHERE substr(timestamp, 1, 7) = ?
               )
               ORDER BY i.ip""",
            (month,),
        ).fetchall()
    ]


def delete_visits_for_month(conn: sqlite3.Connection, month: str) -> int:
    """Delete one month's visits. Returns the number of deleted rows."""
    cur = conn.execute("DELETE FROM visits WHERE substr(timestamp, 1, 7) = ?", (month,))
    return cur.rowcount


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """Column names of `table`. Callers pass a hardcoded literal, never input."""
    _assert_identifier(table, "table name")
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def insert_archived_visits(conn: sqlite3.Connection, rows: Iterable[dict]) -> int:
    """Re-insert archived visits, original `id` included. Returns rows inserted.

    INSERT OR IGNORE on the primary key, so importing the same archive twice is
    a no-op rather than a duplicate month. Columns are intersected with the live
    table: an archive written before a column existed restores with that column's
    default, and one written after a column was dropped ignores it.
    """
    rows = list(rows)
    if not rows:
        return 0
    known = set(_table_columns(conn, "visits"))
    cols = [c for c in rows[0] if c in known]
    placeholders = ", ".join("?" for _ in cols)
    cur = conn.executemany(
        f"INSERT OR IGNORE INTO visits ({', '.join(cols)}) VALUES ({placeholders})",
        [tuple(r.get(c) for c in cols) for r in rows],
    )
    return cur.rowcount


def insert_missing_intel(conn: sqlite3.Connection, rows: Iterable[dict]) -> int:
    """Restore intel only for IPs that have none. Returns rows inserted.

    Never an upsert: the archive holds a snapshot from the month it was written,
    and an IP still active today has fresher geo, Tor and Shodan data in the live
    table. Restoring June must fill gaps, not roll August back.
    """
    inserted = 0
    for row in rows:
        ip = row.get("ip")
        if not ip:
            continue
        if conn.execute("SELECT 1 FROM ip_intel WHERE ip = ?", (ip,)).fetchone():
            continue
        upsert_ip_intel(conn, row)  # also writes the Shodan child tables
        if row.get("visitor_class"):
            set_visitor_class(conn, ip, row["visitor_class"])
        inserted += 1
    return inserted


def purge_orphaned_intel(conn: sqlite3.Connection) -> int:
    """Delete ip_intel entries with no remaining visits. Returns deleted count."""
    cur = conn.execute(
        """DELETE FROM ip_intel
           WHERE ip NOT IN (SELECT DISTINCT ip FROM visits)"""
    )
    return cur.rowcount
