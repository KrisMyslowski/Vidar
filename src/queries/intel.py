"""The ip_intel cache: enrichment CRUD, the Shodan child tables, and the writes
that record a classification.

Deciding *what* an IP is lives in src/classifier/; writing that verdict back is
SQL and lives here. Also holds the two small key-value tables — processor_state
(the tailer's file offset) and rate_limits (per-IP /api/export hits).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from ..classifier import classify_ip
from ._shared import SHODAN_CHILDREN

# The rules, the needles and the evidence query moved to their own package:
# 850 lines of domain logic in the middle of a SQL module. What stays here is
# what is still SQL — writing a class back to ip_intel, and finding the rows
# that need one.


# A class is derived from an IP's whole history, so it goes stale as soon as the IP
# does something new. We record both when we looked and how far we had seen — the
# visit id, because CURRENT_TIMESTAMP only resolves to the second and a visit landing
# in that same second would look older than the classification.
_SET_CLASS_SQL = """
    UPDATE ip_intel
       SET visitor_class = ?,
           classified_at = CURRENT_TIMESTAMP,
           classified_visit_id = COALESCE(
               (SELECT MAX(v.id) FROM visits v WHERE v.ip = ip_intel.ip), 0)
     WHERE ip = ?
"""


def set_visitor_class(conn: sqlite3.Connection, ip: str, label: str) -> None:
    """Write the visitor_class label for an IP into ip_intel."""
    conn.execute(_SET_CLASS_SQL, (label, ip))


def backfill_visitor_classes(conn: sqlite3.Connection) -> int:
    """Classify all ip_intel rows that have no visitor_class yet. Returns count updated."""
    rows = conn.execute(
        "SELECT ip FROM ip_intel WHERE visitor_class = '' OR visitor_class IS NULL"
    ).fetchall()
    updates = [(classify_ip(conn, ip), ip) for (ip,) in rows]
    if updates:
        conn.executemany(_SET_CLASS_SQL, updates)
    return len(updates)


def reclassify_stale_ips(conn: sqlite3.Connection, limit: int = 5_000) -> int:
    """Re-classify IPs that have been active since they were last classified.

    Without this a label is written once, at enrichment time, and never revisited — so
    an IP first seen fetching one page keeps that verdict after it starts probing.
    Returns the number of IPs whose label actually changed.
    """
    rows = conn.execute(
        """
        SELECT i.ip, i.visitor_class
        FROM ip_intel i
        WHERE i.classified_at IS NULL
           OR EXISTS (SELECT 1 FROM visits v
                      WHERE v.ip = i.ip
                        AND v.id > COALESCE(i.classified_visit_id, 0))
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    # Stamp every row we looked at, changed or not — otherwise an IP whose class is
    # stable would be re-examined on every pass forever.
    updates = [(classify_ip(conn, ip), ip, old) for ip, old in rows]
    if updates:
        conn.executemany(_SET_CLASS_SQL, [(label, ip) for label, ip, _ in updates])
    return sum(1 for label, _, old in updates if label != old)


def get_ips_without_rdns(conn: sqlite3.Connection, limit: int = 500) -> list[str]:
    """Enriched IPs that have never had a PTR lookup attempted.

    reverse_dns arrived from Shodan's `hostnames` only, which covers hosts Shodan has
    scanned — 14.5% of ours — leaving the classifier's crawler-verification rules with
    nothing to check a Googlebot claim against.
    """
    rows = conn.execute(
        "SELECT ip FROM ip_intel WHERE rdns_checked_at IS NULL LIMIT ?", (limit,)
    ).fetchall()
    return [r[0] for r in rows]


def set_reverse_dns(conn: sqlite3.Connection, ip: str, hostname: str) -> None:
    """Record a PTR result. Stamps the attempt even when there is no record, so an IP
    without reverse DNS is not retried forever."""
    conn.execute(
        """UPDATE ip_intel
              SET reverse_dns = CASE WHEN ? != '' THEN ? ELSE reverse_dns END,
                  rdns_checked_at = CURRENT_TIMESTAMP
            WHERE ip = ?""",
        (hostname, hostname, ip),
    )


def force_reclassify_all(conn: sqlite3.Connection) -> int:
    """Re-run classify_ip for EVERY ip_intel row (not just empty ones). Returns count.

    Use after a classifier logic change: backfill_visitor_classes() only touches empty
    classes, so it would leave already-labeled IPs on the old logic.
    """
    rows = conn.execute("SELECT ip FROM ip_intel").fetchall()
    updates = [(classify_ip(conn, ip), ip) for (ip,) in rows]
    if updates:
        conn.executemany(_SET_CLASS_SQL, updates)
    return len(updates)


def get_ip_intel(conn: sqlite3.Connection, ip: str) -> dict | None:
    """Fetch cached enrichment data for an IP. Returns None if not cached."""
    row = conn.execute("SELECT * FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def get_ip_intel_bulk(conn: sqlite3.Connection, ips: list[str]) -> dict[str, dict | None]:
    """Fetch cached enrichment data for multiple IPs in a single query.
    Returns a dict mapping IP -> enrichment dict or None if not cached."""
    if not ips:
        return {}
    placeholders = ",".join("?" * len(ips))
    rows = conn.execute(f"SELECT * FROM ip_intel WHERE ip IN ({placeholders})", ips).fetchall()
    result = {ip: None for ip in ips}
    for row in rows:
        result[row["ip"]] = dict(row)
    return result


# The columns an enrichment round may write, with the value a brand-new row gets
# when nobody answered for that column. Names are literals from this tuple and
# never come from the caller, so the SQL built below stays parameterised in the
# values and fixed in the identifiers.
_INTEL_COLUMNS: tuple[tuple[str, object], ...] = (
    ("country", ""),
    ("country_code", ""),
    ("city", ""),
    ("lat", 0),
    ("lon", 0),
    ("isp", ""),
    ("org", ""),
    ("asn", ""),
    ("is_proxy", 0),
    ("is_hosting", 0),
    ("is_mobile", 0),
    ("reverse_dns", ""),
    ("is_tor", 0),
    ("dnsbl_listed", 0),
    ("dnsbl_sources", ""),
)
_INTEL_BOOL_COLUMNS = frozenset({"is_proxy", "is_hosting", "is_mobile", "is_tor", "dnsbl_listed"})


def upsert_ip_intel(conn: sqlite3.Connection, data: dict) -> None:
    """Insert or update IP intelligence, touching only the columns `data` carries.

    The five sources fail independently: Shodan can time out while ip-api
    answers, the Tor list can be unreachable while both work. This used to fill
    every missing key with its default and write it anyway, which turned a
    provider outage into a recorded fact — is_tor=0 over a confirmed exit node,
    dnsbl_listed=0 over a real hit, a verified PTR replaced by "". A key that is
    absent means nobody answered, and the stored value stays.

    On INSERT the defaults are used, because a new row has nothing to preserve.
    fetched_at always moves: the IP was looked at, whatever came back of it.
    """
    columns = ["ip"] + [col for col, _ in _INTEL_COLUMNS] + ["fetched_at"]
    values: list[object] = [data["ip"]]
    for col, default in _INTEL_COLUMNS:
        raw = data.get(col, default)
        values.append(int(raw) if col in _INTEL_BOOL_COLUMNS else raw)
    # Use `or` so that an explicit None in the dict still gets a real timestamp
    values.append(data.get("fetched_at") or datetime.now(timezone.utc).isoformat())

    answered = [col for col, _ in _INTEL_COLUMNS if col in data] + ["fetched_at"]
    conn.execute(
        f"""INSERT INTO ip_intel ({", ".join(columns)})
            VALUES ({",".join("?" * len(columns))})
            ON CONFLICT(ip) DO UPDATE SET
            {", ".join(f"{col}=excluded.{col}" for col in answered)}""",
        values,
    )
    # Multi-value Shodan fields live only in the child tables (4.3).
    _sync_shodan_children(conn, data)


def _csv_values(raw) -> list[str]:
    """Split a comma-separated string (or pass through a list) into trimmed values."""
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def _sync_shodan_children(conn: sqlite3.Connection, data: dict) -> None:
    """Mirror the Shodan CSV fields into the normalized child tables (4.3).

    Delete-then-insert per IP so values that disappear on re-enrichment (a closed port,
    a patched CVE) are removed. Table/column names are hardcoded literals only.

    A table whose source key is absent from `data` is left untouched. The delete
    is right for "Shodan answered and that port is gone" and catastrophic for
    "Shodan did not answer" — and until the caller learned to tell those apart,
    one timed-out lookup erased every port, CVE, CPE, tag and hostname for the IP.
    """
    ip = data["ip"]
    # Which tables exist and what each one's value column is called comes from
    # SHODAN_CHILDREN, so a sixth child table is added in one place. Only ports
    # need their own reading: they are stored as integers, and anything
    # non-numeric on the way in is dropped rather than written as text.
    children = [
        (
            table,
            col,
            (
                [int(p) for p in _csv_values(data.get(name)) if str(p).isdigit()]
                if col == "port"
                else _csv_values(data.get(name))
            ),
        )
        for table, col, name in SHODAN_CHILDREN
        if name in data
    ]
    for table, col, values in children:
        conn.execute(f"DELETE FROM {table} WHERE ip = ?", (ip,))
        if values:
            conn.executemany(
                f"INSERT OR IGNORE INTO {table}(ip, {col}) VALUES (?, ?)",
                [(ip, v) for v in values],
            )


def mark_enrichment_failed(conn: sqlite3.Connection, ip: str, fetched_at: str) -> None:
    """Record a permanent ip-api failure (invalid/reserved IP) as a stub ip_intel row.

    Without this, get_unenriched_ips() would return the same failing IPs every cycle and
    burn the rate-limited API quota. The stub counts as enriched until the staleness TTL
    expires; on an existing row only fetched_at is bumped, so data from an earlier
    successful enrichment is never overwritten by a failure.
    """
    conn.execute(
        """INSERT INTO ip_intel (ip, fetched_at) VALUES (?, ?)
           ON CONFLICT(ip) DO UPDATE SET fetched_at=excluded.fetched_at""",
        (ip, fetched_at),
    )


def get_unenriched_ips(conn: sqlite3.Connection, limit: int = 100) -> list[str]:
    """IPs in visits that have no ip_intel entry."""
    rows = conn.execute(
        """SELECT DISTINCT v.ip FROM visits v
           LEFT JOIN ip_intel i ON v.ip = i.ip
           WHERE i.ip IS NULL
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [r[0] for r in rows]


def get_stale_ips(conn: sqlite3.Connection, ttl_days: int, limit: int = 100) -> list[str]:
    """IPs whose enrichment data is older than ttl_days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=ttl_days)).isoformat()
    rows = conn.execute(
        "SELECT ip FROM ip_intel WHERE fetched_at < ? LIMIT ?",
        (cutoff, limit),
    ).fetchall()
    return [r[0] for r in rows]


def count_unenriched_ips(conn: sqlite3.Connection) -> int:
    """How many IPs are waiting for a first enrichment.

    Same condition as get_unenriched_ips() without the LIMIT: that one feeds a
    batch, this one answers "how far behind is the worker" for /settings/status.
    """
    return conn.execute(
        """SELECT COUNT(DISTINCT v.ip) FROM visits v
           LEFT JOIN ip_intel i ON v.ip = i.ip
           WHERE i.ip IS NULL"""
    ).fetchone()[0]


def count_stale_ips(conn: sqlite3.Connection, ttl_days: int) -> int:
    """How many enriched IPs are older than the cache TTL."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=ttl_days)).isoformat()
    return conn.execute(
        "SELECT COUNT(*) FROM ip_intel WHERE fetched_at < ?", (cutoff,)
    ).fetchone()[0]


def get_state(conn: sqlite3.Connection, key: str) -> str | None:
    """Read a processor_state value (e.g. file_offset, file_inode)."""
    row = conn.execute("SELECT value FROM processor_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Write a processor_state value. Creates or updates the key."""
    conn.execute(
        """INSERT INTO processor_state (key, value) VALUES (?, ?)
           ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
        (key, value),
    )


def delete_state(conn: sqlite3.Connection, key: str) -> None:
    """Remove a processor_state key. Absent and blank read the same to callers,
    but only removal stops the table growing by a row per event."""
    conn.execute("DELETE FROM processor_state WHERE key = ?", (key,))


def count_export_hits(conn: sqlite3.Connection, client_ip: str, window_s: int, now: float) -> int:
    """Number of export hits by `client_ip` within the last `window_s` seconds."""
    row = conn.execute(
        "SELECT COUNT(*) FROM rate_limits WHERE client_ip = ? AND hit_at > ?",
        (client_ip, now - window_s),
    ).fetchone()
    return row[0] if row else 0


def record_export_hit(conn: sqlite3.Connection, client_ip: str, now: float) -> None:
    """Record one export hit for `client_ip` at time `now` (unix epoch seconds)."""
    conn.execute("INSERT INTO rate_limits (client_ip, hit_at) VALUES (?, ?)", (client_ip, now))


def purge_old_rate_limits(conn: sqlite3.Connection, window_s: int, now: float) -> int:
    """Delete rate-limit hits older than the window. Returns rows removed."""
    cur = conn.execute("DELETE FROM rate_limits WHERE hit_at <= ?", (now - window_s,))
    return cur.rowcount
