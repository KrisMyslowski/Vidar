"""SQLite database infrastructure — schema, migrations, and connection management.

Three responsibilities, kept intentionally separate from query logic (see queries.py):
  Schema      — DDL for visits, ip_intel, processor_state tables and indexes
  Migrations  — idempotent ALTER TABLE helpers for columns added after v1
  Connections — get_conn() context manager, init_db(), vacuum()
"""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .config import settings

_DB_PATH: Path = settings.db_path

# ── Schema ───────────────────────────────────────────────────────────────────

SCHEMA = """
-- Visit records: one row per HTTP request
CREATE TABLE IF NOT EXISTS visits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL,
    method          TEXT,
    path            TEXT,
    server_port     INTEGER DEFAULT 0,
    status          INTEGER,
    bytes_sent      INTEGER,
    user_agent      TEXT,
    referer         TEXT,
    request_time    REAL,
    ssl_protocol    TEXT,
    browser         TEXT    DEFAULT '',
    os              TEXT    DEFAULT '',
    device          TEXT    DEFAULT '',
    accept_language       TEXT    DEFAULT '',
    request_length        INTEGER DEFAULT 0,
    http_x_forwarded_for  TEXT    DEFAULT '',
    ssl_cipher            TEXT    DEFAULT '',
    connection            INTEGER DEFAULT 0,
    connection_requests   INTEGER DEFAULT 0,
    limit_req_status      TEXT    DEFAULT '',
    http_version          TEXT    DEFAULT '',
    sec_fetch_dest        TEXT    DEFAULT '',
    sec_fetch_mode        TEXT    DEFAULT '',
    sec_fetch_site        TEXT    DEFAULT '',
    accept_encoding       TEXT    DEFAULT '',
    ssl_session_reused    TEXT    DEFAULT '',
    created_at            TEXT    DEFAULT CURRENT_TIMESTAMP
);

-- Cached geo/threat intelligence per IP (from ip-api.com + Shodan InternetDB)
CREATE TABLE IF NOT EXISTS ip_intel (
    ip              TEXT    PRIMARY KEY,
    country         TEXT,
    country_code    TEXT,
    city            TEXT,
    lat             REAL,
    lon             REAL,
    isp             TEXT,
    org             TEXT,
    asn             TEXT,
    is_proxy        INTEGER DEFAULT 0,
    is_hosting      INTEGER DEFAULT 0,
    is_mobile       INTEGER DEFAULT 0,
    reverse_dns     TEXT    DEFAULT '',
    is_tor          INTEGER DEFAULT 0,
    dnsbl_listed    INTEGER DEFAULT 0,
    dnsbl_sources   TEXT    DEFAULT '',
    fetched_at      TEXT,
    visitor_class   TEXT    DEFAULT '',
    -- When the class was last derived, and the newest visit it was derived from.
    -- A class summarises an IP's whole history, so later visits can invalidate it;
    -- reclassify_stale_ips() compares the id against visits.id to find the labels
    -- that need a second look. The id rather than the timestamp because CURRENT_TIMESTAMP
    -- only has second resolution — a visit landing in the same second as the
    -- classification would never be seen.
    classified_at        TEXT,
    classified_visit_id  INTEGER DEFAULT 0,
    -- When a PTR lookup was last attempted. Separate from reverse_dns being empty:
    -- most IPs simply have no PTR record, and without this they would be retried forever.
    rdns_checked_at      TEXT
);

-- Tracks log file read position to survive container restarts
CREATE TABLE IF NOT EXISTS processor_state (
    key     TEXT PRIMARY KEY,
    value   TEXT
);

-- Per-IP /api/export hits — persisted so the rate limit survives container restarts
CREATE TABLE IF NOT EXISTS rate_limits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip   TEXT NOT NULL,
    hit_at      REAL NOT NULL
);

-- Normalized Shodan multi-value fields (one row per value), enabling per-value
-- filtering ("all hosts with port 22 / CVE-X / tag scanner"). These are the sole
-- store for the multi-value data; upsert_ip_intel writes them via _sync_shodan_children.
CREATE TABLE IF NOT EXISTS ip_intel_ports (
    ip   TEXT NOT NULL,
    port INTEGER NOT NULL,
    PRIMARY KEY (ip, port),
    FOREIGN KEY (ip) REFERENCES ip_intel(ip) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ip_intel_vulns (
    ip   TEXT NOT NULL,
    vuln TEXT NOT NULL,
    PRIMARY KEY (ip, vuln),
    FOREIGN KEY (ip) REFERENCES ip_intel(ip) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ip_intel_cpes (
    ip  TEXT NOT NULL,
    cpe TEXT NOT NULL,
    PRIMARY KEY (ip, cpe),
    FOREIGN KEY (ip) REFERENCES ip_intel(ip) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ip_intel_tags (
    ip  TEXT NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (ip, tag),
    FOREIGN KEY (ip) REFERENCES ip_intel(ip) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ip_intel_hostnames (
    ip       TEXT NOT NULL,
    hostname TEXT NOT NULL,
    PRIMARY KEY (ip, hostname),
    FOREIGN KEY (ip) REFERENCES ip_intel(ip) ON DELETE CASCADE
);
"""


# Indexes are applied *after* the column migrations in init_db(), never with the
# tables. CREATE TABLE IF NOT EXISTS is a no-op on a database that already has
# the table, so an index over a column that arrives by migration referred to a
# column that did not exist yet — `idx_ip_intel_visitor_class` made init_db()
# raise "no such column: visitor_class" on any database predating that column,
# at startup, before anything else could run. Tables, then columns, then indexes.
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_visits_ip_timestamp ON visits(ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_visits_timestamp ON visits(timestamp);
-- (timestamp, ip), not the (ip, timestamp) above: the dashboard's aggregates
-- all filter by window and then group by ip, and this order lets SQLite answer
-- them from the index alone. Without it, a windowed COUNT(DISTINCT ip) /
-- bounce / top-IPs trio costs 218 ms over 184k visits; with it, 94 ms. The
-- unwindowed path never needed it — it just scans the table.
CREATE INDEX IF NOT EXISTS idx_visits_timestamp_ip ON visits(timestamp, ip);
CREATE INDEX IF NOT EXISTS idx_visits_status_path ON visits(status, path);
-- The one thing that can tell a re-read of the log from real traffic.
-- $time_iso8601 resolves to the second, so (time, ip, request) cannot: two
-- identical requests in one second are indistinguishable from one request
-- ingested twice, and a unique constraint over those would silently drop
-- genuine visits. nginx's $connection with $connection_requests numbers a
-- request uniquely for the life of the process, which is the missing part.
--
-- Partial, on purpose. Rows written before this field existed carry
-- connection = 0, and so does anything logged with the older format; without
-- the WHERE they would all collide on (timestamp, 0, 0) and every visit after
-- the first in a given second would be dropped. Deduplication applies exactly
-- where the log actually provides an identity.
CREATE UNIQUE INDEX IF NOT EXISTS idx_visits_request_identity
    ON visits(timestamp, connection, connection_requests) WHERE connection > 0;
CREATE INDEX IF NOT EXISTS idx_ip_intel_fetched ON ip_intel(fetched_at);
CREATE INDEX IF NOT EXISTS idx_ip_intel_visitor_class ON ip_intel(visitor_class);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_time ON rate_limits(client_ip, hit_at);
CREATE INDEX IF NOT EXISTS idx_ip_intel_ports_port ON ip_intel_ports(port);
CREATE INDEX IF NOT EXISTS idx_ip_intel_vulns_vuln ON ip_intel_vulns(vuln);
CREATE INDEX IF NOT EXISTS idx_ip_intel_cpes_cpe ON ip_intel_cpes(cpe);
CREATE INDEX IF NOT EXISTS idx_ip_intel_tags_tag ON ip_intel_tags(tag);
CREATE INDEX IF NOT EXISTS idx_ip_intel_hostnames_hostname ON ip_intel_hostnames(hostname);
"""


# ── Migration helpers ────────────────────────────────────────────────────────

_ALLOWED_MIGRATION_TABLES = frozenset({"visits", "ip_intel"})


def _intel_cols(conn: sqlite3.Connection) -> set[str]:
    return {r[1] for r in conn.execute("PRAGMA table_info(ip_intel)").fetchall()}


def _add_col_if_missing(conn: sqlite3.Connection, table: str, col: str, typedef: str) -> None:
    """Add a column to `table` only if it doesn't exist yet (idempotent migration helper).

    `table` and `col` are interpolated into SQL — only hardcoded migration literals should
    ever be passed here, and the checks below enforce that at the call site.

    They raise rather than assert: `python -O` strips assertions, and these are
    the only thing standing between this f-string and an arbitrary identifier.
    A guard that disappears under a runtime flag is not a guard.
    """
    if table not in _ALLOWED_MIGRATION_TABLES:
        raise ValueError(f"unknown migration table: {table!r}")
    if not col.isidentifier():
        raise ValueError(f"invalid column name: {col!r}")
    # Derived from the allowlisted table name, so a third table needs no third
    # branch — the old if/elif left `cols` unbound for anything it did not know.
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if col not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")


def _backfill_shodan_children(conn: sqlite3.Connection) -> None:
    """Populate the normalized Shodan child tables from the legacy CSV columns (4.3).

    One-time migration; idempotent via INSERT OR IGNORE. Ports that aren't integers are
    skipped. Runtime sync afterwards is handled by queries.upsert_ip_intel.

    Rows are read in chunks rather than fetchall()'d: this runs against every
    ip_intel row of a database old enough to still have the CSV columns, and the
    one thing it must not do is need the whole table at once on the box it is
    upgrading. The SELECT is on ip_intel and the writes go to the child tables,
    so the open cursor is never reading a table these inserts change.
    """
    cursor = conn.execute("SELECT ip, open_ports, vulns, cpes, tags, hostnames FROM ip_intel")
    while True:
        chunk = cursor.fetchmany(1000)
        if not chunk:
            break
        _backfill_chunk(conn, chunk)


def _backfill_chunk(conn: sqlite3.Connection, chunk) -> None:
    def _split(s: str) -> list[str]:
        return [x.strip() for x in (s or "").split(",") if x.strip()]

    for ip, open_ports, vulns, cpes, tags, hostnames in chunk:
        for p in _split(open_ports):
            if p.isdigit():
                conn.execute(
                    "INSERT OR IGNORE INTO ip_intel_ports(ip, port) VALUES (?, ?)", (ip, int(p))
                )
        for v in _split(vulns):
            conn.execute("INSERT OR IGNORE INTO ip_intel_vulns(ip, vuln) VALUES (?, ?)", (ip, v))
        for c in _split(cpes):
            conn.execute("INSERT OR IGNORE INTO ip_intel_cpes(ip, cpe) VALUES (?, ?)", (ip, c))
        for t in _split(tags):
            conn.execute("INSERT OR IGNORE INTO ip_intel_tags(ip, tag) VALUES (?, ?)", (ip, t))
        for h in _split(hostnames):
            conn.execute(
                "INSERT OR IGNORE INTO ip_intel_hostnames(ip, hostname) VALUES (?, ?)", (ip, h)
            )


# ── Connections ──────────────────────────────────────────────────────────────


def _connect(path: Path) -> sqlite3.Connection:
    """Raw connection helper (no context manager). Used by init_db.

    Note what is deliberately absent: foreign_keys. Nothing here relies on the
    ON DELETE CASCADE that get_conn() enables, and the schema work below runs
    before any of it matters — but a caller that mistook this for get_conn()
    would delete an ip_intel row and leave its five children behind.
    """
    conn = sqlite3.connect(str(path), timeout=settings.db_connection_timeout)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA busy_timeout={int(settings.db_connection_timeout * 1000)}")
    except Exception:
        conn.close()
        raise
    return conn


def init_db(db_path: Path | None = None) -> None:
    """Create tables and indexes. Runs migrations for columns added after v1."""
    path = db_path or _DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(path)
    try:
        conn.executescript(SCHEMA)

        # Migration: visits columns added across versions
        for col, typedef in [
            ("server_port", "INTEGER DEFAULT 0"),
            ("browser", "TEXT DEFAULT ''"),
            ("os", "TEXT DEFAULT ''"),
            ("device", "TEXT DEFAULT ''"),
            ("accept_language", "TEXT DEFAULT ''"),
            ("request_length", "INTEGER DEFAULT 0"),
            ("http_x_forwarded_for", "TEXT DEFAULT ''"),
            ("ssl_cipher", "TEXT DEFAULT ''"),
            ("connection", "INTEGER DEFAULT 0"),
            ("connection_requests", "INTEGER DEFAULT 0"),
            ("limit_req_status", "TEXT DEFAULT ''"),
            ("http_version", "TEXT DEFAULT ''"),
            ("sec_fetch_dest", "TEXT DEFAULT ''"),
            ("sec_fetch_mode", "TEXT DEFAULT ''"),
            ("sec_fetch_site", "TEXT DEFAULT ''"),
            ("accept_encoding", "TEXT DEFAULT ''"),
            ("ssl_session_reused", "TEXT DEFAULT ''"),
            # In SCHEMA since the first version but never in this list, so a
            # database older than it never received the column at all. Added
            # without the DEFAULT CURRENT_TIMESTAMP the schema gives it: SQLite
            # rejects a non-constant default in ADD COLUMN, so on a migrated
            # database the column exists and stays NULL, while a freshly created
            # one fills it. Nothing reads created_at, so that divergence costs
            # nothing today — but anything that starts reading it has to treat
            # NULL as "unknown" rather than assume every row carries a value.
            ("created_at", "TEXT"),
        ]:
            _add_col_if_missing(conn, "visits", col, typedef)

        # Migration: ip_intel columns added across versions. The multi-value Shodan
        # fields (open_ports/tags/hostnames/cpes/vulns) are intentionally NOT here — they
        # were normalized into ip_intel_* child tables (4.3) and the legacy columns are
        # dropped below.
        for col, typedef in [
            ("reverse_dns", "TEXT DEFAULT ''"),
            ("is_tor", "INTEGER DEFAULT 0"),
            ("dnsbl_listed", "INTEGER DEFAULT 0"),
            ("dnsbl_sources", "TEXT DEFAULT ''"),
            ("visitor_class", "TEXT DEFAULT ''"),
            ("classified_at", "TEXT"),
            ("classified_visit_id", "INTEGER DEFAULT 0"),
            ("rdns_checked_at", "TEXT"),
        ]:
            _add_col_if_missing(conn, "ip_intel", col, typedef)

        # idx_visits_ip is superseded by the (ip, timestamp) composite — drop the
        # redundant single-column index on existing databases.
        conn.execute("DROP INDEX IF EXISTS idx_visits_ip")

        # The partial scanner index (status IN (404,403,405)) served get_scanner_paths,
        # which was merged into get_paths with generic status ranges — the range
        # predicate can't use a partial index, so the full (status, path) one replaces it.
        conn.execute("DROP INDEX IF EXISTS idx_visits_status_scan")

        # 4.3 Phase B: migrate the legacy Shodan CSV columns to the child tables, then
        # drop them. On an already-migrated or fresh DB the columns are absent and this is
        # a no-op. Backfill runs only if the child tables are still empty. (DROP COLUMN
        # needs SQLite >= 3.35, satisfied by the runtime in the deploy image.)
        legacy_csv = [
            c
            for c in ("open_ports", "tags", "hostnames", "cpes", "vulns")
            if c in _intel_cols(conn)
        ]
        if legacy_csv:
            # Unconditionally, where it used to run only when ip_intel_ports was
            # empty. That check was a proxy for "the backfill has not run", and
            # a bad one: anything else that puts a row in that table — a runtime
            # upsert between one init_db() and the next, and retention calls
            # init_db() daily — made it read "already done" and the columns were
            # dropped with their contents unread. The backfill is idempotent by
            # construction (INSERT OR IGNORE), so the proxy bought nothing but
            # the failure mode.
            _backfill_shodan_children(conn)
            for col in legacy_csv:
                conn.execute(f"ALTER TABLE ip_intel DROP COLUMN {col}")

        # Last, once every column an index names is guaranteed to exist.
        conn.executescript(INDEXES)

        conn.commit()
    finally:
        conn.close()


async def run_db(work, *args):
    """Run blocking database work in a thread, and finish it even if cancelled.

    asyncio.to_thread cannot cancel the thread it starts — cancelling the task
    only stops the *waiting*. The write then lands after the task is gone, which
    is how a cancelled log tailer commits a batch and a read position behind its
    own back: at shutdown, after "Shutting down" is logged; in tests, into
    whichever database the next test has just pointed _DB_PATH at.

    Shielding the work and awaiting it on the way out costs a moment of shutdown
    and makes cancellation mean what it says. Read-only work does not need this
    (see routes/_cache.fetch), because nothing outlives it.
    """
    task = asyncio.ensure_future(asyncio.to_thread(work, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.wait({task})
        raise


@contextmanager
def get_conn(db_path: Path | None = None):
    """Yield a SQLite connection with WAL mode and foreign keys.

    Everything after connect() is inside the try: a PRAGMA can fail — a lock
    held elsewhere, a read-only mount, a full disk — and the connection was
    built before it, so a failure there leaked a live handle with no close().
    """
    path = db_path or _DB_PATH
    conn = sqlite3.connect(str(path), timeout=settings.db_connection_timeout)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # sqlite3.connect(timeout=…) already sets this; stating it keeps the
        # value visible next to the others. It used to be a hardcoded 5000,
        # which silently overrode DB_CONNECTION_TIMEOUT everywhere but vacuum()
        # and made that setting dead config.
        conn.execute(f"PRAGMA busy_timeout={int(settings.db_connection_timeout * 1000)}")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def vacuum(db_path: Path | None = None) -> None:
    """Run VACUUM to reclaim disk space. Requires its own connection (not in transaction)."""
    path = db_path or _DB_PATH
    conn = sqlite3.connect(str(path), timeout=settings.db_connection_timeout)
    try:
        conn.execute("VACUUM")
    finally:
        conn.close()
