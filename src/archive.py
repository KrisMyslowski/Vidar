"""Monthly archives — the file half of retention.

A month that falls out of the active window is written to
`<archive_dir>/YYYY-MM.zip` and only then removed from the database. The zip
holds three members:

    meta.json       month, created_at, counts, first/last timestamp, schema
    visits.jsonl    one JSON object per visit, original `id` included
    ip_intel.jsonl  intel for the IPs of that month, Shodan values as arrays

JSONL rather than CSV because a restore has to land the same values it took:
CSV turns every column into a string and loses NULL, and the Shodan multi-value
fields would have to be re-parsed. Zip rather than one gzip stream because the
settings page lists archives by reading `meta.json` alone, without inflating the
visits of every month it shows.

No SQL lives here — queries.py owns that, as everywhere else in this codebase.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import settings
from .queries import (
    delete_state,
    delete_visits_for_month,
    get_intel_for_month,
    get_state,
    get_visit_months,
    insert_archived_visits,
    insert_missing_intel,
    purge_orphaned_intel,
    set_state,
    stream_visits_for_month,
)
from .validators import valid_month

logger = logging.getLogger("vidar.archive")

# Bumped when the member layout changes. Written into meta.json so a future
# reader can tell what it is holding before it tries to restore it.
SCHEMA_VERSION = 1

META = "meta.json"
VISITS = "visits.jsonl"
INTEL = "ip_intel.jsonl"

_PIN_PREFIX = "archive.pin."
MODE_ROLLING = "rolling"
MODE_LIFETIME = "lifetime"
# processor_state key holding when the daily pass last completed. Lives here
# with the other state keys; retention.py writes it, the settings page reads it.
LAST_RUN_KEY = "retention.last_run"
ROLLING_MONTHS_KEY = "retention.rolling_months"
DEFAULT_ROLLING_MONTHS = 2
# 0 keeps the current month only; the ceiling stops a typo turning the rolling
# mode into lifetime by accident.
MAX_ROLLING_MONTHS = 24
# How long a zip survives after the month it holds. Separate from the rolling
# window on purpose: that one says what is in the database, this one says how
# long the file beside it lives. Archiving is not deletion, and a single
# "retention" number would have to mean both.
ARCHIVE_KEEP_KEY = "retention.archive_keep_months"
# The default keeps every archive, so an update never removes data an operator
# did not ask it to remove.
ARCHIVE_KEEP_FOREVER = 0
MAX_ARCHIVE_KEEP_MONTHS = 120
# The Shodan columns are aggregated strings on read and lists on write; they
# travel as lists so a restore does not depend on the aggregation separator.
_INTEL_LIST_FIELDS = ("open_ports", "tags", "vulns", "cpes", "hostnames")


# ── Window ───────────────────────────────────────────────────────────────────


def get_rolling_months(conn: sqlite3.Connection) -> int:
    """How many months before the current one stay active. Default 2."""
    raw = get_state(conn, ROLLING_MONTHS_KEY)
    try:
        return min(max(int(raw), 0), MAX_ROLLING_MONTHS)
    except (TypeError, ValueError):
        return DEFAULT_ROLLING_MONTHS


def set_rolling_months(conn: sqlite3.Connection, months: int) -> int:
    """Store the window size, clamped to 0..MAX. Returns what was stored."""
    months = min(max(int(months), 0), MAX_ROLLING_MONTHS)
    set_state(conn, ROLLING_MONTHS_KEY, str(months))
    return months


def get_archive_keep_months(conn: sqlite3.Connection) -> int:
    """Months an archive is kept after its own month. 0 means keep forever."""
    raw = get_state(conn, ARCHIVE_KEEP_KEY)
    try:
        return min(max(int(raw), 0), MAX_ARCHIVE_KEEP_MONTHS)
    except (TypeError, ValueError):
        return ARCHIVE_KEEP_FOREVER


def set_archive_keep_months(conn: sqlite3.Connection, months: int) -> int:
    """Store the archive window, clamped. Returns what was stored, which may differ.

    Two clamps. The ceiling is the same guard as MAX_ROLLING_MONTHS: a typo must
    not turn a window into an eternity.

    The floor is the interesting one. A month is archived once it is older than
    the rolling window, so it reaches the zip at age `rolling + 1`. Anything
    shorter than that would have the same nightly pass write a file and delete it
    again, which is not a configuration — it is a way of saying "do not archive"
    while paying for the zip. Below the floor the value is raised to it, and the
    caller shows what was actually stored.
    """
    months = min(max(int(months), 0), MAX_ARCHIVE_KEEP_MONTHS)
    if months != ARCHIVE_KEEP_FOREVER:
        months = max(months, get_rolling_months(conn) + 1)
    set_state(conn, ARCHIVE_KEEP_KEY, str(months))
    return months


def expired_archives(conn: sqlite3.Connection, today: datetime) -> list[str]:
    """Archives past the keep window, oldest first. Empty when keeping forever.

    Age is counted from the month the archive *names*, never from the file's
    mtime: a data directory that was copied or restored once carries fresh
    timestamps on years-old zips, and mtime would then keep everything or drop
    everything depending on how it was moved.

    Pinned months are skipped for the same reason due_months() skips them — a
    month someone re-imported on purpose is in use, and deleting the file under
    them would take away the thing they came back for.
    """
    keep = get_archive_keep_months(conn)
    if keep == ARCHIVE_KEEP_FOREVER:
        return []
    cutoff = window_start_month(today, keep)
    return sorted(
        a["month"]
        for a in list_archives(conn)
        if a["month"] < cutoff and not pin_expiry(conn, a["month"])
    )


def window_start(today: datetime, months: int = DEFAULT_ROLLING_MONTHS) -> datetime:
    """First day of the oldest month still active: current month minus `months`.

    Month arithmetic on a running index, so it crosses the year without a
    special case. Whole calendar months, not a fixed day count.
    """
    month_index = today.year * 12 + (today.month - 1) - months
    return datetime(month_index // 12, month_index % 12 + 1, 1, tzinfo=timezone.utc)


def window_start_month(today: datetime, months: int = DEFAULT_ROLLING_MONTHS) -> str:
    """The window start as YYYY-MM, which is what months compare against."""
    return window_start(today, months).strftime("%Y-%m")


def due_months(conn: sqlite3.Connection, today: datetime) -> list[str]:
    """Months old enough to archive, oldest first, skipping pinned ones.

    A pinned month was just re-imported on purpose; archiving it the same night
    would undo the click that brought it back.
    """
    cutoff = window_start_month(today, get_rolling_months(conn))
    return [
        m["month"]
        for m in get_visit_months(conn)
        if m["month"] < cutoff and not pin_expiry(conn, m["month"])
    ]


# ── Pins ─────────────────────────────────────────────────────────────────────


def pin_expiry(conn: sqlite3.Connection, month: str) -> str | None:
    """ISO timestamp until which `month` is protected from archiving, if any."""
    return get_state(conn, _PIN_PREFIX + month) or None


def _set_pin(conn: sqlite3.Connection, month: str, until: str) -> None:
    set_state(conn, _PIN_PREFIX + month, until)


def _clear_pin(conn: sqlite3.Connection, month: str) -> None:
    """Drop the row rather than blank it — a cleared pin is an absent pin.

    Writing "" left one processor_state row per month ever restored, forever.
    Readers already treat an empty value as no pin, so both spellings work; only
    one of them stops the table growing.
    """
    delete_state(conn, _PIN_PREFIX + month)


# ── Paths ────────────────────────────────────────────────────────────────────


def archive_dir() -> Path:
    """The archive directory, created on first use.

    Read at call time rather than import time so tests (and a changed .env) can
    point it somewhere else.
    """
    d = Path(settings.archive_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


def archive_path(month: str) -> Path:
    """Path of a month's archive. `month` must already have passed valid_month()."""
    return archive_dir() / f"{month}.zip"


def resolve_archive(month: str) -> Path | None:
    """Existing archive for `month`, or None — refusing anything outside the dir.

    valid_month() is the first gate; this is the second. A single check between
    a URL segment and an open() is one check too few.
    """
    root = archive_dir().resolve()
    path = (root / f"{month}.zip").resolve()
    if root not in path.parents or not path.is_file():
        return None
    return path


# ── Writing ──────────────────────────────────────────────────────────────────


def _write_jsonl(zf: zipfile.ZipFile, name: str, rows) -> int:
    """Stream `rows` into a zip member, one JSON object per line. Returns the count.

    Written row by row rather than joined first. The month used to be held twice
    over — once as dicts, once as the encoded blob handed to writestr — which is
    the opposite of what stream_visits_for_month() reads in chunks of 1000 for.
    A busy month is six figures of rows on a box that also has to keep serving.

    force_zip64 because the member's size is not known before it is written, and
    guessing that a month stays under 2 GB uncompressed is the kind of guess
    that holds until it does not.
    """
    written = 0
    with zf.open(name, "w", force_zip64=True) as member:
        for row in rows:
            member.write((json.dumps(row, default=str) + "\n").encode())
            written += 1
    return written


def _intel_for_archive(conn: sqlite3.Connection, month: str):
    """Yield intel rows with the aggregated Shodan strings split back into lists.

    One row per IP rather than per visit, so this is the small half — but it is
    yielded rather than collected so the caller never holds both halves at once.
    """
    for row in get_intel_for_month(conn, month):
        for field in _INTEL_LIST_FIELDS:
            raw = row.get(field)
            row[field] = [v for v in str(raw).split(",") if v] if raw else []
        yield row


def write_zip(conn: sqlite3.Connection, month: str, path: Path) -> dict:
    """Write one month to `path` as a zip. Returns the meta dict. Reads only.

    Split out from archive_month() so that building the file and deleting the
    rows stay separate steps — the deletion is only ever allowed to follow a
    completed write. Also what a live month's download is built from, so both
    tables hand out the same format and the files are interchangeable.

    Everything leaving this service is compressed. Deflated JSONL runs about 30×
    smaller than the rows it holds, which is the difference between a download
    that costs a few MB of disk and one that costs a few hundred.
    """
    # The counts and the time span are gathered on the way past rather than
    # from a materialised list, so nothing here holds the month. meta is still
    # written last, which is what makes its presence mean "this zip finished".
    span: list[str] = []

    def _visits():
        for row in stream_visits_for_month(conn, month):
            ts = row.get("timestamp")
            if ts:
                if not span:
                    span.extend([ts, ts])
                else:
                    span[0] = min(span[0], ts)
                    span[1] = max(span[1], ts)
            yield row

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        visit_count = _write_jsonl(zf, VISITS, _visits())
        ip_count = _write_jsonl(zf, INTEL, _intel_for_archive(conn, month))
        meta = {
            "month": month,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": SCHEMA_VERSION,
            "visits": visit_count,
            "ips": ip_count,
            "first_ts": span[0] if span else None,
            "last_ts": span[1] if span else None,
        }
        # Last: a zip whose meta is present is a zip that finished.
        zf.writestr(META, json.dumps(meta, indent=2))
    return meta


def export_month(conn: sqlite3.Connection, month: str) -> Path:
    """Zip a month that is still in the database, for download. Returns the path.

    The caller deletes the file once it has been sent. It goes to disk rather
    than to memory on purpose: a busy month is six figures of rows, and holding
    those plus the zip buffer for the length of a download is how a small box
    runs out of RAM. Deflated on the way out — nothing leaves here uncompressed.
    """
    stamp = int(datetime.now(timezone.utc).timestamp())
    tmp = archive_dir() / f".export-{month}-{os.getpid()}-{stamp}.zip"
    write_zip(conn, month, tmp)
    return tmp


def archive_month(conn: sqlite3.Connection, month: str) -> dict:
    """Write `month` to its zip, then delete its rows. Returns the meta dict.

    Order matters more than anything else here. The zip is written to a temp
    name, closed, fsynced and only then renamed into place — a crash before the
    rename leaves no archive *and* no deletion, which is recoverable. Deleting
    first, or renaming a half-written file, loses the month.

    The write lock is taken before the month is read. sqlite3's legacy isolation
    opens a transaction on the first DML and not before, so the SELECTs building
    the zip ran in autocommit while the DELETE that follows opened its own — and
    any visit the tailer inserted for that month in between was deleted without
    ever reaching the archive.

    The temp file carries the pid and a timestamp for the same reason
    export_month's does: `python -m src.retention` beside the running service is
    a documented way to use this, and two passes on one fixed name is two
    writers on one file followed by two renames.
    """
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    final = archive_path(month)
    stamp = int(datetime.now(timezone.utc).timestamp())
    tmp = final.with_name(f".{final.name}.{os.getpid()}-{stamp}.tmp")
    meta = write_zip(conn, month, tmp)
    with open(tmp, "rb") as fh:
        os.fsync(fh.fileno())
    os.replace(tmp, final)

    deleted = delete_visits_for_month(conn, month)
    logger.info("Archived %s: %d visits, %d IPs -> %s", month, deleted, meta["ips"], final.name)
    return meta


# ── Reading ──────────────────────────────────────────────────────────────────


def read_meta(path: Path) -> dict:
    """meta.json of an archive. Returns {} for anything unreadable.

    The settings page lists whatever files are in the directory, so a truncated
    or hand-edited zip has to degrade to an entry with no counts, not to a 500.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            return json.loads(zf.read(META))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        logger.warning("Unreadable archive: %s", path.name)
        return {}


def list_archives(conn: sqlite3.Connection | None = None) -> list[dict]:
    """Every archive on disk, newest month first.

    The directory is the source of truth, not a table: a zip deleted by hand
    would otherwise stay listed forever.
    """
    out = []
    for path in sorted(archive_dir().glob("*.zip"), reverse=True):
        month = path.stem
        # The directory also holds the temp zips a live-month download is built
        # from, and pathlib's glob — unlike the shell's — matches leading dots.
        # Without this an in-flight download shows up as an archive row.
        if not valid_month(month):
            continue
        meta = read_meta(path)
        out.append(
            {
                "month": month,
                "bytes": path.stat().st_size,
                "created_at": meta.get("created_at"),
                "visits": meta.get("visits"),
                "ips": meta.get("ips"),
                "readable": bool(meta),
                "restored_until": pin_expiry(conn, month) if conn is not None else None,
            }
        )
    return out


# ── Restoring ────────────────────────────────────────────────────────────────


def restore_month(conn: sqlite3.Connection, month: str, days: int | None = None) -> dict:
    """Load a month back into the active DB and pin it against re-archiving.

    Idempotent: visits carry their original id and go in with INSERT OR IGNORE,
    intel only fills IPs that have none. Clicking twice changes nothing.
    """
    path = resolve_archive(month)
    if path is None:
        raise FileNotFoundError(f"no archive for {month}")

    with zipfile.ZipFile(path) as zf:
        visits = [json.loads(line) for line in zf.read(VISITS).splitlines() if line]
        intel = [json.loads(line) for line in zf.read(INTEL).splitlines() if line]

    added_intel = insert_missing_intel(conn, intel)
    added_visits = insert_archived_visits(conn, visits)

    days = settings.archive_restore_days if days is None else days
    until = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    _set_pin(conn, month, until)

    logger.info(
        "Restored %s: %d visits, %d IPs, pinned until %s", month, added_visits, added_intel, until
    )
    return {"month": month, "visits": added_visits, "ips": added_intel, "restored_until": until}


def release_month(conn: sqlite3.Connection, month: str) -> int:
    """Drop a restored month back out of the active DB. The zip stays.

    Used by the "put back" button and by the pin expiry. Deleting without
    re-exporting is safe *only* because the archive still holds the month —
    which is why this refuses to run when the file is gone.
    """
    if resolve_archive(month) is None:
        raise FileNotFoundError(f"no archive for {month} — refusing to delete its rows")
    deleted = delete_visits_for_month(conn, month)
    purge_orphaned_intel(conn)
    _clear_pin(conn, month)
    logger.info("Released %s: %d visits removed from the active DB", month, deleted)
    return deleted


def delete_archive(conn: sqlite3.Connection, month: str) -> None:
    """Delete a month's zip. Irreversible unless it was downloaded first.

    Any rows currently restored from it stay in the database and become ordinary
    live data — the pin goes with the file, because nothing is left to put the
    month back into.
    """
    path = resolve_archive(month)
    if path is None:
        raise FileNotFoundError(f"no archive for {month}")
    path.unlink()
    _clear_pin(conn, month)
    logger.info("Deleted archive %s", path.name)


def delete_month(conn: sqlite3.Connection, month: str) -> int:
    """Drop a month from the active database. Returns rows deleted.

    Unlike release_month() this does not require an archive to exist — it is the
    explicit "I do not want this data" action, and the UI asks before calling it.
    """
    deleted = delete_visits_for_month(conn, month)
    purge_orphaned_intel(conn)
    _clear_pin(conn, month)
    logger.info("Deleted %s from the database: %d visits", month, deleted)
    return deleted


def expire_restores(conn: sqlite3.Connection, now: datetime | None = None) -> list[str]:
    """Release every restored month whose pin has run out. Returns those months."""
    now = now or datetime.now(timezone.utc)
    expired = []
    for entry in list_archives(conn):
        until = entry["restored_until"]
        if until and until <= now.isoformat():
            release_month(conn, entry["month"])
            expired.append(entry["month"])
    return expired


# ── Mode ─────────────────────────────────────────────────────────────────────


def get_mode(conn: sqlite3.Connection) -> str:
    """Retention mode. Rolling unless someone chose otherwise in the UI."""
    return MODE_LIFETIME if get_state(conn, "retention.mode") == MODE_LIFETIME else MODE_ROLLING


def set_mode(conn: sqlite3.Connection, mode: str) -> None:
    """Store the retention mode. Anything unrecognised falls back to rolling."""
    set_state(conn, "retention.mode", mode if mode == MODE_LIFETIME else MODE_ROLLING)
