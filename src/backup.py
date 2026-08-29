"""Database snapshots — the copy that exists when the live file does not.

Retention archives the months that fall *out* of the window. Nothing held a copy
of what is still *in* it, so the active database — every visit since the last
archived month, plus all of ip_intel — lived on one file on one disk. The
archives are not a substitute: restoring from them gives back last quarter and
nothing from this one.

Written with `VACUUM INTO`, not a file copy. The database is in WAL mode and
open whenever the service runs, so `cp` can catch a torn page or a half-applied
WAL and produce a file that only looks like a database. VACUUM INTO takes a read
lock, writes a consistent and compacted copy, and needs no downtime.

The write order is archive.py's: gzip to a temp name in the target directory →
fsync → os.replace(). A crash before the rename leaves yesterday's snapshot
intact rather than today's half of one.

Driven by `_backup_task()` in main.py — there is no cron in this project, see
the note in retention.py for what happened the last time there was.

Still runnable by hand: python -m src.backup
"""

from __future__ import annotations

import gzip
import logging
import os
import re
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .db import get_conn
from .queries import get_state, set_state

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vidar.backup")

LAST_RUN_KEY = "backup.last_run"
SUFFIX = ".db.gz"

# VACUUM INTO writes an uncompressed copy before it is gzipped, so a pass needs
# room for the database twice over. Below that it does nothing and says so: a
# backup that fills the disk takes the service down with it, which is a worse
# outcome than the one it was guarding against.
_FREE_SPACE_FACTOR = 2.5


def backup_dir() -> Path:
    """The snapshot directory, created on first use.

    Read at call time rather than import time, like archive_dir(), so tests and
    a changed .env can point it elsewhere.
    """
    d = Path(settings.backup_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


def snapshot_name(now: datetime) -> str:
    """One snapshot per day, named after the database it copies."""
    return f"{Path(settings.db_path).stem}-{now.strftime('%Y-%m-%d')}{SUFFIX}"


def list_snapshots() -> list[dict]:
    """Snapshots on disk, newest first.

    Read from the directory rather than a table, like the archive list: a file
    deleted by hand stops being listed instead of becoming a row pointing at
    nothing.
    """
    out = []
    for path in backup_dir().glob(f"*{SUFFIX}"):
        stat = path.stat()
        out.append(
            {
                "name": path.name,
                "bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            }
        )
    return sorted(out, key=lambda s: s["name"], reverse=True)


# A snapshot name reaches the filesystem from a URL segment, so it is matched
# whole and narrowly — no separators, no dots outside the suffix. archive.py's
# resolve_archive() makes the same argument: one check between a URL and open()
# is one too few, so the resolved path is tested against the directory as well.
_NAME_RE = re.compile(r"[A-Za-z0-9_-]+\.db\.gz")


def resolve_snapshot(name: str) -> Path | None:
    """Existing snapshot for `name`, or None — refusing anything outside the dir."""
    if not _NAME_RE.fullmatch(name):
        return None
    root = backup_dir().resolve()
    path = (root / name).resolve()
    if root not in path.parents or not path.is_file():
        return None
    return path


def _has_room(db_path: Path, target: Path) -> bool:
    try:
        free = shutil.disk_usage(target).free
        needed = db_path.stat().st_size * _FREE_SPACE_FACTOR
    except OSError:
        return True  # cannot tell — attempt it rather than skip silently
    if free >= needed:
        return True
    logger.error(
        "Skipping backup: %.0f MB free, need about %.0f MB. The snapshot is written "
        "uncompressed before it is gzipped.",
        free / 1e6,
        needed / 1e6,
    )
    return False


def create_snapshot(now: datetime | None = None) -> Path | None:
    """Write one compressed snapshot. Returns its path, or None if it was skipped."""
    now = now or datetime.now(timezone.utc)
    db_path = Path(settings.db_path)
    target = backup_dir() / snapshot_name(now)

    if not db_path.exists():
        logger.warning("No database at %s — nothing to back up", db_path)
        return None
    if not _has_room(db_path, target.parent):
        return None

    # Unique per call, because two passes can legitimately overlap: the daily
    # task is due the moment the service starts, and "Back up now" is one click
    # away. With one fixed pair of temp names they raced — the first rename
    # moved the file the second was still writing through, and that one died on
    # a FileNotFoundError after both had done the expensive part. Distinct names
    # let both finish; os.replace is atomic, so the later one simply wins.
    # Neither name ends in the snapshot suffix, so a half-written file is never
    # listed as a snapshot.
    uniq = uuid.uuid4().hex[:8]
    raw = target.with_name(f"{target.name}.{uniq}.raw.tmp")
    tmp = target.with_name(f"{target.name}.{uniq}.tmp")

    try:
        with get_conn() as conn:
            conn.execute("VACUUM INTO ?", (str(raw),))

        with open(raw, "rb") as src, gzip.open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst)
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except (OSError, sqlite3.Error):
        for leftover in (raw, tmp):
            leftover.unlink(missing_ok=True)
        raise
    finally:
        raw.unlink(missing_ok=True)

    logger.info(
        "Snapshot %s (%.1f MB from a %.1f MB database)",
        target.name,
        target.stat().st_size / 1e6,
        db_path.stat().st_size / 1e6,
    )
    return target


def prune(keep: int | None = None) -> list[str]:
    """Delete all but the `keep` newest snapshots. Returns what was removed."""
    keep = settings.backup_keep if keep is None else keep
    # 0 would mean "delete the one just written", which no setting should be
    # able to express by accident.
    keep = max(int(keep), 1)
    removed = []
    for snap in list_snapshots()[keep:]:
        (backup_dir() / snap["name"]).unlink(missing_ok=True)
        removed.append(snap["name"])
    if removed:
        logger.info("Pruned %d old snapshot(s): %s", len(removed), ", ".join(removed))
    return removed


def run_backup(now: datetime | None = None) -> dict:
    """Execute one backup pass. Returns a summary of what it did."""
    now = now or datetime.now(timezone.utc)
    if not settings.backup_enabled:
        return {"written": None, "pruned": [], "ran_at": now.isoformat(), "enabled": False}

    written = create_snapshot(now)
    pruned = prune() if written else []

    # Stamped even when the snapshot was skipped for space: the settings page
    # shows this as "last run", and a pass that ran and declined is not the same
    # state as one that never fired.
    with get_conn() as conn:
        set_state(conn, LAST_RUN_KEY, now.isoformat())

    return {
        "written": written.name if written else None,
        "pruned": pruned,
        "ran_at": now.isoformat(),
        "enabled": True,
    }


def last_run(conn: sqlite3.Connection) -> str | None:
    """When the last backup pass completed, for the settings page."""
    return get_state(conn, LAST_RUN_KEY)


if __name__ == "__main__":
    run_backup()
