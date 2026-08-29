"""Data retention — the daily pass that keeps the active database bounded.

Two modes, chosen in the UI (Settings › Storage & Retention) and stored under
`retention.mode`:

  rolling   the current month plus the two before it stay in the database.
            A month that falls out is archived to a zip and then removed.
  lifetime  nothing is archived and nothing is deleted.

Driven by `_retention_task()` in main.py, inside the app's event loop. It used
to be a cron job in the container, which never actually ran: the crontab was
installed in the wrong format *and* its output redirect could not be opened by
the user the job ran as, so it failed before reaching Python. Anything that has
to happen on a schedule belongs next to the other background tasks, where it
runs as the same user and logs to the same place.

Still runnable by hand: python -m src.retention
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

from .archive import (
    LAST_RUN_KEY,
    MODE_ROLLING,
    archive_month,
    delete_archive,
    due_months,
    expire_restores,
    expired_archives,
    get_mode,
    resolve_archive,
)
from .db import get_conn, init_db, vacuum
from .queries import purge_orphaned_intel, set_state

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vidar.retention")


def run_retention(now: datetime | None = None) -> dict:
    """Execute one retention pass. Returns a summary of what it did."""
    now = now or datetime.now(timezone.utc)
    init_db()

    with get_conn() as conn:
        # Expiry runs in both modes: a pin is a promise with an end date, and
        # switching to lifetime should not turn a 7-day restore into forever.
        expired = expire_restores(conn, now)
        mode = get_mode(conn)
        due = due_months(conn, now) if mode == MODE_ROLLING else []

    # One transaction per month, not one for the pass. Each zip is renamed into
    # place the moment it is written, so a failure on the third month used to
    # roll back the deletions for the first two while their archives stayed on
    # disk — and the whole pass held the write lock throughout, which is what
    # put the tailer into its exponential backoff for the duration.
    archived: list[str] = []
    for month in due:
        with get_conn() as conn:
            archive_month(conn, month)
        archived.append(month)

    # Third step, after archiving and in the same pass, because the order is what
    # makes it correct: a month first falls out of the window and becomes a zip,
    # and only then can another zip be old enough to go. Running expiry first
    # would judge a set of archives that the same pass is about to add to.
    #
    # Archives only leave when an operator has switched expiry on; the default
    # keeps them, so an update never deletes anything by arriving.
    # Rolling only. Lifetime says nothing is archived and nothing is deleted, and
    # an archive already on disk is data the operator still has — expiring it
    # under a mode that promises the opposite is the kind of deletion nobody can
    # predict. It is also where the control lives: the keep window sits with the
    # mode that produces archives, so in lifetime it would act while invisible.
    with get_conn() as conn:
        stale = expired_archives(conn, now) if mode == MODE_ROLLING else []

    dropped: list[str] = []
    for month in stale:
        with get_conn() as conn:
            path = resolve_archive(month)
            size = path.stat().st_size if path else 0
            delete_archive(conn, month)
        dropped.append(month)
        # An automatic deletion with no trace in the log is not a feature.
        logger.info(
            "Archive expired: %s (%.1f MB) — past the archive keep window", month, size / 1e6
        )

    with get_conn() as conn:
        if archived or expired or dropped:
            purge_orphaned_intel(conn)
        set_state(conn, LAST_RUN_KEY, now.isoformat())

    logger.info(
        "Retention pass (%s): archived %s, expired %s, archives dropped %s",
        mode,
        archived or "nothing",
        expired or "nothing",
        dropped or "nothing",
    )

    # Only worth the table rewrite when rows actually left.
    if archived or expired:
        try:
            vacuum()
            logger.info("VACUUM completed")
        except sqlite3.OperationalError as e:
            logger.error("VACUUM failed (continuing anyway): %s", e)

    return {
        "mode": mode,
        "archived": archived,
        "expired": expired,
        "dropped": dropped,
        "ran_at": now.isoformat(),
    }


if __name__ == "__main__":
    run_retention()
