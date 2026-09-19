"""The lifespan's periodic tasks do their SQLite work on a worker thread.

Routes had moved to _cache.fetch() and the tailer and enricher to db.run_db()
long before these four did. The classifier backfill ran force_reclassify_all()
on the event loop — minutes on a real database after a rules change, with the
tailer, the enricher and every page frozen behind it — and the reclassifier,
retention and backup ticks read their state there too.

Each test records which thread opened a connection. The event loop's thread is
the one running the test, so any connection opened on it is the defect.
"""

import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from src import main
from src.db import get_conn


@pytest.fixture
def conn_threads(tmp_db):
    """Thread ids that opened a connection through main.get_conn."""
    seen: list[int] = []

    @contextmanager
    def recording_conn():
        seen.append(threading.get_ident())
        with get_conn() as conn:
            yield conn

    with patch.object(main, "get_conn", recording_conn):
        yield seen


async def test_the_classifier_backfill_runs_on_a_worker_thread(conn_threads):
    await main._backfill()
    assert conn_threads, "the backfill opened no connection at all"
    assert threading.get_ident() not in conn_threads


async def test_the_reclassifier_runs_on_a_worker_thread(conn_threads, monkeypatch):
    monkeypatch.setattr(main.settings, "reclassify_interval_minutes", 1)
    real_sleep = asyncio.sleep
    ticks = 0

    async def one_tick(_seconds):
        nonlocal ticks
        ticks += 1
        if ticks > 1:
            raise asyncio.CancelledError
        await real_sleep(0)

    with patch.object(main.asyncio, "sleep", one_tick):
        with pytest.raises(asyncio.CancelledError):
            await main._reclassify_task()

    assert conn_threads, "the reclassifier opened no connection at all"
    assert threading.get_ident() not in conn_threads


@pytest.mark.parametrize("task", ["_retention_task", "_backup_task"])
async def test_the_daily_tasks_read_their_state_on_a_worker_thread(conn_threads, task):
    async def stop(_seconds):
        raise asyncio.CancelledError

    # The due passes themselves already ran in to_thread; only the check was not.
    with (
        patch.object(main, "run_retention", lambda: None),
        patch.object(main, "run_backup", lambda: None),
        patch.object(main.asyncio, "sleep", stop),
    ):
        with pytest.raises(asyncio.CancelledError):
            await getattr(main, task)()

    assert conn_threads, f"{task} opened no connection at all"
    assert threading.get_ident() not in conn_threads
