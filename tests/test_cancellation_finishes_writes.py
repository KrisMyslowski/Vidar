"""A cancelled background task must not still be writing.

asyncio.to_thread cannot cancel the thread it starts. Cancelling the task only
stops the *waiting*, so when the log tailer's batch insert moved off the event
loop, cancelling the tailer left the write running — and it committed rows and a
read position after the task was gone.

Two consequences, both observed. At shutdown the tailer commits a batch after
"Shutting down Vidar" is logged. In the suite it was worse: each test
patches the module-level _DB_PATH, so an orphaned write from one test landed in
the *next* test's database, injecting a stale file_offset, inode and
fingerprint. The following tailer then resumed at a position that did not
describe its file and re-read the same lines forever — which is what made runs
stall for minutes, intermittently, in a way a watchdog thread's timing was
enough to hide.

db.run_db() is the fix: shield the work, and await it on the way out.
"""

import asyncio
import time

import pytest

from src import log_processor as lp
from src.db import get_conn, run_db
from src.queries import get_state
from tests.test_log_rotation import _ips, _line


class TestRunDbFinishesWhatItStarted:
    async def test_it_returns_the_result_normally(self, tmp_db):
        assert await run_db(lambda a, b: a + b, 2, 3) == 5

    async def test_a_cancelled_call_still_completes_the_work(self, tmp_db):
        done = []

        def slow():
            time.sleep(0.2)
            done.append(True)

        task = asyncio.create_task(run_db(slow))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert done == [True], "the write must not still be running after the await"

    async def test_it_propagates_an_error(self, tmp_db):
        def boom():
            raise ValueError("disk full")

        with pytest.raises(ValueError, match="disk full"):
            await run_db(boom)


class TestCancellingTheTailerLeavesNothingRunning:
    async def test_the_batch_is_committed_before_cancel_returns(self, fast_log, monkeypatch):
        """Before: the database was still empty when `await task` returned, and
        three rows plus an offset appeared a fraction of a second later."""
        fast_log.write_text(_line("1.1.1.1") * 3)

        started = asyncio.Event()
        real = lp._write_batch

        # *args rather than the signature: this stands in for _write_batch to
        # make it slow, not to pin its parameters, and spelling them out here
        # broke the test the next time one was added.
        def slow_write(*args, **kwargs):
            started.set()
            time.sleep(0.3)
            return real(*args, **kwargs)

        monkeypatch.setattr(lp, "_write_batch", slow_write)

        task = asyncio.create_task(lp.tail_log(asyncio.Queue(maxsize=100)))
        await asyncio.wait_for(started.wait(), timeout=3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        settled = len(_ips())
        with get_conn() as conn:
            offset = get_state(conn, "file_offset")

        await asyncio.sleep(0.5)
        assert len(_ips()) == settled, "a write landed after the task was gone"
        assert settled == 3, "and the batch it was in the middle of was kept"
        assert offset is not None and int(offset) > 0


class TestTheEnricherToo:
    async def test_a_cancelled_persist_still_lands(self, tmp_db, monkeypatch):
        import src.enricher as enricher

        persisted = []

        def slow_persist(results, failed_ips):
            time.sleep(0.2)
            persisted.append(len(results))

        monkeypatch.setattr(enricher, "_persist_batch", slow_persist)

        task = asyncio.create_task(run_db(enricher._persist_batch, [{"ip": "1.2.3.4"}], []))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert persisted == [1]
