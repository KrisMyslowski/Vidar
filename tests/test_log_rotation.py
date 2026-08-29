"""Rotation, truncation, and where the tailer starts reading.

The three cases the tail loop exists for, and the three it had no test for.

Determinism note: asyncio is single-threaded, so a block of synchronous
filesystem work between two awaits cannot be interleaved with a poll. Every
"the tailer must not have seen this yet" setup below relies on that rather than
on sleeps.
"""

import asyncio
import json
import logging
import os

import pytest

from src import config
from src import log_processor as lp
from src.db import get_conn
from src.log_processor import _fingerprint, _path_replaced, _starts_a_line
from src.queries import get_state


def _line(ip: str, path: str = "/p") -> str:
    return (
        json.dumps(
            {
                "time": "2026-06-13T10:00:00+00:00",
                "remote_addr": ip,
                "request": f"GET {path} HTTP/1.1",
                "status": 200,
                "body_bytes_sent": 10,
                "http_user_agent": "Mozilla/5.0",
                "request_method": "GET",
                "request_uri": path,
            }
        )
        + "\n"
    )


def _ips() -> list[str]:
    with get_conn() as conn:
        return [r[0] for r in conn.execute("SELECT ip FROM visits ORDER BY id")]


class _Tailer:
    """Run tail_log as a task for the duration of a `with` block."""

    async def __aenter__(self):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.task = asyncio.create_task(lp.tail_log(self.queue))
        return self

    async def __aexit__(self, *_exc):
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass

    async def until(self, predicate, timeout: float = 3.0) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            await asyncio.sleep(0.01)
            if predicate():
                return True
        return False


class TestRotationByRename:
    """nginx's usual rotation: the file is renamed and a new one takes its place,
    then nginx is signalled to reopen. Anything it appended to the old inode
    between our last read and that signal lives only on the old descriptor.

    Reopening by path lost exactly that: the loop saw a new inode, reset the
    offset to zero and read the *new* file. Holding the descriptor means the old
    one is drained to EOF first.
    """

    async def test_the_tail_of_the_old_file_is_not_lost(self, fast_log):
        async with _Tailer() as tailer:
            fast_log.write_text(_line("1.1.1.1"))
            assert await tailer.until(lambda: _ips() == ["1.1.1.1"])

            # No await in this block: the tailer cannot poll in the middle of it,
            # so 2.2.2.2 is written and rotated away strictly between two polls.
            with fast_log.open("a") as fh:
                fh.write(_line("2.2.2.2"))
            rotated = fast_log.with_suffix(".log.1")
            os.rename(fast_log, rotated)
            fast_log.write_text(_line("3.3.3.3"))

            assert await tailer.until(lambda: "3.3.3.3" in _ips())

        assert _ips() == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    async def test_it_switches_to_the_new_file_and_says_so(self, fast_log, caplog):
        async with _Tailer() as tailer:
            fast_log.write_text(_line("1.1.1.1"))
            assert await tailer.until(lambda: _ips() == ["1.1.1.1"])

            with caplog.at_level(logging.INFO, logger="vidar.log_processor"):
                os.rename(fast_log, fast_log.with_suffix(".log.1"))
                fast_log.write_text(_line("2.2.2.2"))
                assert await tailer.until(lambda: "2.2.2.2" in _ips())

        assert "rotated" in caplog.text
        with get_conn() as conn:
            # The persisted inode is the new file's, not the rotated-away one.
            assert int(get_state(conn, "file_inode")) == os.stat(fast_log).st_ino

    async def test_a_missing_path_is_waited_out_not_treated_as_rotation(self, fast_log):
        """Mid-rotation the path can briefly not exist. That is not a new file."""
        async with _Tailer() as tailer:
            fast_log.write_text(_line("1.1.1.1"))
            assert await tailer.until(lambda: _ips() == ["1.1.1.1"])

            moved = fast_log.with_suffix(".log.1")
            os.rename(fast_log, moved)
            await asyncio.sleep(0.05)  # tailer polls into the gap
            with moved.open("a") as fh:
                fh.write(_line("2.2.2.2"))
            os.rename(moved, fast_log)

            assert await tailer.until(lambda: "2.2.2.2" in _ips())

        assert _ips() == ["1.1.1.1", "2.2.2.2"]


class TestCopytruncate:
    """The other rotation style: the file is copied away and truncated in place,
    same inode. Detected by `size < offset` — which only holds while the file is
    still smaller than where we were. Grow past that within one poll and the
    seek lands mid-line, and every read after it is byte-misaligned for good.
    """

    async def test_a_truncate_that_regrows_past_the_offset_is_detected(self, fast_log, caplog):
        async with _Tailer() as tailer:
            fast_log.write_text(_line("1.1.1.1") * 6)
            assert await tailer.until(lambda: len(_ips()) == 6)
            offset_before = os.stat(fast_log).st_size

            with caplog.at_level(logging.INFO, logger="vidar.log_processor"):
                # Truncate and refill past the old offset, all between two polls.
                fresh = _line("2.2.2.2") * 12
                assert len(fresh) > offset_before, "the point is to overshoot"
                fast_log.write_text(fresh)

                assert await tailer.until(lambda: _ips().count("2.2.2.2") == 12)

        assert "truncated" in caplog.text
        with get_conn() as conn:
            assert int(get_state(conn, "file_offset")) == os.stat(fast_log).st_size

    async def test_a_plain_truncate_is_still_detected(self, fast_log):
        async with _Tailer() as tailer:
            fast_log.write_text(_line("1.1.1.1") * 6)
            assert await tailer.until(lambda: len(_ips()) == 6)

            fast_log.write_text(_line("2.2.2.2"))  # shorter than the old offset
            assert await tailer.until(lambda: "2.2.2.2" in _ips())


class TestAnOffsetHasToSitOnALineBoundary:
    @pytest.mark.parametrize(
        "content,offset,expected",
        [
            (b"abc\n", 0, True),
            (b"abc\ndef\n", 4, True),
            (b"abc\ndef\n", 6, False),
            (b"abc\n", 99, False),
        ],
        ids=["zero", "after-a-newline", "mid-line", "past-the-end"],
    )
    def test_it(self, tmp_path, content, offset, expected):
        f = tmp_path / "x"
        f.write_bytes(content)
        with f.open("rb") as fh:
            assert _starts_a_line(fh.fileno(), offset) is expected


class TestTheFingerprintSeesThroughTheBuffer:
    """The reason it reads with os.pread. A BufferedReader answers seek(0)+read()
    from bytes it already holds, so a file replaced in place fingerprints as its
    old contents — precisely the case this exists to catch."""

    def test_a_file_replaced_under_a_held_descriptor_fingerprints_differently(self, tmp_path):
        f = tmp_path / "x"
        f.write_bytes(b"A" * 400)
        with f.open("rb") as fh:
            before = _fingerprint(fh.fileno())
            assert fh.read(64), "prime the buffer, as the read loop would"
            f.write_bytes(b"B" * 400)
            assert _fingerprint(fh.fileno()) != before

    def test_too_short_to_be_stable_is_empty(self, tmp_path):
        f = tmp_path / "x"
        f.write_bytes(b"A" * 10)
        with f.open("rb") as fh:
            assert _fingerprint(fh.fileno()) == ""


class TestPathReplacement:
    def test_a_different_inode_is_a_replacement(self, tmp_path):
        f = tmp_path / "x"
        f.write_bytes(b"")
        assert _path_replaced(f, os.stat(f).st_ino) is False
        assert _path_replaced(f, os.stat(f).st_ino + 1) is True

    def test_a_vanished_path_is_not(self, tmp_path):
        """Nothing to switch to yet — keep the descriptor and wait."""
        assert _path_replaced(tmp_path / "gone", 1234) is False


class TestWhereItStartsOnAFreshDatabase:
    """No stored read position means a first run or a restored database. Byte 0
    re-ingests everything the file still holds, and `visits` has no way to catch
    it: nginx timestamps resolve to the second, so two identical requests in one
    second are indistinguishable from one request ingested twice.
    """

    @pytest.fixture
    def log_with_history(self, tmp_db, tmp_path, monkeypatch):
        log = tmp_path / "access.log"
        log.write_text(_line("9.9.9.9") * 4)
        monkeypatch.setattr(config.settings, "log_path", log)
        monkeypatch.setattr(config.settings, "poll_interval_seconds", 0.01)
        return log

    async def test_by_default_it_starts_at_the_end(self, log_with_history, caplog):
        with caplog.at_level(logging.INFO, logger="vidar.log_processor"):
            async with _Tailer() as tailer:
                await tailer.until(lambda: False, timeout=0.2)

                # What arrives after we attach is still read.
                with log_with_history.open("a") as fh:
                    fh.write(_line("5.5.5.5"))
                assert await tailer.until(lambda: _ips() == ["5.5.5.5"])

        assert "starting at the end" in caplog.text
        assert "INGEST_EXISTING_BACKLOG" in caplog.text, "name the way to opt in"

    async def test_the_backlog_is_read_when_asked_for(self, log_with_history, monkeypatch):
        monkeypatch.setattr(config.settings, "ingest_existing_backlog", True)
        async with _Tailer() as tailer:
            assert await tailer.until(lambda: len(_ips()) == 4)

    async def test_a_stored_position_wins_over_both(self, log_with_history):
        """An ordinary restart resumes, and reads neither more nor less."""
        one_line = len(_line("9.9.9.9"))
        with get_conn() as conn:
            from src.queries import set_state

            set_state(conn, "file_offset", str(one_line * 2))
            set_state(conn, "file_inode", str(os.stat(log_with_history).st_ino))

        async with _Tailer() as tailer:
            assert await tailer.until(lambda: len(_ips()) == 2)
            await asyncio.sleep(0.1)
        assert len(_ips()) == 2, "resumed at the stored offset, not before it"
