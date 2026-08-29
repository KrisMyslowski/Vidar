"""Async regression tests for the tail_log loop: poison-row skip (R1) and bounded reads (R2)."""

import asyncio
import json

from src import log_processor as lp
from src.db import get_conn
from src.queries import get_state


def _line(ip: str, path: str = "/p") -> str:
    return json.dumps(
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


def _visit_count() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]


async def _drive_until(check, timeout: float = 3.0) -> None:
    """Run tail_log until check() is true (or timeout), then cancel it cleanly."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    task = asyncio.create_task(lp.tail_log(queue))
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            await asyncio.sleep(0.02)
            if check():
                return
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def test_tail_log_skips_poison_row(fast_log, monkeypatch):
    """R1: a line whose insert raises (non-OperationalError) is skipped; the good rows
    persist and the offset still advances (no reprocessing wedge)."""
    fast_log.write_text("\n".join(_line(ip) for ip in ("1.1.1.1", "6.6.6.6", "2.2.2.2")) + "\n")

    real_insert = lp.insert_visit

    def poison_insert(conn, **kw):
        if kw.get("ip") == "6.6.6.6":
            raise ValueError("simulated poison row")
        return real_insert(conn, **kw)

    monkeypatch.setattr(lp, "insert_visit", poison_insert)

    await _drive_until(lambda: _visit_count() >= 2)

    with get_conn() as conn:
        ips = sorted(r[0] for r in conn.execute("SELECT ip FROM visits"))
        offset = get_state(conn, "file_offset")
    assert ips == ["1.1.1.1", "2.2.2.2"]  # poison row skipped, not wedged
    assert offset is not None and int(offset) > 0  # offset advanced past the batch


async def test_tail_log_bounded_read_drains(fast_log, monkeypatch):
    """R2: with a tiny byte budget the backlog is drained across multiple polls
    (and f.tell() keeps working with the bounded readline loop)."""
    monkeypatch.setattr(lp, "_MAX_READ_BYTES", 300)
    n = 30
    fast_log.write_text("\n".join(_line(f"203.0.{i // 256}.{i % 256}") for i in range(n)) + "\n")

    await _drive_until(lambda: _visit_count() >= n)

    assert _visit_count() == n


async def test_partial_last_line_left_for_next_poll(fast_log):
    """A trailing line without \\n (nginx still writing) is not consumed: the offset
    stops at the last complete line, and the finished line is ingested whole later."""
    full = _line("1.1.1.1")
    partial = _line("2.2.2.2")
    cut = len(partial) // 2
    fast_log.write_text(full + "\n" + partial[:cut])

    await _drive_until(lambda: _visit_count() >= 1)

    with get_conn() as conn:
        ips = [r[0] for r in conn.execute("SELECT ip FROM visits")]
        offset = int(get_state(conn, "file_offset"))
    assert ips == ["1.1.1.1"]
    assert offset == len((full + "\n").encode())  # offset stops before the partial line

    with open(fast_log, "a") as f:
        f.write(partial[cut:] + "\n")

    await _drive_until(lambda: _visit_count() >= 2)

    with get_conn() as conn:
        ips = sorted(r[0] for r in conn.execute("SELECT ip FROM visits"))
    assert ips == ["1.1.1.1", "2.2.2.2"]  # completed line ingested — no loss, no garbage


async def test_oversized_unterminated_line_skipped(fast_log, monkeypatch):
    """A single unterminated line exceeding the read budget is consumed (offset
    advances past it) instead of stalling the tailer forever."""
    monkeypatch.setattr(lp, "_MAX_READ_BYTES", 100)
    garbage = "x" * 500  # no newline, far over budget
    fast_log.write_text(garbage)

    def _offset() -> int:
        with get_conn() as conn:
            return int(get_state(conn, "file_offset") or 0)

    await _drive_until(lambda: _offset() >= len(garbage))

    assert _offset() == len(garbage)  # advanced past the junk — no stall
    assert _visit_count() == 0  # nothing bogus was inserted
