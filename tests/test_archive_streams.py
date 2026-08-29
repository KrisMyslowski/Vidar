"""Archiving a month must not hold the month.

stream_visits_for_month() reads in chunks of 1000 precisely so a busy month
never lands in memory at once — and write_zip() then did `list(...)` on it, and
handed writestr() a single joined blob, so the month was held twice over. A
six-figure month on a small box is exactly where this matters, and exactly where
nothing would have noticed until it fell over.
"""

import json
import tracemalloc
import zipfile

import pytest

from src.archive import write_zip
from src.db import get_conn
from src.queries import insert_visit, upsert_ip_intel

MONTH = "2026-04"
SMALL_MONTH = "2026-03"
# Both above one read chunk (stream_visits_for_month fetches 1000 rows at a
# time), so the comparison is between two months whose fixed costs — the chunk
# itself and the compressor's buffers — are already paid. Below that the peak is
# still those costs arriving, which says nothing about the month.
ROWS = 10_000
SMALL_ROWS = 2_000
# Each visit carries a kilobyte of user-agent, so the raw month is measured in
# megabytes and a peak that tracks it is unmistakable.
PADDING = "x" * 1024


def _seed(conn, month: str, rows: int) -> None:
    for i in range(rows):
        insert_visit(
            conn,
            ip=f"203.0.113.{i % 254}",
            timestamp=f"{month}-15T10:00:{i % 60:02d}+00:00",
            path=f"/page/{i}",
            user_agent=PADDING,
        )


@pytest.fixture
def big_month(tmp_db):
    with get_conn() as conn:
        _seed(conn, MONTH, ROWS)
        upsert_ip_intel(conn, {"ip": "203.0.113.1", "country": "Germany"})
    return ROWS * len(PADDING)


@pytest.fixture
def two_months(tmp_db):
    """One month eight times the size of the other, in one database."""
    with get_conn() as conn:
        _seed(conn, SMALL_MONTH, SMALL_ROWS)
        _seed(conn, MONTH, ROWS)
        upsert_ip_intel(conn, {"ip": "203.0.113.1", "country": "Germany"})
    return SMALL_MONTH, MONTH


def _peak_writing(month: str, path) -> int:
    tracemalloc.start()
    try:
        with get_conn() as conn:
            write_zip(conn, month, path)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class TestTheMonthIsStreamed:
    def test_peak_memory_does_not_grow_with_the_month(self, two_months, tmp_path):
        """The property, stated as a plateau rather than a number.

        What is bounded is the chunk stream_visits_for_month() reads, plus the
        compressor — an absolute figure would be pinning those. What matters is
        that eight times the rows do not cost eight times the memory. Under the
        old shape, which held the dicts *and* their joined encoding, they did.
        """
        small, large = two_months
        _peak_writing(small, tmp_path / "warm.zip")  # first call pays one-off costs

        peak_small = _peak_writing(small, tmp_path / "small.zip")
        peak_large = _peak_writing(large, tmp_path / "large.zip")

        assert peak_large < peak_small * 1.5, (
            f"{SMALL_ROWS} rows peaked at {peak_small / 1e6:.2f} MB and "
            f"{ROWS} rows at {peak_large / 1e6:.2f} MB — that tracks the month"
        )

    def test_every_row_still_arrives(self, big_month, tmp_path):
        path = tmp_path / "m.zip"
        with get_conn() as conn:
            meta = write_zip(conn, MONTH, path)

        with zipfile.ZipFile(path) as zf:
            lines = zf.read("visits.jsonl").decode().splitlines()
            stored = json.loads(zf.read("meta.json"))

        assert len(lines) == ROWS
        assert meta["visits"] == ROWS == stored["visits"]
        assert json.loads(lines[0])["path"] == "/page/0"
        assert json.loads(lines[-1])["path"] == f"/page/{ROWS - 1}"

    def test_the_span_is_gathered_on_the_way_past(self, big_month, tmp_path):
        """first_ts and last_ts used to come from a list comprehension over the
        materialised month."""
        with get_conn() as conn:
            meta = write_zip(conn, MONTH, tmp_path / "m.zip")
        assert meta["first_ts"] == f"{MONTH}-15T10:00:00+00:00"
        assert meta["last_ts"] == f"{MONTH}-15T10:00:59+00:00"

    def test_an_empty_month_has_no_span(self, tmp_db, tmp_path):
        with get_conn() as conn:
            meta = write_zip(conn, "2020-01", tmp_path / "empty.zip")
        assert meta == {
            **meta,
            "visits": 0,
            "ips": 0,
            "first_ts": None,
            "last_ts": None,
        }

    def test_the_zip_is_still_readable_by_the_restore_path(self, big_month, tmp_path):
        """force_zip64 changes the member headers; the reader has to be fine
        with that, since restore_month() opens exactly these files."""
        path = tmp_path / "m.zip"
        with get_conn() as conn:
            write_zip(conn, MONTH, path)
        with zipfile.ZipFile(path) as zf:
            assert zf.testzip() is None
            assert set(zf.namelist()) == {"visits.jsonl", "ip_intel.jsonl", "meta.json"}
