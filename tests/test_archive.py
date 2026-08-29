"""Monthly archiving: the window, the round trip, and what must not be lost.

The premise of the whole feature is that archiving is safe — a month leaves the
database only because a file now holds it. Most of what is asserted here is that
promise under conditions that break it: a half-written zip, a second click, an
IP whose live intel is newer than the archived copy.
"""

import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from src import archive
from src.db import get_conn
from src.queries import (
    count_visits,
    get_state,
    get_visit_months,
    get_visitor_detail,
    insert_visit,
    set_state,
    set_visitor_class,
    upsert_ip_intel,
)
from src.retention import run_retention

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)


def _seed(conn, ip: str, month: str, day: int = 5, **intel):
    """One visit in `month` plus an ip_intel row for its IP."""
    insert_visit(
        conn,
        ip=ip,
        timestamp=f"{month}-{day:02d}T10:00:00+00:00",
        path="/index.html",
        status=200,
        user_agent="Mozilla/5.0",
        browser="Chrome",
    )
    upsert_ip_intel(conn, {"ip": ip, "country": "Germany", **intel})


# ── Window ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "today,expected",
    [
        (datetime(2026, 8, 7, tzinfo=timezone.utc), "2026-06"),
        (datetime(2026, 8, 31, tzinfo=timezone.utc), "2026-06"),
        # Across the year boundary — the arithmetic is on a month index, not on
        # a month number that would underflow.
        (datetime(2026, 1, 15, tzinfo=timezone.utc), "2025-11"),
        (datetime(2026, 2, 1, tzinfo=timezone.utc), "2025-12"),
        (datetime(2026, 3, 1, tzinfo=timezone.utc), "2026-01"),
    ],
)
def test_window_start_is_two_calendar_months_back(today, expected):
    assert archive.window_start_month(today) == expected


@pytest.mark.parametrize(
    "months,expected",
    [
        (0, "2026-08"),  # current month only
        (1, "2026-07"),
        (2, "2026-06"),  # the default
        (8, "2025-12"),  # back across the year
    ],
)
def test_window_size_moves_the_boundary(months, expected):
    assert archive.window_start_month(NOW, months) == expected


def test_due_months_are_those_before_the_window(tmp_db):
    with get_conn(tmp_db) as conn:
        for month in ("2026-04", "2026-05", "2026-06", "2026-07", "2026-08"):
            _seed(conn, f"10.0.0.{month[-1]}", month)
        assert archive.due_months(conn, NOW) == ["2026-04", "2026-05"]

        # A wider window pulls months back in; a narrower one pushes more out.
        archive.set_rolling_months(conn, 4)
        assert archive.due_months(conn, NOW) == []
        archive.set_rolling_months(conn, 0)
        assert archive.due_months(conn, NOW) == ["2026-04", "2026-05", "2026-06", "2026-07"]


def test_rolling_months_defaults_and_clamps(tmp_db):
    with get_conn(tmp_db) as conn:
        assert archive.get_rolling_months(conn) == archive.DEFAULT_ROLLING_MONTHS
        assert archive.set_rolling_months(conn, 99) == archive.MAX_ROLLING_MONTHS
        assert archive.set_rolling_months(conn, -1) == 0
        # A hand-edited or half-written value must not take the pass down.
        set_state(conn, archive.ROLLING_MONTHS_KEY, "nonsense")
        assert archive.get_rolling_months(conn) == archive.DEFAULT_ROLLING_MONTHS


# ── Deleting ─────────────────────────────────────────────────────────────────


def test_delete_month_drops_rows_without_writing_an_archive(tmp_db, tmp_archive_dir):
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        assert archive.delete_month(conn, "2026-04") == 1
        assert count_visits(conn) == 0
    assert not (tmp_archive_dir / "2026-04.zip").exists()


def test_delete_archive_leaves_restored_rows_in_place(tmp_db, tmp_archive_dir):
    """The file goes; whatever was already restored from it becomes live data."""
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        archive.archive_month(conn, "2026-04")
        archive.restore_month(conn, "2026-04")

        archive.delete_archive(conn, "2026-04")

        assert not (tmp_archive_dir / "2026-04.zip").exists()
        assert count_visits(conn) == 1
        assert archive.pin_expiry(conn, "2026-04") is None
        # The month is ordinary data again, so the pass may archive it afresh.
        assert archive.due_months(conn, NOW) == ["2026-04"]


def test_delete_archive_needs_an_archive(tmp_db):
    with get_conn(tmp_db) as conn:
        with pytest.raises(FileNotFoundError):
            archive.delete_archive(conn, "2019-01")


def test_export_month_zips_without_touching_the_database(tmp_db):
    """The download of a live month is a read — and always compressed."""
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-08")
        path = archive.export_month(conn, "2026-08")

        assert count_visits(conn) == 1
        with zipfile.ZipFile(path) as zf:
            assert sorted(zf.namelist()) == ["ip_intel.jsonl", "meta.json", "visits.jsonl"]
            assert json.loads(zf.read("meta.json"))["visits"] == 1


def test_an_in_flight_export_is_not_an_archive(tmp_db, tmp_archive_dir):
    """The export temp file lands in the archive dir and ends in .zip.

    pathlib's glob matches leading dots, so listing by suffix alone put a
    half-served download in the archive table for the length of the download.
    """
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        _seed(conn, "2.2.2.2", "2026-08")
        archive.archive_month(conn, "2026-04")
        archive.export_month(conn, "2026-08")

        assert [e["month"] for e in archive.list_archives(conn)] == ["2026-04"]


# ── Round trip ───────────────────────────────────────────────────────────────


def test_archive_writes_a_zip_then_empties_the_month(tmp_db, tmp_archive_dir):
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        _seed(conn, "1.1.1.2", "2026-04", day=9)
        _seed(conn, "2.2.2.2", "2026-07")

        meta = archive.archive_month(conn, "2026-04")

        assert meta["visits"] == 2 and meta["ips"] == 2
        assert count_visits(conn) == 1, "only the July visit is left"

    path = tmp_archive_dir / "2026-04.zip"
    assert path.is_file()
    with zipfile.ZipFile(path) as zf:
        assert sorted(zf.namelist()) == ["ip_intel.jsonl", "meta.json", "visits.jsonl"]
        assert json.loads(zf.read("meta.json"))["month"] == "2026-04"
        assert len(zf.read("visits.jsonl").splitlines()) == 2


def test_restore_brings_every_field_back_including_the_id(tmp_db):
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04", tags="scanner", open_ports="22,443")
        set_visitor_class(conn, "1.1.1.1", "bots/scanning-tools")
        before = [dict(r) for r in conn.execute("SELECT * FROM visits ORDER BY id")]

        archive.archive_month(conn, "2026-04")
        assert count_visits(conn) == 0

        archive.restore_month(conn, "2026-04")
        after = [dict(r) for r in conn.execute("SELECT * FROM visits ORDER BY id")]
        assert after == before

        detail = get_visitor_detail(conn, "1.1.1.1")
        assert detail["visitor_class"] == "bots/scanning-tools"
        assert sorted(detail["tags"].split(",")) == ["scanner"]
        assert sorted(detail["open_ports"].split(",")) == ["22", "443"]


def test_restoring_twice_does_not_duplicate(tmp_db):
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        archive.archive_month(conn, "2026-04")

        archive.restore_month(conn, "2026-04")
        archive.restore_month(conn, "2026-04")
        assert count_visits(conn) == 1


def test_restore_never_overwrites_fresher_intel(tmp_db):
    """The archived snapshot is old by definition — it must only fill gaps.

    An IP seen in April and again in August has August's enrichment in the live
    table. Rolling it back to April's would silently downgrade current data.
    """
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04", country="Germany", is_tor=0)
        archive.archive_month(conn, "2026-04")

        # Same IP shows up again, now enriched differently.
        _seed(conn, "1.1.1.1", "2026-08", country="France", is_tor=1)

        archive.restore_month(conn, "2026-04")
        row = conn.execute("SELECT country, is_tor FROM ip_intel WHERE ip = ?", ("1.1.1.1",))
        country, is_tor = row.fetchone()
        assert (country, is_tor) == ("France", 1)


def test_restore_of_an_unknown_month_raises(tmp_db):
    with get_conn(tmp_db) as conn:
        with pytest.raises(FileNotFoundError):
            archive.restore_month(conn, "2019-01")


# ── Pins ─────────────────────────────────────────────────────────────────────


def test_a_restored_month_is_skipped_by_the_next_pass(tmp_db):
    """Without the pin, the nightly pass would undo the re-import the same day."""
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        archive.archive_month(conn, "2026-04")
        archive.restore_month(conn, "2026-04")

        assert archive.due_months(conn, NOW) == []
        assert count_visits(conn) == 1


def test_an_expired_pin_moves_the_month_back_out(tmp_db):
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        archive.archive_month(conn, "2026-04")
        archive.restore_month(conn, "2026-04", days=7)

        assert archive.expire_restores(conn, NOW) == []
        assert count_visits(conn) == 1

        later = datetime.now(timezone.utc) + timedelta(days=8)
        assert archive.expire_restores(conn, later) == ["2026-04"]
        assert count_visits(conn) == 0
        assert archive.pin_expiry(conn, "2026-04") is None


def test_release_refuses_when_the_archive_is_gone(tmp_db, tmp_archive_dir):
    """Deleting rows is only safe while the file still holds them."""
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        archive.archive_month(conn, "2026-04")
        archive.restore_month(conn, "2026-04")

        (tmp_archive_dir / "2026-04.zip").unlink()

        with pytest.raises(FileNotFoundError):
            archive.release_month(conn, "2026-04")
        assert count_visits(conn) == 1


# ── Failure modes ────────────────────────────────────────────────────────────


def test_a_failed_write_deletes_nothing(tmp_db, tmp_archive_dir, monkeypatch):
    """No archive means no deletion. The month survives a crash mid-write."""
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")

        def boom(*a, **kw):
            raise OSError("disk full")

        monkeypatch.setattr(archive.os, "replace", boom)
        with pytest.raises(OSError):
            archive.archive_month(conn, "2026-04")

        assert count_visits(conn) == 1
        assert not (tmp_archive_dir / "2026-04.zip").exists()


def test_an_unreadable_archive_is_listed_not_fatal(tmp_db, tmp_archive_dir):
    tmp_archive_dir.mkdir(parents=True, exist_ok=True)
    (tmp_archive_dir / "2026-04.zip").write_bytes(b"not a zip")
    with get_conn(tmp_db) as conn:
        entries = archive.list_archives(conn)
    assert len(entries) == 1
    assert entries[0]["readable"] is False and entries[0]["visits"] is None


# ── Path safety ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "month",
    ["../secrets", "2026-13", "2026-00", "2026-6", "2026", "", "2026-04/../..", "2026-04.zip"],
)
def test_resolve_archive_rejects_anything_but_a_month(month, tmp_archive_dir):
    from src.validators import valid_month

    assert valid_month(month) is None


def test_resolve_archive_stays_inside_the_directory(tmp_archive_dir, tmp_path):
    outside = tmp_path / "elsewhere.zip"
    outside.write_bytes(b"x")
    assert archive.resolve_archive("../elsewhere") is None


# ── The daily pass ───────────────────────────────────────────────────────────


def test_rolling_pass_archives_everything_out_of_window(tmp_db, tmp_archive_dir):
    with get_conn(tmp_db) as conn:
        for month in ("2026-04", "2026-05", "2026-07", "2026-08"):
            _seed(conn, f"10.0.0.{month[-1]}", month)

    result = run_retention(NOW)

    assert result["archived"] == ["2026-04", "2026-05"]
    assert (tmp_archive_dir / "2026-04.zip").is_file()
    assert (tmp_archive_dir / "2026-05.zip").is_file()
    with get_conn(tmp_db) as conn:
        assert [m["month"] for m in get_visit_months(conn)] == ["2026-07", "2026-08"]
        assert get_state(conn, "retention.last_run") == NOW.isoformat()


def test_lifetime_pass_touches_nothing(tmp_db, tmp_archive_dir):
    with get_conn(tmp_db) as conn:
        _seed(conn, "1.1.1.1", "2026-04")
        archive.set_mode(conn, "lifetime")

    result = run_retention(NOW)

    assert result["mode"] == "lifetime" and result["archived"] == []
    assert not (tmp_archive_dir / "2026-04.zip").exists()
    with get_conn(tmp_db) as conn:
        assert count_visits(conn) == 1


def test_mode_defaults_to_rolling_and_ignores_junk(tmp_db):
    with get_conn(tmp_db) as conn:
        assert archive.get_mode(conn) == "rolling"
        archive.set_mode(conn, "lifetime")
        assert archive.get_mode(conn) == "lifetime"
        archive.set_mode(conn, "whatever")
        assert archive.get_mode(conn) == "rolling"


# ── Archive expiry ───────────────────────────────────────────────────────────


def test_archives_are_kept_by_default(tmp_db, tmp_archive_dir):
    """An update must not delete data because it arrived.

    The rolling window bounds the database; nothing ever bounded the zips beside
    it. Adding an expiry that defaults to on would silently remove months from
    every existing deployment on the first nightly pass.
    """
    with get_conn(tmp_db) as conn:
        assert archive.get_archive_keep_months(conn) == archive.ARCHIVE_KEEP_FOREVER
        _seed(conn, "203.0.113.1", "2020-01")
        archive.archive_month(conn, "2020-01")
    with get_conn(tmp_db) as conn:
        assert archive.expired_archives(conn, datetime(2026, 8, 29, tzinfo=timezone.utc)) == []


def test_expiry_counts_from_the_month_not_the_file(tmp_db, tmp_archive_dir):
    """A data directory that was copied once carries today's mtime on old zips.

    Age has to come from the month the archive names, or a restored backup either
    keeps everything forever or drops all of it, depending on how it was moved.
    """
    with get_conn(tmp_db) as conn:
        _seed(conn, "203.0.113.2", "2020-01")
        archive.archive_month(conn, "2020-01")
        archive.set_archive_keep_months(conn, 12)
    # Touch the zip so the filesystem says it is brand new.
    zip_path = tmp_archive_dir / "2020-01.zip"
    zip_path.touch()
    with get_conn(tmp_db) as conn:
        assert archive.expired_archives(conn, datetime(2026, 8, 29, tzinfo=timezone.utc)) == [
            "2020-01"
        ]


def test_a_pinned_month_does_not_expire(tmp_db, tmp_archive_dir):
    """A pin means somebody re-imported that month on purpose.

    due_months() already refuses to re-archive a pinned month; deleting its zip
    would take away the thing they brought back, which is worse.
    """
    with get_conn(tmp_db) as conn:
        _seed(conn, "203.0.113.3", "2020-01")
        archive.archive_month(conn, "2020-01")
        archive.set_archive_keep_months(conn, 12)
        archive.restore_month(conn, "2020-01")
    with get_conn(tmp_db) as conn:
        assert archive.pin_expiry(conn, "2020-01")
        assert archive.expired_archives(conn, datetime(2026, 8, 29, tzinfo=timezone.utc)) == []


def test_the_keep_window_cannot_undercut_the_rolling_window(tmp_db):
    """Below rolling + 1 the same pass would write a zip and delete it again.

    A month reaches the archive once it is older than the rolling window, so a
    shorter keep window is not a configuration — it is a way of paying for a zip
    nobody gets. The stored value is raised to the floor and returned, so the
    caller can show what actually happened.
    """
    with get_conn(tmp_db) as conn:
        archive.set_rolling_months(conn, 3)
        assert archive.set_archive_keep_months(conn, 1) == 4
        assert archive.get_archive_keep_months(conn) == 4
        # Keeping forever stays reachable — it is not "shorter than rolling".
        assert archive.set_archive_keep_months(conn, 0) == archive.ARCHIVE_KEEP_FOREVER


def test_the_daily_pass_drops_an_expired_archive(tmp_db, tmp_archive_dir):
    with get_conn(tmp_db) as conn:
        _seed(conn, "203.0.113.4", "2020-01")
        archive.archive_month(conn, "2020-01")
        archive.set_archive_keep_months(conn, 12)
    assert (tmp_archive_dir / "2020-01.zip").exists()
    result = run_retention(datetime(2026, 8, 29, tzinfo=timezone.utc))
    assert result["dropped"] == ["2020-01"]
    assert not (tmp_archive_dir / "2020-01.zip").exists()


def test_lifetime_does_not_expire_archives(tmp_db, tmp_archive_dir):
    """The mode says nothing is archived and nothing is deleted. Both halves.

    The keep window lives on the rolling half of the settings page, so in
    lifetime it would act while being invisible — an operator who set a window,
    then switched to the mode that promises no deletion, would keep losing
    archives with nothing on the page to explain it.
    """
    with get_conn(tmp_db) as conn:
        _seed(conn, "203.0.113.5", "2020-01")
        archive.archive_month(conn, "2020-01")
        archive.set_archive_keep_months(conn, 12)
        archive.set_mode(conn, archive.MODE_LIFETIME)
    result = run_retention(datetime(2026, 8, 29, tzinfo=timezone.utc))
    assert result["dropped"] == []
    assert (tmp_archive_dir / "2020-01.zip").exists()
