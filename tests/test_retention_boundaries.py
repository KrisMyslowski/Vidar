"""Where one retention pass ends and the next begins.

Two boundaries were in the wrong place. The month was read outside the
transaction that deleted it — sqlite3's legacy isolation opens a transaction on
the first DML and not before, so the SELECTs that built the zip ran in
autocommit while the DELETE opened its own, and anything the tailer inserted for
that month in between was deleted without ever reaching the archive. And the
whole pass was a single transaction across every due month, while each zip was
renamed into place the moment it was written: a failure on the third month rolled
back the deletions for the first two, whose archives were already on disk, and
the write lock was held for the duration — which is what put the tailer into its
exponential backoff every night.
"""

import sqlite3
from unittest.mock import patch

import pytest

from src import archive
from src.archive import archive_month, archive_path
from src.db import get_conn
from src.queries import get_state, insert_visit, upsert_ip_intel
from src.retention import run_retention


def _seed(conn, month: str, ip: str = "93.184.216.34") -> None:
    insert_visit(conn, ip=ip, timestamp=f"{month}-15T10:00:00+00:00", path="/")
    upsert_ip_intel(conn, {"ip": ip, "country": "Germany", "fetched_at": "2026-01-01T00:00:00"})


def _months(conn) -> list[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT substr(timestamp,1,7) FROM visits")]


class TestTheMonthIsLockedBeforeItIsRead:
    def test_archive_month_holds_the_write_lock_while_it_reads(self, tmp_db):
        """Proven by a second connection failing to write during the read, not
        by inspecting a flag."""
        blocked = []

        real_write_zip = archive.write_zip

        def write_zip_and_probe(conn, month, path):
            other = sqlite3.connect(str(tmp_db), timeout=0)
            try:
                other.execute("PRAGMA busy_timeout=0")
                other.execute(
                    "INSERT INTO visits (ip, timestamp) VALUES ('1.1.1.1', ?)",
                    (f"{month}-16T10:00:00+00:00",),
                )
                other.commit()
                blocked.append(False)
            except sqlite3.OperationalError:
                blocked.append(True)
            finally:
                other.close()
            return real_write_zip(conn, month, path)

        with get_conn() as conn:
            _seed(conn, "2026-04")

        with patch.object(archive, "write_zip", write_zip_and_probe):
            with get_conn() as conn:
                archive_month(conn, "2026-04")

        assert blocked == [True], "another writer got in between the read and the delete"

    def test_it_still_works_inside_a_transaction_a_caller_opened(self, tmp_db):
        with get_conn() as conn:
            _seed(conn, "2026-04")
        with get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            archive_month(conn, "2026-04")
        assert archive_path("2026-04").exists()


class TestOneTransactionPerMonth:
    def test_a_later_failure_does_not_undo_an_earlier_month(self, tmp_db, monkeypatch):
        with get_conn() as conn:
            for month in ("2026-01", "2026-02"):
                _seed(conn, month, ip=f"93.184.216.{month[-1]}")
            # A current month so the window has something to keep.
            _seed(conn, "2026-08", ip="203.0.113.9")

        real = archive.archive_month
        seen: list[str] = []

        def fail_on_the_second(conn, month):
            seen.append(month)
            if len(seen) == 2:
                raise RuntimeError("disk full")
            return real(conn, month)

        monkeypatch.setattr("src.retention.archive_month", fail_on_the_second)
        monkeypatch.setattr("src.retention.due_months", lambda conn, now: ["2026-01", "2026-02"])

        with pytest.raises(RuntimeError):
            run_retention()

        assert archive_path("2026-01").exists(), "the first month was written"
        with get_conn() as conn:
            months = _months(conn)
        assert "2026-01" not in months, "and its rows are gone, not rolled back"
        assert "2026-02" in months, "the month that failed keeps its rows"

    def test_a_normal_pass_archives_every_due_month(self, tmp_db, monkeypatch):
        with get_conn() as conn:
            _seed(conn, "2026-01", ip="93.184.216.1")
            _seed(conn, "2026-02", ip="93.184.216.2")
            _seed(conn, "2026-08", ip="203.0.113.9")

        monkeypatch.setattr("src.retention.due_months", lambda conn, now: ["2026-01", "2026-02"])
        result = run_retention()

        assert result["archived"] == ["2026-01", "2026-02"]
        assert archive_path("2026-01").exists() and archive_path("2026-02").exists()
        with get_conn() as conn:
            assert _months(conn) == ["2026-08"]
            assert get_state(conn, "retention.last_run")


class TestTheTemporaryFileCannotCollide:
    def test_two_passes_do_not_share_a_temp_name(self, tmp_db):
        """`python -m src.retention` beside the running service is documented as
        supported, and a fixed temp name is two writers on one file."""
        names = []

        real_write_zip = archive.write_zip

        def record(conn, month, path):
            names.append(path.name)
            return real_write_zip(conn, month, path)

        with get_conn() as conn:
            _seed(conn, "2026-04")
            _seed(conn, "2026-05", ip="93.184.216.35")

        with patch.object(archive, "write_zip", record):
            with get_conn() as conn:
                archive_month(conn, "2026-04")
            with get_conn() as conn:
                archive_month(conn, "2026-05")

        assert len(set(names)) == 2
        for name in names:
            assert str(archive.os.getpid()) in name, "the pid distinguishes the writer"

    def test_a_temp_file_is_never_listed_as_an_archive(self, tmp_db):
        with get_conn() as conn:
            _seed(conn, "2026-04")
            archive_month(conn, "2026-04")
        listed = {a["month"] for a in archive.list_archives()}
        assert listed == {"2026-04"}


class TestAClearedPinLeavesNoRow:
    def test_it_is_deleted_not_blanked(self, tmp_db):
        """Writing "" left one processor_state row per month ever restored."""
        with get_conn() as conn:
            archive._set_pin(conn, "2026-04", "2026-05-01T00:00:00+00:00")
            assert archive.pin_expiry(conn, "2026-04")

            archive._clear_pin(conn, "2026-04")
            assert archive.pin_expiry(conn, "2026-04") is None
            rows = conn.execute(
                "SELECT COUNT(*) FROM processor_state WHERE key LIKE 'archive.pin.%'"
            ).fetchone()[0]
        assert rows == 0
