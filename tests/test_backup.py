"""Snapshots of the live database.

The property that matters is not "a file appeared" but "the file is a database
that still holds the rows" — a torn copy of a WAL database looks fine until
something opens it. So the tests open every snapshot they make.
"""

import gzip
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from src import backup
from src.db import get_conn
from src.queries import insert_visit


@pytest.fixture
def db_with_rows(tmp_db):
    with get_conn() as conn:
        for i in range(25):
            insert_visit(conn, ip=f"1.2.3.{i}", timestamp="2026-08-14T10:00:00+00:00", path="/")
    return tmp_db


def _rows_in(path):
    """Open a snapshot the way a restore would, and count what survived."""
    raw = path.with_suffix(".opened")
    with gzip.open(path, "rb") as src:
        raw.write_bytes(src.read())
    try:
        return sqlite3.connect(raw).execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    finally:
        raw.unlink(missing_ok=True)


class TestTheSnapshot:
    def test_it_is_a_database_that_still_has_the_rows(self, db_with_rows, tmp_backup_dir):
        path = backup.create_snapshot()
        assert _rows_in(path) == 25

    def test_it_is_compressed(self, db_with_rows, tmp_backup_dir):
        path = backup.create_snapshot()
        assert path.name.endswith(".db.gz")
        assert path.stat().st_size < db_with_rows.stat().st_size

    def test_it_is_named_after_the_database_and_the_day(self, db_with_rows, tmp_backup_dir):
        path = backup.create_snapshot(datetime(2026, 8, 14, tzinfo=timezone.utc))
        assert path.name == "test-2026-08-14.db.gz"

    def test_a_second_run_the_same_day_replaces_the_first(self, db_with_rows, tmp_backup_dir):
        now = datetime(2026, 8, 14, tzinfo=timezone.utc)
        backup.create_snapshot(now)
        with get_conn() as conn:
            insert_visit(conn, ip="9.9.9.9", timestamp="2026-08-14T11:00:00+00:00", path="/")
        path = backup.create_snapshot(now)
        assert len(list(tmp_backup_dir.glob("*.db.gz"))) == 1
        assert _rows_in(path) == 26

    def test_it_leaves_no_temporaries_behind(self, db_with_rows, tmp_backup_dir):
        backup.create_snapshot()
        assert [p.name for p in tmp_backup_dir.iterdir() if ".tmp" in p.name] == []

    def test_two_passes_at_once_both_finish(self, db_with_rows, tmp_backup_dir):
        """The daily task is due the moment the service starts, and "Back up
        now" is one click away — so they overlap. Sharing one temp name, the
        first rename pulled the file out from under the second and it died on a
        FileNotFoundError. Production hit this on the very first run.
        """
        import threading

        errors = []

        def run():
            try:
                backup.create_snapshot(datetime(2026, 8, 14, tzinfo=timezone.utc))
            except Exception as e:  # noqa: BLE001 — the point is that none escape
                errors.append(e)

        threads = [threading.Thread(target=run) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        snaps = backup.list_snapshots()
        assert len(snaps) == 1
        assert _rows_in(tmp_backup_dir / snaps[0]["name"]) == 25
        assert [p.name for p in tmp_backup_dir.iterdir() if ".tmp" in p.name] == []

    def test_no_database_is_reported_not_raised(self, tmp_db, tmp_backup_dir, monkeypatch):
        """A missing file is an operator problem, not a crashed background task."""
        from src import config

        monkeypatch.setattr(config.settings, "db_path", tmp_db.parent / "gone.db")
        assert backup.create_snapshot() is None


class TestPruning:
    def test_it_keeps_the_newest_and_drops_the_rest(self, db_with_rows, tmp_backup_dir):
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        for i in range(5):
            backup.create_snapshot(start + timedelta(days=i))
        backup.prune(keep=2)
        assert [s["name"] for s in backup.list_snapshots()] == [
            "test-2026-08-05.db.gz",
            "test-2026-08-04.db.gz",
        ]

    def test_keep_zero_still_keeps_one(self, db_with_rows, tmp_backup_dir):
        """No setting should be able to express "delete the snapshot just taken"."""
        backup.create_snapshot()
        backup.prune(keep=0)
        assert len(backup.list_snapshots()) == 1


class TestThePass:
    def test_it_writes_prunes_and_stamps(self, db_with_rows, tmp_backup_dir, monkeypatch):
        from src import config

        monkeypatch.setattr(config.settings, "backup_keep", 1)
        backup.create_snapshot(datetime(2026, 8, 1, tzinfo=timezone.utc))
        result = backup.run_backup(datetime(2026, 8, 14, tzinfo=timezone.utc))

        assert result["written"] == "test-2026-08-14.db.gz"
        assert result["pruned"] == ["test-2026-08-01.db.gz"]
        with get_conn() as conn:
            assert backup.last_run(conn) == "2026-08-14T00:00:00+00:00"

    def test_disabled_writes_nothing(self, db_with_rows, tmp_backup_dir, monkeypatch):
        from src import config

        monkeypatch.setattr(config.settings, "backup_enabled", False)
        assert backup.run_backup()["written"] is None
        assert backup.list_snapshots() == []

    def test_no_room_declines_instead_of_filling_the_disk(
        self, db_with_rows, tmp_backup_dir, monkeypatch
    ):
        """The guard exists because a backup that fills the volume takes the
        service down — a worse outcome than the one it guards against."""
        import shutil

        monkeypatch.setattr(
            backup.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(100, 100, 0)
        )
        assert backup.create_snapshot() is None
        assert backup.list_snapshots() == []


class TestTheDownloadGate:
    """The name reaches the filesystem from a URL segment."""

    @pytest.mark.parametrize(
        "name",
        ["../../etc/passwd", "..%2Fx.db.gz", "x.db.gz/../../y", "", "nope.txt", "a/b.db.gz"],
    )
    def test_it_refuses_anything_that_is_not_a_plain_snapshot_name(self, tmp_backup_dir, name):
        assert backup.resolve_snapshot(name) is None

    def test_it_resolves_a_real_one(self, db_with_rows, tmp_backup_dir):
        path = backup.create_snapshot()
        assert backup.resolve_snapshot(path.name) == path.resolve()

    def test_a_well_formed_name_that_does_not_exist_is_none(self, tmp_backup_dir):
        assert backup.resolve_snapshot("test-2026-01-01.db.gz") is None
