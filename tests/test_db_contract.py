"""What get_conn() promises, and what a migration does to an older database.

Neither had a test. Nothing in the suite asserted WAL, foreign_keys, the busy
timeout, or the commit/rollback contract — so `PRAGMA busy_timeout=5000`
silently overrode DB_CONNECTION_TIMEOUT everywhere but vacuum(), and the
ON DELETE CASCADE that purge_orphaned_intel depends on rested on a pragma no
test knew about. And only the Shodan phase-B migration was ever run against an
existing database; the sixteen visits columns and the ip_intel ones were not,
which is how `created_at` sat in the schema but in no migration list.
"""

import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from src.config import settings
from src.db import _add_col_if_missing, get_conn, init_db


class TestTheConnectionContract:
    def test_wal_is_on(self, tmp_db):
        with get_conn() as conn:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"

    def test_foreign_keys_are_on(self, tmp_db):
        """purge_orphaned_intel deletes ip_intel rows and relies on the cascade
        to clear the five child tables. Without this pragma they are orphaned."""
        with get_conn() as conn:
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    def test_the_busy_timeout_comes_from_the_setting(self, tmp_db, monkeypatch):
        """It was hardcoded to 5000, which overrode the configured value
        everywhere except vacuum() and made the setting dead config."""
        monkeypatch.setattr(settings, "db_connection_timeout", 3)
        with get_conn() as conn:
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 3000

    def test_it_commits_on_a_clean_exit(self, tmp_db):
        with get_conn() as conn:
            conn.execute("INSERT INTO processor_state (key, value) VALUES ('k', 'v')")
        with get_conn() as conn:
            assert (
                conn.execute("SELECT value FROM processor_state WHERE key='k'").fetchone()[0]
                == "v"
            )

    def test_it_rolls_back_on_an_exception(self, tmp_db):
        with pytest.raises(RuntimeError):
            with get_conn() as conn:
                conn.execute("INSERT INTO processor_state (key, value) VALUES ('k', 'v')")
                raise RuntimeError("boom")
        with get_conn() as conn:
            assert (
                conn.execute("SELECT COUNT(*) FROM processor_state WHERE key='k'").fetchone()[0]
                == 0
            )

    def test_the_connection_is_closed_either_way(self, tmp_db):
        held = None
        with get_conn() as conn:
            held = conn
        with pytest.raises(sqlite3.ProgrammingError):
            held.execute("SELECT 1")

    def test_a_failing_pragma_does_not_leak_the_connection(self, tmp_db):
        """The connection used to be built before the try, so a pragma that
        raised — a lock held elsewhere, a read-only mount, a full disk — left a
        live handle that nothing ever closed."""
        conn = MagicMock()
        conn.execute.side_effect = sqlite3.OperationalError("database is locked")

        with patch("src.db.sqlite3.connect", return_value=conn):
            with pytest.raises(sqlite3.OperationalError):
                with get_conn():
                    pass

        conn.close.assert_called_once()


class TestMigratingAnOlderDatabase:
    """Only the Shodan phase-B step had ever been run against an existing
    database. These build a v1-shaped one and put init_db over it."""

    @pytest.fixture
    def v1_db(self, tmp_path, monkeypatch):
        path = tmp_path / "v1.db"
        conn = sqlite3.connect(str(path))
        conn.executescript(
            """
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                path TEXT DEFAULT '',
                status INTEGER DEFAULT 0
            );
            CREATE TABLE ip_intel (
                ip TEXT PRIMARY KEY,
                country TEXT DEFAULT '',
                fetched_at TEXT
            );
            INSERT INTO visits (ip, timestamp, path, status)
                 VALUES ('93.184.216.34', '2026-06-01T10:00:00+00:00', '/', 200);
            INSERT INTO ip_intel (ip, country, fetched_at)
                 VALUES ('93.184.216.34', 'Germany', '2026-06-01T10:00:00+00:00');
            """
        )
        conn.commit()
        conn.close()

        import src.db as db_module

        monkeypatch.setattr(db_module, "_DB_PATH", path)
        monkeypatch.setattr(settings, "db_path", path)
        return path

    def _cols(self, path, table):
        conn = sqlite3.connect(str(path))
        try:
            return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        finally:
            conn.close()

    def test_every_visits_column_arrives(self, v1_db):
        init_db(v1_db)
        cols = self._cols(v1_db, "visits")
        for expected in (
            "server_port",
            "browser",
            "os",
            "device",
            "sec_fetch_dest",
            "ssl_session_reused",
        ):
            assert expected in cols, f"{expected} missing after migration"

    def test_created_at_arrives_too(self, v1_db):
        """In SCHEMA from the first version and in no migration list, so a
        database older than it never received the column."""
        init_db(v1_db)
        assert "created_at" in self._cols(v1_db, "visits")

    def test_the_intel_columns_arrive(self, v1_db):
        init_db(v1_db)
        cols = self._cols(v1_db, "ip_intel")
        for expected in ("reverse_dns", "is_tor", "dnsbl_listed", "visitor_class"):
            assert expected in cols, f"{expected} missing after migration"

    def test_the_child_tables_are_created(self, v1_db):
        init_db(v1_db)
        conn = sqlite3.connect(str(v1_db))
        try:
            names = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        finally:
            conn.close()
        assert {"ip_intel_ports", "ip_intel_tags", "ip_intel_vulns"} <= names

    def test_the_existing_rows_survive(self, v1_db):
        init_db(v1_db)
        with get_conn(v1_db) as conn:
            row = conn.execute("SELECT ip, path, status FROM visits").fetchone()
        assert (row["ip"], row["path"], row["status"]) == ("93.184.216.34", "/", 200)

    def test_running_it_twice_changes_nothing(self, v1_db):
        init_db(v1_db)
        first = self._cols(v1_db, "visits")
        init_db(v1_db)
        assert self._cols(v1_db, "visits") == first
        with get_conn(v1_db) as conn:
            assert conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0] == 1


class TestTheMigrationGuardsAreRealChecks:
    """They were assertions, which `python -O` strips — and they are the only
    thing between an f-string and an arbitrary SQL identifier."""

    def test_an_unknown_table_is_refused(self, tmp_db):
        with get_conn() as conn:
            with pytest.raises(ValueError, match="unknown migration table"):
                _add_col_if_missing(conn, "sqlite_master", "x", "TEXT")

    def test_a_non_identifier_column_is_refused(self, tmp_db):
        with get_conn() as conn:
            with pytest.raises(ValueError, match="invalid column name"):
                _add_col_if_missing(conn, "visits", "x; DROP TABLE visits", "TEXT")

    def test_an_allowed_column_is_added_once(self, tmp_db):
        with get_conn() as conn:
            _add_col_if_missing(conn, "visits", "some_new_col", "TEXT DEFAULT ''")
            _add_col_if_missing(conn, "visits", "some_new_col", "TEXT DEFAULT ''")
            cols = [r[1] for r in conn.execute("PRAGMA table_info(visits)")]
        assert cols.count("some_new_col") == 1
