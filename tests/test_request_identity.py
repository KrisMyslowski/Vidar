"""Telling a re-read of the log from real traffic.

`visits` had no way to recognise a duplicate, and none could be built from what
the log carried: $time_iso8601 resolves to the second, so two identical requests
in one second are indistinguishable from one request ingested twice. A unique
constraint over (time, ip, request) would have dropped genuine visits, which is
worse than counting some twice — under-reporting nobody notices.

nginx's $connection with $connection_requests numbers a request uniquely for the
life of the process. With that in the log there is a real key, and the index is
partial so it only applies where the log actually provides one: rows written
before the field existed, and anything logged with the older format, carry
connection = 0 and are inserted exactly as before.
"""

import json
import sqlite3

import pytest

from src.db import get_conn, init_db
from src.log_processor import parse_log_line, process_entry
from src.queries import insert_visit

STAMP = "2026-06-13T10:00:00+00:00"


def _visit(conn, **over):
    kwargs = {"ip": "93.184.216.34", "timestamp": STAMP, "path": "/", "status": 200}
    kwargs.update(over)
    return insert_visit(conn, **kwargs)


def _count(conn):
    return conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]


class TestTheIdentityIsTheConnectionAndItsCounter:
    def test_the_same_request_twice_is_stored_once(self, tmp_db):
        with get_conn() as conn:
            first = _visit(conn, connection=17, connection_requests=3)
            second = _visit(conn, connection=17, connection_requests=3)
            assert _count(conn) == 1
        assert first > 0
        assert second == 0, "an ignored duplicate reports no row id"

    def test_two_requests_on_one_connection_are_two_visits(self, tmp_db):
        with get_conn() as conn:
            _visit(conn, connection=17, connection_requests=1)
            _visit(conn, connection=17, connection_requests=2)
            assert _count(conn) == 2

    def test_two_connections_in_the_same_second_are_two_visits(self, tmp_db):
        """The case a (time, ip, request) key would have thrown away."""
        with get_conn() as conn:
            _visit(conn, connection=17, connection_requests=1)
            _visit(conn, connection=18, connection_requests=1)
            assert _count(conn) == 2

    def test_the_same_counter_in_a_different_second_is_a_different_visit(self, tmp_db):
        """$connection restarts from one when nginx does."""
        with get_conn() as conn:
            _visit(conn, connection=1, connection_requests=1)
            _visit(
                conn, connection=1, connection_requests=1, timestamp="2026-06-13T10:00:01+00:00"
            )
            assert _count(conn) == 2


class TestALogWithoutTheFieldIsUnaffected:
    """The partial index earns its WHERE here. Without it every one of these
    would collide on (timestamp, 0, 0)."""

    def test_identical_visits_without_a_connection_are_all_kept(self, tmp_db):
        with get_conn() as conn:
            for _ in range(5):
                _visit(conn)
            assert _count(conn) == 5

    def test_a_mix_of_old_and_new_rows_behaves_per_row(self, tmp_db):
        with get_conn() as conn:
            _visit(conn)  # legacy format
            _visit(conn)  # legacy, kept
            _visit(conn, connection=5, connection_requests=1)  # new
            _visit(conn, connection=5, connection_requests=1)  # new, ignored
            assert _count(conn) == 3


class TestTheFieldTravelsFromNginxToTheRow:
    def test_the_log_format_emits_it(self):
        from pathlib import Path

        conf = (
            Path(__file__).resolve().parent.parent / "deploy/nginx-log-format.conf"
        ).read_text()
        assert '"connection":$connection,' in conf

    def test_a_log_line_carrying_it_reaches_the_visit(self, tmp_db):
        entry = parse_log_line(
            json.dumps(
                {
                    "time": STAMP,
                    "remote_addr": "93.184.216.34",
                    "request": "GET / HTTP/1.1",
                    "status": 200,
                    "body_bytes_sent": 10,
                    "request_method": "GET",
                    "request_uri": "/",
                    "connection": 4242,
                    "connection_requests": 7,
                }
            )
        )
        assert entry.connection == 4242
        data = process_entry(entry)
        assert data["connection"] == 4242

        with get_conn() as conn:
            insert_visit(conn, **data)
            row = conn.execute("SELECT connection, connection_requests FROM visits").fetchone()
        assert (row["connection"], row["connection_requests"]) == (4242, 7)

    def test_a_line_without_it_still_parses(self, tmp_db):
        entry = parse_log_line(
            json.dumps(
                {
                    "time": STAMP,
                    "remote_addr": "93.184.216.34",
                    "request": "GET / HTTP/1.1",
                    "status": 200,
                    "body_bytes_sent": 10,
                }
            )
        )
        assert entry.connection == 0


class TestTheMigrationAddsItToAnExistingDatabase:
    @pytest.fixture
    def older(self, tmp_path, monkeypatch):
        path = tmp_path / "older.db"
        init_db(path)
        conn = sqlite3.connect(str(path))
        # Rebuild the table without the column, keeping rows that would collide
        # on the partial index if it applied to them.
        conn.executescript(
            """
            DROP INDEX IF EXISTS idx_visits_request_identity;
            ALTER TABLE visits DROP COLUMN connection;
            INSERT INTO visits (ip, timestamp, path, status)
                 VALUES ('93.184.216.34', '2026-06-13T10:00:00+00:00', '/', 200),
                        ('93.184.216.34', '2026-06-13T10:00:00+00:00', '/', 200);
            """
        )
        conn.commit()
        conn.close()

        import src.db as db_module
        from src.config import settings

        monkeypatch.setattr(db_module, "_DB_PATH", path)
        monkeypatch.setattr(settings, "db_path", path)
        return path

    def test_the_column_and_the_index_arrive(self, older):
        init_db(older)
        conn = sqlite3.connect(str(older))
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(visits)")}
            idx = {r[1] for r in conn.execute("PRAGMA index_list(visits)")}
        finally:
            conn.close()
        assert "connection" in cols
        assert "idx_visits_request_identity" in idx

    def test_the_rows_that_predate_it_survive(self, older):
        """They all carry connection = 0, so a non-partial index would have
        made this migration fail outright — or worse, succeed and drop one."""
        init_db(older)
        with get_conn(older) as conn:
            assert _count(conn) == 2

    def test_and_deduplication_works_from_then_on(self, older):
        init_db(older)
        with get_conn(older) as conn:
            _visit(conn, connection=9, connection_requests=1)
            _visit(conn, connection=9, connection_requests=1)
            assert _count(conn) == 3
