"""The one migration that reads data out of a column before dropping it.

Phase B of 4.3 moves the Shodan CSV columns into the child tables and then
removes them, so it is the only step in init_db() where getting the order or
the guard wrong loses something that cannot be recomputed — Shodan will not
answer for an IP it no longer scans.

The guard was "run the backfill only if ip_intel_ports is empty", a proxy for
"the backfill has not run yet". Anything else that put a row in that table made
it read "already done", and the columns were dropped unread. retention calls
init_db() once a day, long after runtime upserts have populated children, so
the two were not as far apart as the proxy assumed.

The atomicity it leaned on is real and worth pinning: sqlite3 opens a
transaction on the first INSERT and the ALTER TABLE statements join it, so an
interrupted run rolls back both the rows and the drops.
"""

import sqlite3

import pytest

from src.db import _connect, init_db

LEGACY = ("open_ports", "tags", "hostnames", "cpes", "vulns")


def _legacy_db(path):
    """A database at 4.2: children present but empty, CSV columns still there."""
    init_db(path)
    conn = _connect(path)
    for col in LEGACY:
        conn.execute(f"ALTER TABLE ip_intel ADD COLUMN {col} TEXT DEFAULT ''")
    conn.commit()
    conn.close()
    return path


def _cols(path):
    conn = sqlite3.connect(str(path))
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(ip_intel)")}
    finally:
        conn.close()


def _children(path, ip):
    conn = sqlite3.connect(str(path))
    try:
        return {
            "ports": [
                r[0] for r in conn.execute("SELECT port FROM ip_intel_ports WHERE ip=?", (ip,))
            ],
            "tags": [
                r[0] for r in conn.execute("SELECT tag FROM ip_intel_tags WHERE ip=?", (ip,))
            ],
            "vulns": [
                r[0] for r in conn.execute("SELECT vuln FROM ip_intel_vulns WHERE ip=?", (ip,))
            ],
        }
    finally:
        conn.close()


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    path = _legacy_db(tmp_path / "legacy.db")
    import src.db as db_module
    from src.config import settings

    monkeypatch.setattr(db_module, "_DB_PATH", path)
    monkeypatch.setattr(settings, "db_path", path)
    return path


def _seed(path, ip, ports="22,443", tags="cloud", vulns="CVE-2021-44228"):
    conn = _connect(path)
    conn.execute(
        "INSERT INTO ip_intel (ip, open_ports, tags, vulns) VALUES (?, ?, ?, ?)",
        (ip, ports, tags, vulns),
    )
    conn.commit()
    conn.close()


class TestTheBackfillRunsWhateverElseIsInTheTable:
    def test_a_populated_child_table_no_longer_skips_it(self, legacy):
        """The failure the guard created: another IP's runtime data in
        ip_intel_ports made the migration decide it had already run."""
        _seed(legacy, "93.184.216.34")
        conn = _connect(legacy)
        conn.execute("INSERT INTO ip_intel (ip) VALUES ('198.51.100.7')")
        conn.execute("INSERT INTO ip_intel_ports (ip, port) VALUES ('198.51.100.7', 8080)")
        conn.commit()
        conn.close()

        init_db(legacy)

        assert _children(legacy, "93.184.216.34")["ports"] == [22, 443]
        assert _cols(legacy).isdisjoint(LEGACY), "the columns are gone once read"

    def test_the_ordinary_upgrade_still_works(self, legacy):
        _seed(legacy, "93.184.216.34")
        init_db(legacy)
        got = _children(legacy, "93.184.216.34")
        assert got["ports"] == [22, 443]
        assert got["tags"] == ["cloud"]
        assert got["vulns"] == ["CVE-2021-44228"]

    def test_running_it_again_changes_nothing(self, legacy):
        _seed(legacy, "93.184.216.34")
        init_db(legacy)
        first = _children(legacy, "93.184.216.34")
        init_db(legacy)
        assert _children(legacy, "93.184.216.34") == first

    def test_junk_in_a_port_list_is_skipped_not_stored(self, legacy):
        _seed(legacy, "93.184.216.34", ports="22,http,443,")
        init_db(legacy)
        assert _children(legacy, "93.184.216.34")["ports"] == [22, 443]

    def test_a_row_with_no_shodan_data_is_fine(self, legacy):
        _seed(legacy, "93.184.216.34", ports="", tags="", vulns="")
        init_db(legacy)
        assert _children(legacy, "93.184.216.34") == {"ports": [], "tags": [], "vulns": []}


class TestAnInterruptedMigrationLosesNothing:
    def test_a_crash_mid_backfill_leaves_the_columns_in_place(self, legacy, monkeypatch):
        """What makes the whole step safe: the first INSERT opens a transaction
        and the ALTER TABLE ... DROP COLUMN statements join it, so nothing is
        committed until everything is."""
        _seed(legacy, "93.184.216.34")

        import src.db as db_module

        real = db_module._backfill_chunk

        def die_after_one(conn, chunk):
            real(conn, chunk[:1])
            raise RuntimeError("killed mid-migration")

        monkeypatch.setattr(db_module, "_backfill_chunk", die_after_one)
        with pytest.raises(RuntimeError):
            init_db(legacy)

        assert set(LEGACY) <= _cols(legacy), "the source columns survive a failed run"
        assert _children(legacy, "93.184.216.34")["ports"] == [], "and so does the rollback"

    def test_and_the_retry_completes_it(self, legacy, monkeypatch):
        _seed(legacy, "93.184.216.34")

        import src.db as db_module

        real = db_module._backfill_chunk
        monkeypatch.setattr(
            db_module, "_backfill_chunk", lambda c, ch: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        with pytest.raises(RuntimeError):
            init_db(legacy)

        monkeypatch.setattr(db_module, "_backfill_chunk", real)
        init_db(legacy)

        assert _children(legacy, "93.184.216.34")["ports"] == [22, 443]
        assert _cols(legacy).isdisjoint(LEGACY)


class TestItDoesNotNeedTheWholeTable:
    def test_rows_are_read_in_chunks(self, legacy, monkeypatch):
        """It runs over every ip_intel row of the database it is upgrading."""
        import src.db as db_module

        sizes = []
        real = db_module._backfill_chunk

        def record(conn, chunk):
            sizes.append(len(chunk))
            real(conn, chunk)

        conn = _connect(legacy)
        for i in range(2500):
            conn.execute(
                "INSERT INTO ip_intel (ip, open_ports) VALUES (?, '22')",
                (f"203.0.113.{i // 254}.{i % 254}",),
            )
        conn.commit()
        conn.close()

        monkeypatch.setattr(db_module, "_backfill_chunk", record)
        init_db(legacy)

        assert sizes == [1000, 1000, 500], f"expected chunked reads, got {sizes}"
