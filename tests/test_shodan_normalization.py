"""Tests for 4.3 Shodan field normalization: child tables, dual-write sync,
backfill, cascade delete, and the per-value filter queries."""

from src.db import _backfill_shodan_children, get_conn, init_db
from src.queries import (
    count_shodan_hosts,
    get_shodan_hosts,
    get_top_ports,
    get_top_tags,
    get_top_vulns,
    get_visitor_detail,
    insert_visit,
    purge_orphaned_intel,
    upsert_ip_intel,
)


def _intel_cols(conn):
    return {r[1] for r in conn.execute("PRAGMA table_info(ip_intel)").fetchall()}


def _child(conn, table, col, ip):
    return {
        r[0] for r in conn.execute(f"SELECT {col} FROM {table} WHERE ip = ?", (ip,)).fetchall()
    }


def test_upsert_syncs_child_tables(tmp_db):
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(
            conn,
            {
                "ip": "1.2.3.4",
                "open_ports": "22,80,443",
                "vulns": "CVE-2021-1,CVE-2021-2",
                "cpes": "cpe:/a:openbsd:openssh",
                "tags": "scanner,vpn",
                "hostnames": "a.example.com",
            },
        )
    with get_conn(tmp_db) as conn:
        assert _child(conn, "ip_intel_ports", "port", "1.2.3.4") == {22, 80, 443}
        assert _child(conn, "ip_intel_vulns", "vuln", "1.2.3.4") == {"CVE-2021-1", "CVE-2021-2"}
        assert _child(conn, "ip_intel_cpes", "cpe", "1.2.3.4") == {"cpe:/a:openbsd:openssh"}
        assert _child(conn, "ip_intel_tags", "tag", "1.2.3.4") == {"scanner", "vpn"}
        assert _child(conn, "ip_intel_hostnames", "hostname", "1.2.3.4") == {"a.example.com"}


def test_reupsert_removes_stale_child_rows(tmp_db):
    """A port that closes (or a CVE that's patched) is dropped on re-enrichment."""
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "1.2.3.4", "open_ports": "22,80,443"})
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "1.2.3.4", "open_ports": "22"})
    with get_conn(tmp_db) as conn:
        assert _child(conn, "ip_intel_ports", "port", "1.2.3.4") == {22}


def test_upsert_ignores_non_integer_ports(tmp_db):
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "1.2.3.4", "open_ports": "22,foo,443"})
    with get_conn(tmp_db) as conn:
        assert _child(conn, "ip_intel_ports", "port", "1.2.3.4") == {22, 443}


def test_backfill_from_csv(tmp_db):
    # Simulate a pre-4.3 DB: re-add the legacy CSV columns, seed a row, then backfill.
    with get_conn(tmp_db) as conn:
        for col in ("open_ports", "vulns", "cpes", "tags", "hostnames"):
            conn.execute(f"ALTER TABLE ip_intel ADD COLUMN {col} TEXT DEFAULT ''")
        conn.execute(
            "INSERT INTO ip_intel (ip, open_ports, vulns, tags) VALUES (?, ?, ?, ?)",
            ("9.9.9.9", "53,853", "CVE-2020-1", "dns"),
        )
    with get_conn(tmp_db) as conn:
        _backfill_shodan_children(conn)
    with get_conn(tmp_db) as conn:
        assert _child(conn, "ip_intel_ports", "port", "9.9.9.9") == {53, 853}
        assert _child(conn, "ip_intel_vulns", "vuln", "9.9.9.9") == {"CVE-2020-1"}
        assert _child(conn, "ip_intel_tags", "tag", "9.9.9.9") == {"dns"}


def test_phase_b_migration_backfills_then_drops_csv(tmp_db):
    """init_db on a legacy DB (CSV columns present, child tables empty) backfills the
    child tables and then drops the columns."""
    with get_conn(tmp_db) as conn:
        for col in ("open_ports", "vulns", "cpes", "tags", "hostnames"):
            conn.execute(f"ALTER TABLE ip_intel ADD COLUMN {col} TEXT DEFAULT ''")
        conn.execute(
            "INSERT INTO ip_intel (ip, open_ports, tags) VALUES (?, ?, ?)",
            ("8.8.8.8", "443,8080", "scanner"),
        )
        assert "open_ports" in _intel_cols(conn)

    init_db(tmp_db)  # runs the Phase B migration

    with get_conn(tmp_db) as conn:
        cols = _intel_cols(conn)
        for col in ("open_ports", "vulns", "cpes", "tags", "hostnames"):
            assert col not in cols
        assert _child(conn, "ip_intel_ports", "port", "8.8.8.8") == {443, 8080}
        assert _child(conn, "ip_intel_tags", "tag", "8.8.8.8") == {"scanner"}


def test_cascade_delete_removes_child_rows(tmp_db):
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.2.3.4", timestamp="2026-06-10T10:00:00", path="/")
        upsert_ip_intel(conn, {"ip": "1.2.3.4", "open_ports": "22"})
        upsert_ip_intel(conn, {"ip": "5.6.7.8", "open_ports": "80"})  # orphan (no visit)
    with get_conn(tmp_db) as conn:
        purge_orphaned_intel(conn)
    with get_conn(tmp_db) as conn:
        assert _child(conn, "ip_intel_ports", "port", "5.6.7.8") == set()
        assert _child(conn, "ip_intel_ports", "port", "1.2.3.4") == {22}


def test_visitor_detail_aggregates_shodan_from_children(tmp_db):
    """get_visitor_detail re-aggregates the child tables back into CSV display fields."""
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.2.3.4", timestamp="2026-06-10T10:00:00", path="/")
        upsert_ip_intel(
            conn, {"ip": "1.2.3.4", "open_ports": "22,443", "tags": "scanner", "vulns": "CVE-Z"}
        )
    with get_conn(tmp_db) as conn:
        detail = get_visitor_detail(conn, "1.2.3.4")
        assert set(detail["open_ports"].split(",")) == {"22", "443"}
        assert detail["tags"] == "scanner"
        assert detail["vulns"] == "CVE-Z"


def test_filter_by_port(tmp_db):
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "1.1.1.1", "open_ports": "22,80"})
        upsert_ip_intel(conn, {"ip": "2.2.2.2", "open_ports": "443"})
    with get_conn(tmp_db) as conn:
        ips = {h["ip"] for h in get_shodan_hosts(conn, port=22)}
        assert ips == {"1.1.1.1"}
        assert count_shodan_hosts(conn, port=22) == 1
        assert count_shodan_hosts(conn) == 2  # unfiltered: both have exposure


def test_top_aggregates_rank_by_host_count(tmp_db):
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "1.1.1.1", "open_ports": "22,80", "tags": "scanner"})
        upsert_ip_intel(conn, {"ip": "2.2.2.2", "open_ports": "22", "vulns": "CVE-X"})
    with get_conn(tmp_db) as conn:
        ports = get_top_ports(conn)
        assert ports[0] == {"value": 22, "ip_count": 2}  # shared by both IPs -> first
        assert {"value": 80, "ip_count": 1} in ports
        assert get_top_tags(conn) == [{"value": "scanner", "ip_count": 1}]
        assert get_top_vulns(conn) == [{"value": "CVE-X", "ip_count": 1}]


def test_top_ports_counts_distinct_ips(tmp_db):
    """A port repeated on the same IP counts that IP once."""
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "1.1.1.1", "open_ports": "443,443"})
    with get_conn(tmp_db) as conn:
        assert get_top_ports(conn) == [{"value": 443, "ip_count": 1}]


def test_filter_by_vuln_and_tag(tmp_db):
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "1.1.1.1", "vulns": "CVE-X", "tags": "scanner"})
        upsert_ip_intel(conn, {"ip": "2.2.2.2", "vulns": "CVE-Y", "tags": "vpn"})
    with get_conn(tmp_db) as conn:
        assert {h["ip"] for h in get_shodan_hosts(conn, vuln="CVE-X")} == {"1.1.1.1"}
        assert {h["ip"] for h in get_shodan_hosts(conn, tag="vpn")} == {"2.2.2.2"}
        # combined filters AND together
        assert get_shodan_hosts(conn, vuln="CVE-X", tag="vpn") == []
