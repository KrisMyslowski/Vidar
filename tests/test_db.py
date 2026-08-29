from src.db import get_conn
from src.queries import (
    count_visits,
    get_ip_intel,
    get_state,
    get_stats,
    get_unenriched_ips,
    get_visitor_ip_counts,
    get_visits,
    insert_visit,
    set_state,
    set_visitor_class,
    upsert_ip_intel,
)


def test_init_db(tmp_db):
    with get_conn(tmp_db) as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        names = {r[0] for r in tables}
        assert "visits" in names
        assert "ip_intel" in names
        assert "processor_state" in names
        assert "rate_limits" in names
        for child in (
            "ip_intel_ports",
            "ip_intel_vulns",
            "ip_intel_cpes",
            "ip_intel_tags",
            "ip_intel_hostnames",
        ):
            assert child in names


def test_insert_and_get_visits(tmp_db):
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn, ip="1.2.3.4", timestamp="2026-04-06T12:00:00", method="GET", path="/", status=200
        )
        insert_visit(
            conn,
            ip="5.6.7.8",
            timestamp="2026-04-06T12:01:00",
            method="POST",
            path="/contact",
            status=200,
        )

    with get_conn(tmp_db) as conn:
        visits = get_visits(conn, page=1, limit=10)
        assert len(visits) == 2
        assert count_visits(conn) == 2


def test_get_visits_with_ip_filter(tmp_db):
    """get_visits should filter by IP."""
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.2.3.4", timestamp="2026-04-06T12:00:00", path="/")
        insert_visit(conn, ip="5.6.7.8", timestamp="2026-04-06T12:01:00", path="/")

    with get_conn(tmp_db) as conn:
        visits = get_visits(conn, page=1, limit=10, ip_filter="1.2.3.4")
        assert len(visits) == 1
        assert visits[0]["ip"] == "1.2.3.4"
        assert count_visits(conn, ip_filter="1.2.3.4") == 1


def test_get_visits_with_country_filter(tmp_db):
    """get_visits should filter by country."""
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.2.3.4", timestamp="2026-04-06T12:00:00", path="/")
        insert_visit(conn, ip="5.6.7.8", timestamp="2026-04-06T12:01:00", path="/")
        # Add country enrichment
        upsert_ip_intel(conn, {"ip": "1.2.3.4", "country": "US", "country_code": "US"})
        upsert_ip_intel(conn, {"ip": "5.6.7.8", "country": "DE", "country_code": "DE"})

    with get_conn(tmp_db) as conn:
        visits = get_visits(conn, page=1, limit=10, country_filter="US")
        assert len(visits) == 1
        assert visits[0]["ip"] == "1.2.3.4"
        assert count_visits(conn, country_filter="US") == 1


def test_upsert_ip_intel(tmp_db):
    data = {
        "ip": "1.2.3.4",
        "country": "Germany",
        "country_code": "DE",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.405,
        "isp": "Test ISP",
        "org": "Test Org",
        "asn": "AS12345",
        "is_proxy": False,
        "is_hosting": True,
        "is_mobile": False,
    }
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, data)
        result = get_ip_intel(conn, "1.2.3.4")
        assert result is not None
        assert result["country"] == "Germany"
        assert result["is_hosting"] == 1

    # Upsert again with updated data
    data["city"] = "Munich"
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, data)
        result = get_ip_intel(conn, "1.2.3.4")
        assert result["city"] == "Munich"


def test_unenriched_ips(tmp_db):
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.2.3.4", timestamp="2026-04-06T12:00:00")
        insert_visit(conn, ip="5.6.7.8", timestamp="2026-04-06T12:01:00")
        upsert_ip_intel(conn, {"ip": "1.2.3.4"})

        unenriched = get_unenriched_ips(conn)
        assert "5.6.7.8" in unenriched
        assert "1.2.3.4" not in unenriched
        # Regression: no extra IPs should be returned
        assert len(unenriched) == 1


def test_processor_state(tmp_db):
    with get_conn(tmp_db) as conn:
        assert get_state(conn, "file_offset") is None
        set_state(conn, "file_offset", "1234")
        assert get_state(conn, "file_offset") == "1234"
        set_state(conn, "file_offset", "5678")
        assert get_state(conn, "file_offset") == "5678"


def test_stats(tmp_db):
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn,
            ip="1.2.3.4",
            timestamp="2026-04-06T12:00:00",
            path="/",
            status=200,
            bytes_sent=1024,
        )
        insert_visit(
            conn,
            ip="1.2.3.4",
            timestamp="2026-04-06T12:01:00",
            path="/about",
            status=200,
            bytes_sent=2048,
        )
        insert_visit(
            conn, ip="1.2.3.5", timestamp="2026-04-06T13:00:00", path="/", status=404, bytes_sent=0
        )
        stats = get_stats(conn)

        # Basic counts
        assert stats["total_visits"] == 3
        assert stats["unique_ips"] == 2

        # Aggregates
        assert stats["total_bandwidth"] == 3072  # 1024 + 2048
        assert "top_countries" in stats
        assert "top_pages" in stats
        assert "top_referrers" in stats
        assert "error_rate" in stats
        assert stats["error_rate"] >= 0  # One 404 out of 3
        assert "avg_response_time" in stats
        assert "visitor_class_breakdown" in stats
        assert isinstance(stats["visitor_class_breakdown"], list)

        if stats["top_ips"]:
            assert "visitor_class" in stats["top_ips"][0]
            assert "country_code" in stats["top_ips"][0]


def test_visitor_ip_counts_are_scoped_to_the_window(tmp_db):
    """The chips sit next to a table that counts IPs in the chosen window.

    Counting every classified IP regardless of the range made the chip read as a
    filtered number while the table beside it was one.
    """
    with get_conn(tmp_db) as conn:
        for ip, day, cls in (
            ("1.1.1.1", "01", "bots/crawler"),
            ("1.1.1.2", "10", "bots/crawler"),
            ("1.1.1.3", "20", "threats/exploit-probers"),
        ):
            insert_visit(conn, ip=ip, timestamp=f"2026-04-{day}T12:00:00")
            upsert_ip_intel(conn, {"ip": ip})
            set_visitor_class(conn, ip, cls)

        everything = get_visitor_ip_counts(conn)
        assert everything["all"] == 3
        assert everything["bots"] == 2

        first_week = get_visitor_ip_counts(conn, "2026-04-01", "2026-04-07")
        assert first_week["all"] == 1
        assert first_week["bots"] == 1
        assert first_week.get("threats", 0) == 0


def test_an_ip_without_intel_counts_as_unknown(tmp_db):
    """A visit arrives before its enrichment does; the row still exists.

    An inner join would have dropped it, and `all` would then disagree with the
    table below, which counts it.
    """
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="9.9.9.9", timestamp="2026-04-06T12:00:00")
        counts = get_visitor_ip_counts(conn)

    assert counts["all"] == 1
    assert counts["unknown"] == 1


def test_stats_are_scoped_to_the_window(tmp_db):
    """Every figure on the Overview answers for the range in its header.

    The tiles used to be all-time while the chart beside them was not, so the
    same page showed two different truths and only one of them was labelled.
    """
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.1.1.1", timestamp="2026-04-01T10:00:00", path="/", bytes_sent=100)
        insert_visit(
            conn, ip="1.1.1.2", timestamp="2026-04-20T10:00:00", path="/x", bytes_sent=200
        )
        insert_visit(conn, ip="1.1.1.2", timestamp="2026-04-21T10:00:00", status=404)
        upsert_ip_intel(conn, {"ip": "1.1.1.1", "country_code": "DE", "country": "Germany"})
        upsert_ip_intel(conn, {"ip": "1.1.1.2", "country_code": "AT", "country": "Austria"})

        everything = get_stats(conn)
        assert everything["total_visits"] == 3
        assert everything["unique_ips"] == 2
        assert everything["total_countries"] == 2
        assert everything["total_bandwidth"] == 300

        early = get_stats(conn, since="2026-04-01T00:00:00", until="2026-04-10T23:59:59")
        assert early["total_visits"] == 1
        assert early["unique_ips"] == 1
        assert early["total_bandwidth"] == 100
        assert early["error_rate"] == 0.0
        # Only the IP seen in the window counts towards the country total.
        assert early["total_countries"] == 1
        assert [p["path"] for p in early["top_pages"]] == ["/"]


def test_bounce_rate_is_a_property_of_the_window(tmp_db):
    """An IP that came back next month did not bounce *this* month."""
    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.1.1.1", timestamp="2026-04-01T10:00:00")
        insert_visit(conn, ip="1.1.1.1", timestamp="2026-05-01T10:00:00")

        assert get_stats(conn)["bounce_rate"] == 0.0
        april = get_stats(conn, since="2026-04-01T00:00:00", until="2026-04-30T23:59:59")
        assert april["bounce_rate"] == 100.0
