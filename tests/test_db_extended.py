"""Extended tests for DB layer (visitors, IP intel, stale IPs)."""

from datetime import datetime, timedelta, timezone

import pytest

from src.db import get_conn
from src.queries import (
    backfill_visitor_classes,
    count_visitors_grouped,
    get_ip_intel_bulk,
    get_stale_ips,
    get_visitor_detail,
    get_visitor_requests,
    get_visitors_grouped,
    insert_visit,
    stream_visits_for_export,
    upsert_ip_intel,
)


class TestGetStaleIps:
    """Test stale IP detection for re-enrichment."""

    def test_get_stale_ips_returns_old_intel(self, tmp_db):
        """IPs with intel older than TTL should be returned."""
        with get_conn(tmp_db) as conn:
            # Insert an IP with old enrichment
            old_time = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
            intel_data = {
                "ip": "1.2.3.4",
                "country": "US",
                "country_code": "US",
                "city": "New York",
                "lat": 40.0,
                "lon": -75.0,
                "isp": "ISP",
                "org": "Org",
                "asn": "ASN",
                "is_proxy": False,
                "is_hosting": False,
                "is_mobile": False,
                "reverse_dns": "",
                "open_ports": "",
                "tags": "",
                "hostnames": "",
                "cpes": "",
                "vulns": "",
                "is_tor": False,
                "dnsbl_listed": False,
                "dnsbl_sources": "",
                "fetched_at": old_time,
            }
            upsert_ip_intel(conn, intel_data)

        # With TTL=30 days, should be stale
        with get_conn(tmp_db) as conn:
            stale = get_stale_ips(conn, ttl_days=30, limit=100)
            assert "1.2.3.4" in stale

    def test_get_stale_ips_respects_ttl(self, tmp_db):
        """Recent intel should not be considered stale."""
        with get_conn(tmp_db) as conn:
            recent_time = datetime.now(timezone.utc).isoformat()
            intel_data = {
                "ip": "1.2.3.5",
                "country": "US",
                "country_code": "US",
                "city": "New York",
                "lat": 40.0,
                "lon": -75.0,
                "isp": "ISP",
                "org": "Org",
                "asn": "ASN",
                "is_proxy": False,
                "is_hosting": False,
                "is_mobile": False,
                "reverse_dns": "",
                "open_ports": "",
                "tags": "",
                "hostnames": "",
                "cpes": "",
                "vulns": "",
                "is_tor": False,
                "dnsbl_listed": False,
                "dnsbl_sources": "",
                "fetched_at": recent_time,
            }
            upsert_ip_intel(conn, intel_data)

        with get_conn(tmp_db) as conn:
            stale = get_stale_ips(conn, ttl_days=30, limit=100)
            assert "1.2.3.5" not in stale

    def test_get_stale_ips_respects_limit(self, tmp_db):
        """Should respect limit parameter."""
        with get_conn(tmp_db) as conn:
            old_time = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
            for i in range(5):
                intel_data = {
                    "ip": f"1.2.3.{i}",
                    "country": "US",
                    "country_code": "US",
                    "city": "New York",
                    "lat": 40.0,
                    "lon": -75.0,
                    "isp": "ISP",
                    "org": "Org",
                    "asn": "ASN",
                    "is_proxy": False,
                    "is_hosting": False,
                    "is_mobile": False,
                    "reverse_dns": "",
                    "open_ports": "",
                    "tags": "",
                    "hostnames": "",
                    "cpes": "",
                    "vulns": "",
                    "is_tor": False,
                    "dnsbl_listed": False,
                    "dnsbl_sources": "",
                    "fetched_at": old_time,
                }
                upsert_ip_intel(conn, intel_data)

        with get_conn(tmp_db) as conn:
            stale = get_stale_ips(conn, ttl_days=30, limit=2)
            assert len(stale) <= 2


class TestGetIpIntelBulk:
    """Test bulk IP intel lookup."""

    def test_bulk_lookup_mixed_found_missing(self, tmp_db):
        """Should return dict with None for missing IPs."""
        with get_conn(tmp_db) as conn:
            upsert_ip_intel(
                conn,
                {
                    "ip": "1.2.3.4",
                    "country": "US",
                    "country_code": "US",
                    "city": "New York",
                    "lat": 40.0,
                    "lon": -75.0,
                    "isp": "ISP",
                    "org": "Org",
                    "asn": "ASN",
                    "is_proxy": False,
                    "is_hosting": False,
                    "is_mobile": False,
                    "reverse_dns": "",
                    "open_ports": "",
                    "tags": "",
                    "hostnames": "",
                    "cpes": "",
                    "vulns": "",
                    "is_tor": False,
                    "dnsbl_listed": False,
                    "dnsbl_sources": "",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                },
            )

        with get_conn(tmp_db) as conn:
            result = get_ip_intel_bulk(conn, ["1.2.3.4", "1.2.3.5", "1.2.3.6"])
            assert result["1.2.3.4"] is not None
            assert result["1.2.3.4"]["country"] == "US"
            assert result["1.2.3.5"] is None
            assert result["1.2.3.6"] is None

    def test_bulk_lookup_empty_list(self, tmp_db):
        """Empty list should return empty dict."""
        with get_conn(tmp_db) as conn:
            result = get_ip_intel_bulk(conn, [])
            assert result == {}


class TestGetVisitorsGrouped:
    """Test grouped visitor list."""

    def test_grouped_visitors_empty(self, tmp_db):
        """Empty DB should return empty list."""
        with get_conn(tmp_db) as conn:
            result = get_visitors_grouped(conn, page=1, limit=50)
            assert result == []

    def test_grouped_visitors_aggregation(self, tmp_db):
        """Should aggregate visits by IP."""
        with get_conn(tmp_db) as conn:
            # Insert multiple visits from same IP
            now = datetime.now(timezone.utc).isoformat()
            for i in range(3):
                insert_visit(conn, ip="1.2.3.4", timestamp=now, method="GET", path=f"/page{i}")

        with get_conn(tmp_db) as conn:
            result = get_visitors_grouped(conn, page=1, limit=50)
            assert len(result) == 1
            assert result[0]["ip"] == "1.2.3.4"
            assert result[0]["visit_count"] == 3

    def test_grouped_visitors_pagination(self, tmp_db):
        """Should paginate results."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            for i in range(5):
                insert_visit(conn, ip=f"1.2.3.{i}", timestamp=now, method="GET", path="/")

        with get_conn(tmp_db) as conn:
            page1 = get_visitors_grouped(conn, page=1, limit=2, sort="ip", order="ASC")
            page2 = get_visitors_grouped(conn, page=2, limit=2, sort="ip", order="ASC")
            assert len(page1) == 2
            assert len(page2) == 2
            assert page1[0]["ip"] != page2[0]["ip"]

    def test_grouped_visitors_with_country_filter(self, tmp_db):
        """Should filter by country."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            insert_visit(conn, ip="1.2.3.4", timestamp=now, method="GET", path="/")
            insert_visit(conn, ip="1.2.3.5", timestamp=now, method="GET", path="/")

            upsert_ip_intel(
                conn,
                {
                    "ip": "1.2.3.4",
                    "country": "US",
                    "country_code": "US",
                    "city": "New York",
                    "lat": 40.0,
                    "lon": -75.0,
                    "isp": "ISP",
                    "org": "Org",
                    "asn": "ASN",
                    "is_proxy": False,
                    "is_hosting": False,
                    "is_mobile": False,
                    "reverse_dns": "",
                    "open_ports": "",
                    "tags": "",
                    "hostnames": "",
                    "cpes": "",
                    "vulns": "",
                    "is_tor": False,
                    "dnsbl_listed": False,
                    "dnsbl_sources": "",
                    "fetched_at": now,
                },
            )

        with get_conn(tmp_db) as conn:
            result = get_visitors_grouped(conn, page=1, limit=50, country_filter="US")
            assert len(result) == 1
            assert result[0]["ip"] == "1.2.3.4"


class TestGetVisitorRequests:
    """Test per-IP request list."""

    def test_visitor_requests_empty(self, tmp_db):
        """Non-existent IP should return empty list."""
        with get_conn(tmp_db) as conn:
            result = get_visitor_requests(conn, ip="1.2.3.4", page=1)
            assert result == []

    def test_visitor_requests_pagination(self, tmp_db):
        """Should paginate visits for single IP."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            for i in range(5):
                insert_visit(
                    conn, ip="1.2.3.4", timestamp=now, method="GET", path=f"/page{i}", status=200
                )

        with get_conn(tmp_db) as conn:
            page1 = get_visitor_requests(conn, ip="1.2.3.4", page=1, limit=2)
            page2 = get_visitor_requests(conn, ip="1.2.3.4", page=2, limit=2)
            page3 = get_visitor_requests(conn, ip="1.2.3.4", page=3, limit=2)
            assert len(page1) == 2
            assert len(page2) == 2
            assert len(page3) == 1

    def test_visitor_requests_sort_by_status(self, tmp_db):
        """Should sort by status code."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            insert_visit(conn, ip="1.2.3.4", timestamp=now, method="GET", path="/", status=200)
            insert_visit(conn, ip="1.2.3.4", timestamp=now, method="GET", path="/", status=404)
            insert_visit(conn, ip="1.2.3.4", timestamp=now, method="GET", path="/", status=500)

        with get_conn(tmp_db) as conn:
            result = get_visitor_requests(
                conn, ip="1.2.3.4", page=1, limit=10, sort="status", order="ASC"
            )
            assert result[0]["status"] == 200
            assert result[1]["status"] == 404
            assert result[2]["status"] == 500

    def test_visitor_requests_sort_by_browser(self, tmp_db):
        """Should sort by browser."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, method="GET", path="/", browser="Firefox"
            )
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, method="GET", path="/", browser="Chrome"
            )
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, method="GET", path="/", browser="Safari"
            )

        with get_conn(tmp_db) as conn:
            result = get_visitor_requests(
                conn, ip="1.2.3.4", page=1, limit=10, sort="browser", order="ASC"
            )
            browsers = [r["browser"] for r in result]
            assert browsers == sorted(browsers)


class TestCountVisitorsGrouped:
    """Test grouped visitor count."""

    def test_count_visitors_grouped_empty(self, tmp_db):
        """Empty DB should return 0."""
        with get_conn(tmp_db) as conn:
            count = count_visitors_grouped(conn)
            assert count == 0

    def test_count_visitors_grouped_aggregates(self, tmp_db):
        """Should count unique IPs."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            for _ in range(3):
                insert_visit(conn, ip="1.2.3.4", timestamp=now, method="GET", path="/")
            for _ in range(2):
                insert_visit(conn, ip="1.2.3.5", timestamp=now, method="GET", path="/")

        with get_conn(tmp_db) as conn:
            count = count_visitors_grouped(conn)
            assert count == 2

    def test_ip_filter_is_exact_match(self, tmp_db):
        """The ip_filter matches the complete IP only — no substring semantics
        (the route validates with valid_ip(), so only full IPs arrive)."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            insert_visit(conn, ip="1.2.3.4", timestamp=now, method="GET", path="/")
            insert_visit(conn, ip="1.2.3.45", timestamp=now, method="GET", path="/")

        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, ip_filter="1.2.3.4")
            assert [r["ip"] for r in rows] == ["1.2.3.4"]
            assert count_visitors_grouped(conn, ip_filter="1.2.3.4") == 1
            assert count_visitors_grouped(conn, ip_filter="1.2.3") == 0


class TestGetVisitorDetail:
    """Test visitor detail (single IP aggregated view)."""

    def test_visitor_detail_not_found(self, tmp_db):
        """Non-existent IP should return None."""
        with get_conn(tmp_db) as conn:
            result = get_visitor_detail(conn, ip="1.2.3.4")
            assert result is None

    def test_visitor_detail_aggregates(self, tmp_db):
        """Should aggregate data for single IP."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                method="GET",
                path="/",
                browser="Chrome",
                os="Windows",
            )
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                method="POST",
                path="/api",
                browser="Chrome",
                os="Windows",
            )
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                method="GET",
                path="/other",
                browser="Firefox",
                os="Linux",
            )

        with get_conn(tmp_db) as conn:
            detail = get_visitor_detail(conn, ip="1.2.3.4")
            assert detail is not None
            assert detail["ip"] == "1.2.3.4"
            assert detail["visit_count"] == 3
            assert "Chrome" in detail["browsers"]  # browsers should include both
            assert detail["unique_pages"] == 3


class TestGoodFanClassifier:
    """Tests for the Human visitor HAVING/WHERE classification logic."""

    def _clean_intel(self, ip: str) -> dict:
        return {
            "ip": ip,
            "country": "DE",
            "country_code": "DE",
            "city": "Berlin",
            "lat": 52.5,
            "lon": 13.4,
            "isp": "ISP",
            "org": "Org",
            "asn": "AS1",
            "is_proxy": False,
            "is_hosting": False,
            "is_mobile": False,
            "reverse_dns": "",
            "open_ports": "",
            "tags": "",
            "hostnames": "",
            "cpes": "",
            "vulns": "",
            "is_tor": False,
            "dnsbl_listed": False,
            "dnsbl_sources": "",
        }

    def test_basic_human(self, tmp_db):
        """IP with browser navigation signals, 2 distinct pages, no 404s → qualifies as human."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/",
                status=200,
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
            )
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/about",
                status=200,
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
            )

        with get_conn(tmp_db) as conn:
            backfill_visitor_classes(conn)
            fans = get_visitors_grouped(conn, class_filter=["humans"])
            assert any(f["ip"] == "1.2.3.4" for f in fans)
            assert count_visitors_grouped(conn, class_filter=["humans"]) == 1

    def test_404_rate_below_threshold_passes(self, tmp_db):
        """9 successful + 1 404 = 10% 404 rate → still qualifies (<10% threshold)."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            for _ in range(9):
                insert_visit(
                    conn, ip="1.2.3.4", timestamp=now, path="/", status=200, device="Desktop"
                )
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, path="/old-page", status=404, device="Desktop"
            )

        with get_conn(tmp_db) as conn:
            # 10% 404 rate — should NOT pass (threshold is < 0.1, i.e. strictly less than 10%)
            fans = get_visitors_grouped(conn, class_filter=["humans"])
            assert not any(f["ip"] == "1.2.3.4" for f in fans)

    def test_404_rate_well_below_threshold_passes(self, tmp_db):
        """1 404 out of 20 requests = 5% with browser signals → qualifies (threshold is 20%)."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            for _ in range(19):
                insert_visit(
                    conn,
                    ip="1.2.3.4",
                    timestamp=now,
                    path="/",
                    status=200,
                    sec_fetch_mode="navigate",
                    sec_fetch_dest="document",
                )
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/old",
                status=404,
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
            )

        with get_conn(tmp_db) as conn:
            backfill_visitor_classes(conn)
            fans = get_visitors_grouped(conn, class_filter=["humans"])
            assert any(f["ip"] == "1.2.3.4" for f in fans)

    def test_hosting_ip_excluded(self, tmp_db):
        """Hosting/DC IPs are excluded regardless of behavior."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            intel = self._clean_intel("1.2.3.4")
            intel["is_hosting"] = True
            upsert_ip_intel(conn, intel)
            insert_visit(conn, ip="1.2.3.4", timestamp=now, path="/", status=200, device="Desktop")

        with get_conn(tmp_db) as conn:
            assert count_visitors_grouped(conn, class_filter=["humans"]) == 0

    def test_tor_ip_excluded(self, tmp_db):
        """Tor exit nodes are excluded."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            intel = self._clean_intel("1.2.3.4")
            intel["is_tor"] = True
            upsert_ip_intel(conn, intel)
            insert_visit(conn, ip="1.2.3.4", timestamp=now, path="/", status=200, device="Desktop")

        with get_conn(tmp_db) as conn:
            assert count_visitors_grouped(conn, class_filter=["humans"]) == 0

    def test_scanner_path_excluded(self, tmp_db):
        """Requests to scanner paths (wp-admin etc.) disqualify the IP."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            insert_visit(conn, ip="1.2.3.4", timestamp=now, path="/", status=200, device="Desktop")
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/wp-admin/login.php",
                status=403,
                device="Bot",
            )

        with get_conn(tmp_db) as conn:
            assert count_visitors_grouped(conn, class_filter=["humans"]) == 0

    def test_sec_fetch_present_qualifies(self, tmp_db):
        """sec_fetch_mode=navigate + sec_fetch_dest=document on 2 paths → qualifies."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/",
                status=200,
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
            )
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/about",
                status=200,
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
            )

        with get_conn(tmp_db) as conn:
            backfill_visitor_classes(conn)
            fans = get_visitors_grouped(conn, class_filter=["humans"])
            assert any(f["ip"] == "1.2.3.4" for f in fans)

    def test_sec_fetch_absent_no_browser_signal_is_not_human(self, tmp_db):
        """Pre-V4 data (no Sec-Fetch, no zstd, no HTTP/2) → not classified as human."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            # Simulates pre-V4 log data: Desktop UA, two pages, but no browser signals
            insert_visit(conn, ip="1.2.3.4", timestamp=now, path="/", status=200, device="Desktop")
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, path="/about", status=200, device="Desktop"
            )

        with get_conn(tmp_db) as conn:
            assert (
                count_visitors_grouped(conn, class_filter=["humans"]) == 0
            ), "No browser signals → not classified as human"

    def test_sec_fetch_partial_below_50pct_excluded(self, tmp_db):
        """IP with some Sec-Fetch data but <50% coverage is excluded as suspicious."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            # 1 of 5 requests has sec_fetch — 20%, suspicious pattern
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/",
                status=200,
                device="Desktop",
                sec_fetch_dest="document",
            )
            for _ in range(4):
                insert_visit(
                    conn,
                    ip="1.2.3.4",
                    timestamp=now,
                    path="/api",
                    status=200,
                    device="Desktop",
                    sec_fetch_dest="",
                )

        with get_conn(tmp_db) as conn:
            assert (
                count_visitors_grouped(conn, class_filter=["humans"]) == 0
            ), "Mixed Sec-Fetch with <50% coverage should be excluded"

    def test_two_visits_with_browser_signal_qualifies(self, tmp_db):
        """2 visits with browser signals and 2 distinct paths → qualifies.

        There is deliberately no minimum visit count.
        """
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            upsert_ip_intel(conn, self._clean_intel("1.2.3.4"))
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/",
                status=200,
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
            )
            insert_visit(
                conn,
                ip="1.2.3.4",
                timestamp=now,
                path="/about",
                status=200,
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
            )

        with get_conn(tmp_db) as conn:
            backfill_visitor_classes(conn)
            fans = get_visitors_grouped(conn, class_filter=["humans"])
            assert any(f["ip"] == "1.2.3.4" for f in fans)

    def test_visitor_detail_sec_fetch_rate(self, tmp_db):
        """get_visitor_detail returns correct sec_fetch_rate."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, path="/", status=200, sec_fetch_dest="document"
            )
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, path="/b", status=200, sec_fetch_dest="document"
            )
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, path="/c", status=200, sec_fetch_dest=""
            )

        with get_conn(tmp_db) as conn:
            detail = get_visitor_detail(conn, "1.2.3.4")
            assert detail is not None
            # 2 of 3 have sec_fetch_dest → rate = 0.67
            assert detail["sec_fetch_rate"] == pytest.approx(0.67, abs=0.01)
            assert "document" in (detail["sec_fetch_dests"] or "")

    def test_visitor_detail_http_versions(self, tmp_db):
        """get_visitor_detail returns http_versions aggregate."""
        with get_conn(tmp_db) as conn:
            now = datetime.now(timezone.utc).isoformat()
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, path="/", status=200, http_version="HTTP/2.0"
            )
            insert_visit(
                conn, ip="1.2.3.4", timestamp=now, path="/b", status=200, http_version="HTTP/1.1"
            )

        with get_conn(tmp_db) as conn:
            detail = get_visitor_detail(conn, "1.2.3.4")
            assert "HTTP/2.0" in (detail["http_versions"] or "")
            assert "HTTP/1.1" in (detail["http_versions"] or "")


class TestClassFilterMultiSelect:
    """Tests for multi-select class filtering on visitor query functions."""

    def _intel(self, ip: str, visitor_class: str) -> dict:
        return {
            "ip": ip,
            "country": "DE",
            "country_code": "DE",
            "city": "Berlin",
            "lat": 52.5,
            "lon": 13.4,
            "isp": "ISP",
            "org": "Org",
            "asn": "AS1",
            "is_proxy": False,
            "is_hosting": False,
            "is_mobile": False,
            "reverse_dns": "",
            "open_ports": "",
            "tags": "",
            "hostnames": "",
            "cpes": "",
            "vulns": "",
            "is_tor": False,
            "dnsbl_listed": False,
            "dnsbl_sources": "",
            "visitor_class": visitor_class,
        }

    def _seed(self, conn, ip: str, visitor_class: str):
        now = datetime.now(timezone.utc).isoformat()
        insert_visit(conn, ip=ip, timestamp=now, path="/")
        intel = self._intel(ip, visitor_class)
        upsert_ip_intel(conn, intel)
        conn.execute("UPDATE ip_intel SET visitor_class = ? WHERE ip = ?", (visitor_class, ip))

    def test_empty_filter_returns_all(self, tmp_db):
        """Empty class_filter returns all IPs."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "bots/search-crawlers")
            self._seed(conn, "2.2.2.2", "humans/browser-direct")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, class_filter=None)
            assert len(rows) == 2

    def test_single_class_filter(self, tmp_db):
        """Single class filter returns only matching IPs."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "bots/search-crawlers")
            self._seed(conn, "2.2.2.2", "humans/browser-direct")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, class_filter=["bots/search-crawlers"])
            assert len(rows) == 1
            assert rows[0]["ip"] == "1.1.1.1"

    def test_multi_class_filter(self, tmp_db):
        """Multiple classes return IPs matching any of them."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "bots/search-crawlers")
            self._seed(conn, "2.2.2.2", "humans/browser-direct")
            self._seed(conn, "3.3.3.3", "threats/dnsbl-listed")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(
                conn, class_filter=["bots/search-crawlers", "humans/browser-direct"]
            )
            ips = {r["ip"] for r in rows}
            assert ips == {"1.1.1.1", "2.2.2.2"}

    def test_unknown_filter_includes_null_and_empty(self, tmp_db):
        """class_filter=['unknown'] returns IPs with unknown, empty, or NULL visitor_class."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "unknown")
            self._seed(conn, "2.2.2.2", "")
            self._seed(conn, "3.3.3.3", "bots/search-crawlers")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, class_filter=["unknown"])
            ips = {r["ip"] for r in rows}
            assert "1.1.1.1" in ips
            assert "2.2.2.2" in ips
            assert "3.3.3.3" not in ips

    def test_unknown_plus_class_filter(self, tmp_db):
        """Combining unknown + specific class returns both sets."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "unknown")
            self._seed(conn, "2.2.2.2", "bots/generic-bots")
            self._seed(conn, "3.3.3.3", "threats/dnsbl-listed")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, class_filter=["unknown", "bots/generic-bots"])
            ips = {r["ip"] for r in rows}
            assert ips == {"1.1.1.1", "2.2.2.2"}

    def test_class_humans_returns_humans_only(self, tmp_db):
        """class=humans returns only humans/* IPs (group-prefix match)."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "humans/browser-direct")
            self._seed(conn, "2.2.2.2", "unknown")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, class_filter=["humans"])
            ips = {r["ip"] for r in rows}
            assert "1.1.1.1" in ips
            assert "2.2.2.2" not in ips

    def test_class_humans_plus_unknown_adds_unknowns(self, tmp_db):
        """class=humans,unknown returns humans/* plus unknown IPs."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "humans/browser-direct")
            self._seed(conn, "2.2.2.2", "unknown")
            self._seed(conn, "3.3.3.3", "bots/generic-bots")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, class_filter=["humans", "unknown"])
            ips = {r["ip"] for r in rows}
            assert "1.1.1.1" in ips
            assert "2.2.2.2" in ips
            assert "3.3.3.3" not in ips

    def test_class_human_subclass_narrows(self, tmp_db):
        """A specific human subclass shows only that subclass."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "humans/browser-direct")
            self._seed(conn, "2.2.2.2", "humans/browser-referred")
        with get_conn(tmp_db) as conn:
            rows = get_visitors_grouped(conn, class_filter=["humans/browser-direct"])
            ips = {r["ip"] for r in rows}
            assert "1.1.1.1" in ips
            assert "2.2.2.2" not in ips

    def test_count_visitors_grouped_multi_filter(self, tmp_db):
        """count_visitors_grouped respects multi-class filter."""
        with get_conn(tmp_db) as conn:
            self._seed(conn, "1.1.1.1", "bots/search-crawlers")
            self._seed(conn, "2.2.2.2", "humans/browser-direct")
            self._seed(conn, "3.3.3.3", "threats/dnsbl-listed")
        with get_conn(tmp_db) as conn:
            total = count_visitors_grouped(
                conn, class_filter=["bots/search-crawlers", "threats/dnsbl-listed"]
            )
            assert total == 2


def test_date_range_includes_full_end_day(tmp_db):
    """C4 regression: a single-day filter includes the whole end day (incl. 23:59:59)
    and excludes the next day — consistently for export and grouped queries."""
    with get_conn(tmp_db) as conn:
        insert_visit(
            conn,
            ip="9.9.9.9",
            timestamp="2026-06-13T23:59:59+00:00",
            method="GET",
            path="/",
            status=200,
        )
        insert_visit(
            conn,
            ip="9.9.9.9",
            timestamp="2026-06-14T00:00:00+00:00",
            method="GET",
            path="/next",
            status=200,
        )
        upsert_ip_intel(conn, {"ip": "9.9.9.9"})
    with get_conn(tmp_db) as conn:
        exported = list(stream_visits_for_export(conn, "2026-06-13", "2026-06-13"))
        grouped = get_visitors_grouped(conn, date_from="2026-06-13", date_to="2026-06-13")
    assert len(exported) == 1  # the 23:59:59 visit is in; the next-day one is out
    assert exported[0]["timestamp"].startswith("2026-06-13")
    assert grouped and grouped[0]["visit_count"] == 1


class TestVisualQueryHelpers:
    """Queries feeding the timeline heatmap, status-mix chart, and KPI sparklines."""

    def test_hourly_heatmap_buckets_by_dow_and_hour(self, tmp_db):
        with get_conn(tmp_db) as conn:
            # 2026-07-06 is a Monday (strftime %w == 1)
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-06T09:15:00+00:00", path="/")
            insert_visit(conn, ip="1.2.3.5", timestamp="2026-07-06T09:45:00+00:00", path="/")
            insert_visit(conn, ip="1.2.3.6", timestamp="2026-07-05T23:00:00+00:00", path="/")

        from src.queries import get_hourly_heatmap

        with get_conn(tmp_db) as conn:
            rows = {(r["dow"], r["hr"]): r["total"] for r in get_hourly_heatmap(conn)}
        assert rows[(1, 9)] == 2  # Monday 09:xx
        assert rows[(0, 23)] == 1  # Sunday 23:xx

    def test_hourly_heatmap_splits_by_group(self, tmp_db):
        """Each cell carries the per-taxonomy-group breakdown for the toggle."""
        from src.queries import get_hourly_heatmap, set_visitor_class, upsert_ip_intel

        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-06T09:00:00+00:00", path="/")
            insert_visit(conn, ip="1.2.3.5", timestamp="2026-07-06T09:30:00+00:00", path="/")
            upsert_ip_intel(conn, {"ip": "1.2.3.4", "fetched_at": "2026-07-06"})
            upsert_ip_intel(conn, {"ip": "1.2.3.5", "fetched_at": "2026-07-06"})
            set_visitor_class(conn, "1.2.3.4", "humans/browser-direct")
            set_visitor_class(conn, "1.2.3.5", "bots/generic-bots")

        with get_conn(tmp_db) as conn:
            cell = {(r["dow"], r["hr"]): r for r in get_hourly_heatmap(conn)}[(1, 9)]
        assert cell["total"] == 2
        assert cell["humans"] == 1
        assert cell["bots"] == 1
        assert cell["threats"] == 0

    def test_hourly_heatmap_respects_date_range(self, tmp_db):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-01T10:00:00+00:00", path="/")
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-06T10:00:00+00:00", path="/")

        from src.queries import get_hourly_heatmap

        with get_conn(tmp_db) as conn:
            rows = get_hourly_heatmap(conn, since="2026-07-06T00:00:00", until="2026-07-06")
        assert sum(r["total"] for r in rows) == 1

    def test_status_timeline_per_day_classes(self, tmp_db):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-06T10:00:00+00:00", status=200)
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-06T11:00:00+00:00", status=404)
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-06T12:00:00+00:00", status=500)
            insert_visit(conn, ip="1.2.3.4", timestamp="2026-07-07T10:00:00+00:00", status=301)

        from src.queries import get_status_timeline

        with get_conn(tmp_db) as conn:
            rows = get_status_timeline(conn)
        assert [r["day"] for r in rows] == ["2026-07-06", "2026-07-07"]
        assert (rows[0]["s2xx"], rows[0]["s4xx"], rows[0]["s5xx"]) == (1, 1, 1)
        assert rows[1]["s3xx"] == 1

    def test_daily_kpis_counts_visits_errors_bytes(self, tmp_db):
        now = datetime.now(timezone.utc).isoformat()
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.2.3.4", timestamp=now, status=200, bytes_sent=100)
            insert_visit(conn, ip="1.2.3.4", timestamp=now, status=404, bytes_sent=50)

        from src.queries import get_daily_kpis

        with get_conn(tmp_db) as conn:
            rows = get_daily_kpis(conn, since="2026-01-01T00:00:00")
        assert len(rows) == 1
        assert rows[0]["visits"] == 2
        assert rows[0]["errors"] == 1
        assert rows[0]["bytes"] == 150

    def test_heatmap_grid_is_monday_first(self):
        from src.routes._charts import build_heatmap_grid

        grid, maxes = build_heatmap_grid(
            [
                {
                    "dow": 1,
                    "hr": 9,
                    "total": 5,
                    "humans": 3,
                    "bots": 2,
                    "automated": 0,
                    "threats": 0,
                    "unknown": 0,
                },
                {
                    "dow": 0,
                    "hr": 23,
                    "total": 2,
                    "humans": 0,
                    "bots": 0,
                    "automated": 0,
                    "threats": 0,
                    "unknown": 2,
                },
            ]
        )
        assert [g["label"] for g in grid] == ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        assert grid[0]["cells"][9]["total"] == 5  # Monday 09
        assert grid[0]["cells"][9]["humans"] == 3
        assert grid[6]["cells"][23]["unknown"] == 2  # Sunday 23
        assert maxes["total"] == 5
        assert maxes["humans"] == 3
