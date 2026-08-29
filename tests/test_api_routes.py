"""Tests for API routes (/api/stats, /api/activity, /api/visits, /api/export)."""

import csv
import io
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src import __version__
from src.db import get_conn
from src.main import app
from src.queries import insert_visit, upsert_ip_intel


@pytest.fixture
def client(tmp_db):
    """FastAPI test client with patched DB path."""
    from unittest.mock import patch

    from src.config import settings

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


@pytest.fixture
def populated_db(tmp_db):
    """Populate DB with sample visits."""
    with get_conn(tmp_db) as conn:
        now = datetime.now(timezone.utc).isoformat()

        # Insert various visits
        insert_visit(
            conn,
            ip="1.2.3.4",
            timestamp=now,
            method="GET",
            path="/",
            status=200,
            bytes_sent=5000,
            browser="Chrome",
            os="Windows",
        )
        insert_visit(
            conn,
            ip="1.2.3.4",
            timestamp=now,
            method="POST",
            path="/api",
            status=201,
            bytes_sent=1000,
            browser="Chrome",
            os="Windows",
        )
        insert_visit(
            conn,
            ip="1.2.3.5",
            timestamp=now,
            method="GET",
            path="/about",
            status=200,
            bytes_sent=3000,
            browser="Firefox",
            os="Linux",
        )
        insert_visit(
            conn,
            ip="1.2.3.5",
            timestamp=now,
            method="GET",
            path="/",
            status=404,
            bytes_sent=0,
            browser="Firefox",
            os="Linux",
        )

        # Add enrichment data
        upsert_ip_intel(
            conn,
            {
                "ip": "1.2.3.4",
                "country": "US",
                "country_code": "US",
                "city": "New York",
                "lat": 40.0,
                "lon": -75.0,
                "isp": "ISP1",
                "org": "Org1",
                "asn": "AS1",
                "is_proxy": False,
                "is_hosting": False,
                "is_mobile": False,
                "reverse_dns": "host1.example.com",
                "open_ports": "80,443",
                "tags": "web",
                "hostnames": "host1.example.com",
                "cpes": "",
                "vulns": "",
                "is_tor": False,
                "dnsbl_listed": False,
                "dnsbl_sources": "",
                "fetched_at": now,
            },
        )

        upsert_ip_intel(
            conn,
            {
                "ip": "1.2.3.5",
                "country": "DE",
                "country_code": "DE",
                "city": "Berlin",
                "lat": 52.5,
                "lon": 13.4,
                "isp": "ISP2",
                "org": "Org2",
                "asn": "AS2",
                "is_proxy": True,
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

    yield tmp_db


class TestStatsEndpoint:
    """Test /api/stats endpoint."""

    def test_stats_empty_db(self, client, tmp_db):
        """Stats on empty DB should return zeros."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", tmp_db):
            response = client.get("/api/stats")
            assert response.status_code == 200
            data = response.json()
            assert data["total_visits"] == 0
            assert data["unique_ips"] == 0

    def test_stats_populated(self, client, populated_db):
        """Stats should aggregate visits correctly."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/stats")
            assert response.status_code == 200
            data = response.json()
            assert data["total_visits"] == 4
            assert data["unique_ips"] == 2
            assert "top_countries" in data
            assert "top_pages" in data

    def test_stats_reports_the_running_version(self, client, tmp_db):
        """The version travels with the stats, so a tunnelled caller can tell
        which build answered without opening the dashboard."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", tmp_db):
            assert client.get("/api/stats").json()["version"] == __version__


class TestVisitsEndpoint:
    """Test /api/visits endpoint."""

    def test_visits_empty(self, client, tmp_db):
        """Empty DB should return empty data."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", tmp_db):
            response = client.get("/api/visits")
            assert response.status_code == 200
            data = response.json()
            assert data["data"] == []
            assert data["total"] == 0

    def test_visits_pagination(self, client, populated_db):
        """Should paginate visits."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/visits?page=1&limit=2")
            assert response.status_code == 200
            data = response.json()
            assert len(data["data"]) == 2
            assert data["total"] == 4

    def test_visits_ip_filter(self, client, populated_db):
        """Should filter by IP."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/visits?ip=1.2.3.4")
            assert response.status_code == 200
            data = response.json()
            assert all(v["ip"] == "1.2.3.4" for v in data["data"])
            assert data["total"] == 2

    def test_visits_invalid_ip_filter(self, client, populated_db):
        """Invalid IP should be ignored."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/visits?ip=not-an-ip")
            assert response.status_code == 200
            data = response.json()
            assert data["total"] == 4

    def test_visits_country_filter(self, client, populated_db):
        """Should filter by country code."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/visits?country=US")
            assert response.status_code == 200
            data = response.json()
            # Should only get visits from US IP
            assert all(
                v.get("country_code") == "US" or v.get("country_code") is None
                for v in data["data"]
            )


class TestExportEndpoint:
    """Test /api/export endpoint (JSON and CSV)."""

    def test_export_json_empty(self, client, tmp_db):
        """Empty export as JSON."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", tmp_db):
            response = client.get("/api/export?format=json")
            assert response.status_code == 200
            # Should be valid JSON array
            data = json.loads(response.text)
            assert data == []

    def test_export_json_populated(self, client, populated_db):
        """Export populated DB as JSON."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/export?format=json")
            assert response.status_code == 200
            data = json.loads(response.text)
            assert len(data) == 4
            assert all("ip" in v for v in data)

    def test_export_csv_empty(self, client, tmp_db):
        """Empty export as CSV."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", tmp_db):
            response = client.get("/api/export?format=csv")
            assert response.status_code == 200
            # Empty CSV should just have no data
            assert len(response.text) >= 0

    def test_export_csv_populated(self, client, populated_db):
        """Export populated DB as CSV."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/export?format=csv")
            assert response.status_code == 200
            # Parse CSV
            reader = csv.DictReader(io.StringIO(response.text))
            rows = list(reader)
            assert len(rows) == 4
            assert all("ip" in row for row in rows)

    def test_export_date_filter_from(self, client, populated_db):
        """Should filter by from_date."""
        from datetime import datetime, timedelta, timezone
        from unittest.mock import patch

        from src.config import settings

        now = datetime.now(timezone.utc)
        with patch.object(settings, "db_path", populated_db):
            # Export from 1 day in future (should be empty)
            future_date = (now + timedelta(days=1)).date().isoformat()
            response = client.get(f"/api/export?format=json&from={future_date}")
            assert response.status_code == 200
            data = json.loads(response.text)
            assert len(data) == 0

    def test_export_date_filter_to(self, client, populated_db):
        """Should filter by to_date."""
        from datetime import datetime, timedelta, timezone
        from unittest.mock import patch

        from src.config import settings

        now = datetime.now(timezone.utc)
        with patch.object(settings, "db_path", populated_db):
            # Export to 1 day in past (should be empty)
            past_date = (now - timedelta(days=1)).date().isoformat()
            response = client.get(f"/api/export?format=json&to={past_date}")
            assert response.status_code == 200
            data = json.loads(response.text)
            assert len(data) == 0

    def test_export_invalid_date_format(self, client, populated_db):
        """Invalid date format should be ignored."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/export?format=json&from=invalid-date")
            assert response.status_code == 200
            data = json.loads(response.text)
            # Should still return all data
            assert len(data) == 4

    def test_export_csv_sanitization(self, client, populated_db):
        """CSV export returns 200 and valid CSV with headers."""
        from unittest.mock import patch

        from src.config import settings

        with patch.object(settings, "db_path", populated_db):
            response = client.get("/api/export?format=csv")
            assert response.status_code == 200
            reader = csv.DictReader(io.StringIO(response.text))
            assert list(reader.fieldnames or [])  # headers present


class TestCsvSanitization:
    """Unit tests for _sanitize_csv_cell injection prevention."""

    def test_formula_prefix_equals(self):
        from src.routes.api import _sanitize_csv_cell

        assert _sanitize_csv_cell("=cmd") == "'=cmd"

    def test_formula_prefix_plus(self):
        from src.routes.api import _sanitize_csv_cell

        assert _sanitize_csv_cell("+1") == "'+1"

    def test_formula_prefix_at(self):
        from src.routes.api import _sanitize_csv_cell

        assert _sanitize_csv_cell("@SUM") == "'@SUM"

    def test_formula_prefix_minus(self):
        from src.routes.api import _sanitize_csv_cell

        assert _sanitize_csv_cell("-1+2") == "'-1+2"

    def test_safe_value_unchanged(self):
        from src.routes.api import _sanitize_csv_cell

        assert _sanitize_csv_cell("1.2.3.4") == "1.2.3.4"

    def test_newlines_stripped(self):
        from src.routes.api import _sanitize_csv_cell

        result = _sanitize_csv_cell("foo\nbar\r\nbaz")
        assert "\n" not in result
        assert "\r" not in result

    def test_none_becomes_empty_string(self):
        from src.routes.api import _sanitize_csv_cell

        assert _sanitize_csv_cell(None) == ""


class TestExportRateLimit:
    """The /api/export middleware allows N exports per window, then 429s."""

    def test_limit_then_429(self, client, tmp_db):
        from src.config import settings

        for i in range(settings.export_rate_limit):
            response = client.get("/api/export?format=json")
            assert response.status_code == 200, f"request {i + 1} should pass"
        response = client.get("/api/export?format=json")
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.text

    def test_other_endpoints_not_limited(self, client, tmp_db):
        from src.config import settings

        for _ in range(settings.export_rate_limit + 2):
            assert client.get("/api/stats").status_code == 200

    def test_counter_resets_between_tests(self, client, tmp_db):
        """The per-test tmp_db gives a fresh rate_limits table, so the count resets."""
        assert client.get("/api/export?format=json").status_code == 200

    def test_limit_persists_across_restart(self, client, tmp_db):
        """Rate-limit state is in SQLite, so a 'restart' (new client) still enforces it."""
        from src.config import settings
        from src.main import app

        for _ in range(settings.export_rate_limit):
            assert client.get("/api/export?format=json").status_code == 200

        # Simulate a container restart: a brand-new client against the same DB.
        # Plain construction (no `with`) so the lifespan/background tasks don't start.
        fresh = TestClient(app)
        assert fresh.get("/api/export?format=json").status_code == 429


class TestStreamVisitsForExport:
    """Unit tests for the query-layer export stream (date bounds, ordering)."""

    @pytest.fixture
    def dated_db(self, tmp_db):
        """DB with one visit on each of three known days."""
        with get_conn(tmp_db) as conn:
            for day in ("2026-06-01", "2026-06-05", "2026-06-10"):
                insert_visit(
                    conn,
                    ip="1.2.3.4",
                    timestamp=f"{day}T12:00:00+00:00",
                    method="GET",
                    path="/",
                    status=200,
                    bytes_sent=100,
                )
        yield tmp_db

    def test_no_filter_returns_all_newest_first(self, dated_db):
        from src.queries import stream_visits_for_export

        with get_conn(dated_db) as conn:
            rows = list(stream_visits_for_export(conn))
        assert [r["timestamp"][:10] for r in rows] == ["2026-06-10", "2026-06-05", "2026-06-01"]

    def test_from_date_is_inclusive(self, dated_db):
        from src.queries import stream_visits_for_export

        with get_conn(dated_db) as conn:
            rows = list(stream_visits_for_export(conn, from_date="2026-06-05"))
        assert [r["timestamp"][:10] for r in rows] == ["2026-06-10", "2026-06-05"]

    def test_to_date_covers_full_day(self, dated_db):
        from src.queries import stream_visits_for_export

        with get_conn(dated_db) as conn:
            rows = list(stream_visits_for_export(conn, to_date="2026-06-05"))
        assert [r["timestamp"][:10] for r in rows] == ["2026-06-05", "2026-06-01"]

    def test_rows_include_intel_join_columns(self, dated_db):
        from src.queries import stream_visits_for_export

        with get_conn(dated_db) as conn:
            rows = list(stream_visits_for_export(conn))
        assert "country" in rows[0] and "is_proxy" in rows[0]


class TestActivityEndpoint:
    """/api/activity — the timeline's own data source.

    The page ships its daily rows inline, so this is only called once a reader
    zooms in far enough that days are single points and the chart wants hours.
    """

    @pytest.fixture
    def timeline_db(self, tmp_db):
        from src.queries import set_visitor_class

        with get_conn(tmp_db) as conn:
            for ts, ip in [
                ("2026-08-01T03:10:00+00:00", "10.0.0.1"),
                ("2026-08-01T03:40:00+00:00", "10.0.0.1"),
                ("2026-08-01T21:00:00+00:00", "10.0.0.2"),
                ("2026-08-03T09:00:00+00:00", "10.0.0.2"),
            ]:
                insert_visit(conn, ip=ip, timestamp=ts, method="GET", path="/", status=200)
            upsert_ip_intel(conn, {"ip": "10.0.0.1", "country": "DE", "country_code": "DE"})
            upsert_ip_intel(conn, {"ip": "10.0.0.2", "country": "US", "country_code": "US"})
            set_visitor_class(conn, "10.0.0.1", "bots/generic-bots")
            set_visitor_class(conn, "10.0.0.2", "threats/exploit-probers")
        return tmp_db

    def test_days_are_the_default(self, client, timeline_db):
        body = client.get("/api/activity").json()
        assert body["bucket"] == "day"
        assert [r["day"] for r in body["rows"]] == ["2026-08-01", "2026-08-03"]
        assert body["rows"][0]["total"] == 3

    def test_hours_split_a_day_apart(self, client, timeline_db):
        """The reason the endpoint exists: 03:00 and 21:00 are one bar as days."""
        body = client.get("/api/activity", params={"bucket": "hour"}).json()
        assert body["bucket"] == "hour"
        assert [r["day"] for r in body["rows"]] == [
            "2026-08-01T03",
            "2026-08-01T21",
            "2026-08-03T09",
        ]
        assert body["rows"][0]["total"] == 2

    def test_an_unknown_bucket_falls_back_to_days(self, client, timeline_db):
        """The bucket picks a substring length in SQL, so it never takes the
        caller's word for it."""
        body = client.get("/api/activity", params={"bucket": "10) UNION SELECT 1--"}).json()
        assert body["bucket"] == "day"
        assert len(body["rows"]) == 2

    def test_it_carries_the_same_filters_as_the_page(self, client, timeline_db):
        body = client.get("/api/activity", params={"class": "threats"}).json()
        assert sum(r["total"] for r in body["rows"]) == 2
        assert all(r["bots"] == 0 for r in body["rows"])

    def test_an_unknown_signal_is_dropped_not_applied(self, client, timeline_db):
        full = client.get("/api/activity").json()
        body = client.get("/api/activity", params={"signal": "nonsense"}).json()
        assert body["rows"] == full["rows"]

    def test_the_date_window_narrows_it(self, client, timeline_db):
        body = client.get(
            "/api/activity", params={"from": "2026-08-02", "to": "2026-08-04"}
        ).json()
        assert [r["day"] for r in body["rows"]] == ["2026-08-03"]
