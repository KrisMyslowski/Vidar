"""The status page: what the service is doing, and what it loaded.

Everything here was previously behind an SSH session — `docker logs` for the
worker, `cat /srv/vidar/.env` for the configuration. That second half is why the
secret test below matters more than the rest of the file: a page built to show
the configuration is exactly the page that leaks a key.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.db import get_conn
from src.main import app
from src.queries import count_stale_ips, count_unenriched_ips, insert_visit, upsert_ip_intel


@pytest.fixture
def client(tmp_db):
    return TestClient(app)


class TestTheSecretNeverReachesTheMarkup:
    def test_the_dqs_key_is_not_rendered(self, client):
        """Set to something unmistakable, then looked for in the response."""
        canary = "SECRET-CANARY-8f3a91"
        with patch.object(settings, "dnsbl_dqs_key", canary):
            body = client.get("/settings/status").text
        assert canary not in body

    def test_not_even_a_fragment_of_it(self, client):
        """No truncation, no asterisk run: the length is information too."""
        canary = "abcdefghijklmnopqrstuvwxyz"
        with patch.object(settings, "dnsbl_dqs_key", canary):
            body = client.get("/settings/status").text
        assert "abcdef" not in body
        assert "**********" not in body

    def test_it_says_whether_the_key_is_there(self, client):
        with patch.object(settings, "dnsbl_dqs_key", "anything"):
            assert "set" in client.get("/settings/status").text
        with patch.object(settings, "dnsbl_dqs_key", ""):
            assert "not set" in client.get("/settings/status").text


class TestTheConfigurationView:
    def test_every_setting_appears(self, client):
        """A setting the page forgets is a setting nobody can check."""
        from src.config import Settings

        body = client.get("/settings/status").text
        missing = [f for f in Settings.model_fields if f.upper() not in body]
        assert not missing, f"not shown on the status page: {missing}"

    def test_the_running_version_is_named(self, client):
        from src import __version__

        assert __version__ in client.get("/settings/status").text


class TestTheSiteSettingsWarning:
    def test_it_appears_when_one_is_unset(self, client):
        with patch.object(settings, "site_base_url", ""):
            body = client.get("/settings/status").text
        assert "classification is weaker" in body
        assert "SITE_BASE_URL" in body

    def test_it_is_absent_when_all_three_are_set(self, client):
        with (
            patch.object(settings, "site_base_url", "https://example.test"),
            patch.object(settings, "static_asset_prefixes", ["/assets/"]),
            patch.object(settings, "js_only_path_prefixes", ["/assets/fragments/"]),
        ):
            body = client.get("/settings/status").text
        assert "classification is weaker" not in body

    def test_the_page_and_the_startup_line_read_the_same_list(self):
        """Both call unset_site_settings(); this pins that they still can."""
        from src.config import unset_site_settings

        with patch.object(settings, "site_base_url", ""):
            assert any("SITE_BASE_URL" in item for item in unset_site_settings())


class TestTheCounts:
    def test_unenriched_and_stale_against_a_known_database(self, tmp_db):
        with get_conn(tmp_db) as conn:
            insert_visit(conn, ip="1.1.1.1", timestamp="2026-08-01T00:00:00+00:00")
            insert_visit(conn, ip="2.2.2.2", timestamp="2026-08-01T00:00:00+00:00")
            upsert_ip_intel(conn, {"ip": "1.1.1.1", "country": "DE"})
            # 2.2.2.2 has visits and no intel; 1.1.1.1 was just enriched.
            assert count_unenriched_ips(conn) == 1
            assert count_stale_ips(conn, ttl_days=30) == 0
            assert count_stale_ips(conn, ttl_days=0) == 1


class TestTheEnricherSnapshot:
    """The age reported for the Tor list, which was wrong and invisible.

    _load_tor_exits stamps time.time(); the snapshot subtracted that from
    time.monotonic() and reported the list as 496,394 hours old. Nobody saw it,
    because the list is only fetched with the first enrichment batch and an idle
    instance never has one — so the row said "not loaded yet" and the arithmetic
    behind it was never reached.
    """

    def test_the_age_is_measured_on_the_clock_that_stamped_it(self):
        import time

        import src.enricher as enricher

        with (
            patch.object(enricher, "_tor_exits", {"1.2.3.4"}),
            patch.object(enricher, "_tor_exits_loaded_at", time.time() - 7200),
        ):
            age = enricher.snapshot()["tor_age_seconds"]
        assert age > 0, f"age is negative: the two clocks disagree ({age})"
        assert 7100 < age < 7300, age

    def test_an_unloaded_list_has_no_age(self):
        import src.enricher as enricher

        with (
            patch.object(enricher, "_tor_exits", set()),
            patch.object(enricher, "_tor_exits_loaded_at", 0),
        ):
            snap = enricher.snapshot()
        assert snap["tor_exits"] == 0
        assert snap["tor_age_seconds"] is None

    def test_the_page_says_when_the_list_arrives_rather_than_calling_it_a_fault(self, client):
        """ "not loaded yet" read like something was broken. On an idle instance
        it only means no batch has run."""
        import src.enricher as enricher

        with patch.object(enricher, "_tor_exits", set()):
            body = client.get("/settings/status").text
        assert "downloads with the first enrichment batch" in body


class TestItRendersWithoutTheWorker:
    def test_no_lifespan_means_no_queue_and_no_crash(self, client):
        """A TestClient without a lifespan has no app.state.new_ips_queue.

        Reporting "not running" is the honest answer; an AttributeError on the
        page you open when something is wrong is the worst possible time for one.
        """
        body = client.get("/settings/status")
        assert body.status_code == 200
        assert "not running" in body.text


class TestTheLogFileSaysWhetherItCanBeRead:
    """The tailer reports an unopenable log after 30 seconds and that line then
    scrolls away, while the condition — a bad mount, a path typo, a file the
    container's UID cannot open — stays. The page is where it stays visible."""

    def test_a_readable_log_reports_its_size(self, tmp_path, monkeypatch):
        from src.config import settings
        from src.routes.settings import _log_readability

        log = tmp_path / "access.log"
        log.write_bytes(b"x" * 4096)
        monkeypatch.setattr(settings, "log_path", log)
        assert _log_readability() == {"ok": True, "size": 4096}

    def test_a_missing_log_names_the_reason(self, tmp_path, monkeypatch):
        from src.config import settings
        from src.routes.settings import _log_readability

        monkeypatch.setattr(settings, "log_path", tmp_path / "not-here.log")
        result = _log_readability()
        assert result["ok"] is False
        assert result["reason"]

    def test_a_present_but_unreadable_log_is_the_interesting_case(self, tmp_path, monkeypatch):
        """nginx creates access.log 0640 root:adm, which UID 1000 cannot open —
        the file is there, the size is known, and not a byte can be read."""
        import os

        from src.config import settings
        from src.routes.settings import _log_readability

        if os.geteuid() == 0:
            pytest.skip("root opens anything, so the mode proves nothing")

        log = tmp_path / "access.log"
        log.write_bytes(b"x" * 512)
        log.chmod(0o000)
        monkeypatch.setattr(settings, "log_path", log)
        try:
            result = _log_readability()
        finally:
            log.chmod(0o644)
        assert result["ok"] is False
        assert result["size"] == 512


class TestTheMapKeyIsShownWithoutBeingShown:
    """It is not a secret — it travels in the tile URL and every viewer's browser
    has it. It is masked anyway, because the page is a screenshot away from
    being shared and "set / not set" is the more useful answer regardless."""

    def test_the_page_says_whether_it_is_set_but_not_what_it_is(self, monkeypatch):
        from src.routes.settings import _config_rows

        monkeypatch.setattr(settings, "carto_api_key", "s3cret-key-value")
        rows = {r["env"]: r for group, items in _config_rows() for r in items}
        assert rows["CARTO_API_KEY"]["value"] == "set"
        assert "s3cret" not in str(rows["CARTO_API_KEY"])

    def test_an_unset_key_reads_as_not_set(self, monkeypatch):
        from src.routes.settings import _config_rows

        monkeypatch.setattr(settings, "carto_api_key", "")
        rows = {r["env"]: r for group, items in _config_rows() for r in items}
        assert rows["CARTO_API_KEY"]["value"] == "not set"


class TestTheKeyReachesTheBrowserOnlyWhenSet:
    def test_no_key_means_no_block_at_all(self, tmp_db, monkeypatch):
        monkeypatch.setattr(settings, "carto_api_key", "")
        with TestClient(app) as client:
            assert 'id="map-tile-data"' not in client.get("/visitors").text

    def test_a_key_is_rendered_for_the_map_to_read(self, tmp_db, monkeypatch):
        """The map view needs a marker to render at all — `view == 'map' and
        markers` — so an empty database proves nothing here."""
        monkeypatch.setattr(settings, "carto_api_key", "abc123")
        with get_conn() as conn:
            insert_visit(
                conn,
                ip="198.51.100.4",
                timestamp="2026-06-10T10:00:00+00:00",
                method="GET",
                path="/",
                status=200,
            )
            upsert_ip_intel(conn, {"ip": "198.51.100.4", "lat": 60.1, "lon": 24.9})
        with TestClient(app) as client:
            body = client.get("/visitors?view=map").text
        assert 'id="map-tile-data"' in body
        assert "abc123" in body

    @pytest.mark.parametrize(
        "path",
        ["/", "/analysis", "/exposure", "/settings/status", "/visitors?view=table"],
    )
    def test_pages_without_a_map_do_not_carry_it(self, tmp_db, monkeypatch, path):
        """It sat in base.html at first, so a documentation page and the status
        page both shipped a tile key they have no use for. The table view is in
        the list because map.js is loaded per view, not per page."""
        monkeypatch.setattr(settings, "carto_api_key", "abc123")
        with TestClient(app) as client:
            body = client.get(path).text
        assert "abc123" not in body
