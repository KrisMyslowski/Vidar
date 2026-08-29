"""Two filters were dropping requests worth seeing.

`.json` and `.map` sat in static_extensions, so every request to a .json path
was discarded before the classifier ever saw it — /config.json,
/credentials.json, /.well-known/…, the exact paths a scanner tries. But the
blanket extension is not wrong either: a site that fetches its own
/assets/lang/de.json on every single page load would have every human counted
twice if that were admitted. The path decides, not the suffix.

And a remote_addr that will not parse was reported as "internal", which filed a
broken log field under the wrong reason, hid it completely, and tied it to
filter_internal_ips — a switch it has nothing to do with, and one whose "off"
position would have started inserting the garbage rather than revealing it.
"""

import asyncio
import json
import logging

import pytest

from src import log_processor as lp
from src.config import settings
from src.db import get_conn
from src.log_processor import _report_invalid_ips, parse_log_line, skip_reason


def _entry(path="/", ip="93.184.216.34", ua="Mozilla/5.0"):
    return parse_log_line(
        json.dumps(
            {
                "time": "2026-06-13T10:00:00+00:00",
                "remote_addr": ip,
                "request": f"GET {path} HTTP/1.1",
                "status": 200,
                "body_bytes_sent": 10,
                "http_user_agent": ua,
                "request_method": "GET",
                "request_uri": path,
            }
        )
    )


class TestJsonIsAnAssetOnlyWhereAssetsLive:
    @pytest.fixture
    def assets_at(self, monkeypatch):
        """STATIC_ASSET_PREFIXES ships empty — it describes the watched site, and
        there is no default that fits a second one. Unset, the ambiguous
        extensions are never treated as assets, so a test about *where* assets
        live has to say where that is."""
        from src import config

        monkeypatch.setattr(config.settings, "static_asset_prefixes", ["/assets/"])

    @pytest.mark.parametrize(
        "path",
        [
            "/assets/lang/de.json",
            "/assets/lang/en.json",
            "/assets/js/app.js.map",
            "/assets/lang/de.json?v=3",
        ],
        ids=["de", "en", "sourcemap", "cache-busted"],
    )
    def test_the_sites_own_files_stay_filtered(self, path, assets_at):
        """i18n.js fetches one of these on every page load. Counting them would
        add a phantom visit to every human on the site."""
        assert skip_reason(_entry(path)) == "static-asset"

    @pytest.mark.parametrize(
        "path",
        ["/assets/lang/de.json", "/assets/js/app.js.map"],
        ids=["lang", "sourcemap"],
    )
    def test_unconfigured_prefixes_track_rather_than_discard(self, path):
        """With no prefix configured the same files are *not* dropped. Erring
        toward tracking is the safe direction: a phantom visit is visible and
        correctable, a discarded request is gone before anything can look at it."""
        assert skip_reason(_entry(path)) is None

    @pytest.mark.parametrize(
        "path",
        [
            "/config.json",
            "/credentials.json",
            "/.well-known/security.json",
            "/api/v1/users.json",
            "/admin/config.json",
        ],
        ids=["config", "credentials", "well-known", "api", "admin"],
    )
    def test_probes_are_now_visible(self, path):
        assert skip_reason(_entry(path)) is None, f"{path} was dropped before the classifier"

    @pytest.mark.parametrize(
        "path",
        ["/style.css", "/app.js", "/logo.png", "/font.woff2", "/favicon.ico"],
        ids=["css", "js", "png", "woff2", "ico"],
    )
    def test_the_unambiguous_extensions_are_filtered_anywhere(self, path):
        """These are assets wherever they sit — no scanner learns anything by
        asking for a .woff2, so the path does not need consulting."""
        assert skip_reason(_entry(path)) == "static-asset"

    def test_the_asset_prefix_is_configurable(self, monkeypatch):
        monkeypatch.setattr(settings, "static_asset_prefixes", ["/assets/"])
        assert skip_reason(_entry("/assets/lang.json")) == "static-asset"
        # Same filename, outside the configured prefix: still a tracked request.
        assert skip_reason(_entry("/elsewhere/lang/de.json")) is None

    def test_turning_the_filter_off_still_turns_it_off(self, monkeypatch):
        monkeypatch.setattr(settings, "filter_static_assets", False)
        assert skip_reason(_entry("/assets/lang/de.json")) is None
        assert skip_reason(_entry("/style.css")) is None


class TestAnUnusableAddressIsItsOwnCase:
    @pytest.mark.parametrize(
        "ip",
        ["not-an-ip", "", "1.2.3", "999.1.1.1", "-"],
        ids=["text", "empty", "short", "range", "dash"],
    )
    def test_it_is_reported_as_invalid_not_internal(self, ip):
        assert skip_reason(_entry(ip=ip)) == "invalid-ip"

    def test_it_is_dropped_regardless_of_the_internal_switch(self, monkeypatch):
        """It used to ride on filter_internal_ips, so turning that off would
        have started inserting addresses nothing downstream can use."""
        monkeypatch.setattr(settings, "filter_internal_ips", False)
        assert skip_reason(_entry(ip="not-an-ip")) == "invalid-ip"

    def test_real_internal_addresses_still_read_as_internal(self):
        assert skip_reason(_entry(ip="192.168.1.5")) == "internal-ip"
        assert skip_reason(_entry(ip="127.0.0.1")) == "internal-ip"

    def test_a_public_address_passes(self):
        assert skip_reason(_entry(ip="93.184.216.34")) is None


class TestABrokenAddressFieldIsVisible:
    def test_a_batch_of_them_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            assert _report_invalid_ips(10, 10, False) is True
        assert "unusable remote_addr" in caplog.text
        assert "$remote_addr" in caplog.text, "name the field to check"

    def test_a_stray_one_is_quiet(self):
        assert _report_invalid_ips(100, 1, False) is False

    def test_it_warns_once_per_run(self, caplog):
        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            warned = _report_invalid_ips(10, 10, False)
            for _ in range(4):
                warned = _report_invalid_ips(10, 10, warned)
        assert caplog.text.count("unusable remote_addr") == 1

    async def test_the_tailer_reports_it(self, fast_log, caplog):
        broken = json.dumps(
            {
                "time": "2026-06-13T10:00:00+00:00",
                "remote_addr": "-",
                "request": "GET / HTTP/1.1",
                "status": 200,
                "body_bytes_sent": 10,
                "http_user_agent": "Mozilla/5.0",
                "request_method": "GET",
                "request_uri": "/",
            }
        )
        fast_log.write_text((broken + "\n") * 10)

        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            queue: asyncio.Queue = asyncio.Queue(maxsize=100)
            task = asyncio.create_task(lp.tail_log(queue))
            await asyncio.sleep(0.3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        assert "unusable remote_addr" in caplog.text
        with get_conn() as conn:
            assert conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0] == 0
