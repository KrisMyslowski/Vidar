"""Template rendering must not open a database connection.

routes/_cache.py states the rule at the top of the file — synchronous sqlite3 in
a coroutine stalls the log tailer and the enrichment worker — and enforces it
for handlers through fetch(). The two Jinja globals broke it in the one place
nothing could await: earliest_date() and attention_count() are called while a
template renders, so a cold or expired cache meant a query on the event loop,
hourly for one and every minute for the other, on every page that has a nav bar.

They read now, and schedule the refresh beside the render.
"""

import asyncio
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.main import app
from src.routes import _cache
from tests.test_dashboard_routes import dashboard_db  # noqa: F401

PAGES = [
    "/",
    "/visitors",
    "/analysis",
    "/exposure",
    "/settings/storage",
    "/settings/status",
    "/docs/usage",
]


@pytest.fixture
def client(dashboard_db):  # noqa: F811
    with patch.object(settings, "db_path", dashboard_db):
        yield TestClient(app)


class TestTheGlobalsOnlyRead:
    """Under a running loop — which is where a render happens. Without one, and
    only then, _refresh_soon does the work inline: a script or a sync test has
    nothing to schedule onto."""

    async def test_earliest_date_does_not_query(self, tmp_db):
        """A cold cache returns nothing rather than blocking to find out."""
        with patch("src.routes._cache.get_conn") as conn:
            assert _cache._earliest_date() == ""
            conn.assert_not_called()

    async def test_attention_count_does_not_query(self, tmp_db):
        with patch("src.routes._cache.get_conn") as conn:
            assert _cache._attention_count() == 0
            conn.assert_not_called()

    def test_they_serve_what_the_cache_holds(self, tmp_db):
        _cache._earliest_date_cache = "2026-01-01"
        _cache._earliest_date_cached_at = time.time()
        _cache._agg_cache["attention"] = (time.time(), [{"a": 1}, {"b": 2}])
        try:
            with patch("src.routes._cache.get_conn") as conn:
                assert _cache._earliest_date() == "2026-01-01"
                assert _cache._attention_count() == 2
                conn.assert_not_called()
        finally:
            _cache._earliest_date_cache = None
            _cache._agg_cache.clear()


class TestWarmingFillsThemOffTheLoop:
    async def test_warm_caches_populates_both(self, dashboard_db):  # noqa: F811
        with patch.object(settings, "db_path", dashboard_db):
            await _cache.warm_caches()
        assert _cache._earliest_date_cache, "a date the range inputs can use"
        assert "attention" in _cache._agg_cache

    async def test_it_runs_off_the_event_loop(self, dashboard_db):  # noqa: F811
        """Everything it calls is blocking sqlite3."""
        with patch.object(settings, "db_path", dashboard_db):
            with patch("src.routes._cache.asyncio.to_thread") as to_thread:
                to_thread.return_value = None
                await _cache.warm_caches()
        assert to_thread.call_count == 2


class TestPagesStillRenderTheValues:
    def test_the_nav_badge_appears_once_warm(self, client, dashboard_db):  # noqa: F811
        _cache._agg_cache["attention"] = (time.time(), [{"x": 1}])
        try:
            assert client.get("/visitors").status_code == 200
        finally:
            _cache._agg_cache.clear()

    @pytest.mark.parametrize("page", PAGES)
    def test_every_page_renders_with_a_cold_cache(self, client, page):
        """The globals return neutral values rather than raising or blocking."""
        assert client.get(page).status_code == 200


class TestARefreshIsScheduledNotAwaited:
    async def test_a_stale_value_triggers_one_refresh(self, tmp_db):
        calls = []

        def produce():
            calls.append(1)

        before = set(_cache._refresh_tasks)
        _cache._refresh_soon("probe", produce)
        _cache._refresh_soon("probe", produce)  # already in flight
        _cache._refresh_soon("probe", produce)

        # Wait for *this* test's task. Waiting on the whole set hangs: it can
        # hold tasks scheduled on an earlier test's event loop, which is closed
        # and will never run them to completion.
        mine = set(_cache._refresh_tasks) - before
        assert len(mine) == 1, "three renders, one scheduled refresh"
        await asyncio.wait(mine, timeout=3)
        assert calls == [1], "three renders, one query"

    def test_without_a_loop_it_just_does_the_work(self, tmp_db):
        """Scripts and tests call these outside an event loop."""
        calls = []
        _cache._refresh_soon("probe-sync", lambda: calls.append(1))
        assert calls == [1]
