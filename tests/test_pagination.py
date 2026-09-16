"""The page count four routes and the pagination macro depend on.

`total_pages` has no test and its JSON key is never asserted either — the
closest, test_visits_pagination, reads the row count and ignores the number the
footer is drawn from. Both of its interesting cases are boundaries: an exact
multiple, where an off-by-one adds an empty page, and an empty result, where the
max(1, …) is the only reason the footer does not say "Page 1 / 0".
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.main import app
from src.routes._helpers import total_pages
from tests.test_dashboard_routes import dashboard_db  # noqa: F401


class TestTheArithmetic:
    @pytest.mark.parametrize(
        "total,limit,expected",
        [
            (0, 50, 1),
            (1, 50, 1),
            (49, 50, 1),
            (50, 50, 1),
            (51, 50, 2),
            (100, 50, 2),
            (101, 50, 3),
            (4, 2, 2),
            (5, 2, 3),
            (1, 1, 1),
        ],
        ids=[
            "empty",
            "one",
            "just-under",
            "exact-multiple",
            "one-over",
            "two-exact",
            "two-and-one",
            "small-exact",
            "small-remainder",
            "single-per-page",
        ],
    )
    def test_it_rounds_up(self, total, limit, expected):
        assert total_pages(total, limit) == expected

    def test_an_exact_multiple_does_not_add_an_empty_page(self):
        """The off-by-one this shape is usually written with."""
        assert total_pages(100, 25) == 4

    def test_nothing_at_all_is_still_one_page(self):
        """The footer reads "Page 1 / N"; a zero here would print "Page 1 / 0"
        for every empty filter result."""
        assert total_pages(0, 50) == 1
        assert total_pages(0, 1) == 1


class TestTheApiReportsIt:
    @pytest.fixture
    def client(self, dashboard_db):  # noqa: F811
        with patch.object(settings, "db_path", dashboard_db):
            yield TestClient(app)

    def test_the_key_matches_the_rows(self, client):
        body = client.get("/api/visits?page=1&limit=1").json()
        assert body["total_pages"] == body["total"], "one row per page"
        assert body["total_pages"] >= 1

    def test_an_impossible_filter_still_reports_one_page(self, client):
        body = client.get("/api/visits?ip=198.51.100.99").json()
        assert body["total"] == 0
        assert body["total_pages"] == 1


def test_pages_of_tied_rows_cover_every_address_once(tmp_db):
    """Ten addresses with one visit each, paged three at a time by visit count —
    every row ties on the sort key, so only the tiebreaker decides which page an
    address lands on. The ORDER BY carried none, and a plan free to reorder ties
    between two requests is how an address shows twice and another never."""
    from src.db import get_conn
    from src.queries import get_visitors_grouped, insert_visit

    ips = [f"203.0.113.{n}" for n in range(10)]
    with get_conn(tmp_db) as conn:
        for ip in reversed(ips):
            insert_visit(conn, ip=ip, timestamp="2026-08-20T10:00:00+00:00", path="/")
    with get_conn(tmp_db) as conn:
        pages = [
            [r["ip"] for r in get_visitors_grouped(conn, page=p, limit=3, sort="visit_count")]
            for p in (1, 2, 3, 4)
        ]
    seen = [ip for page in pages for ip in page]
    assert sorted(seen) == sorted(ips) and len(seen) == len(set(seen))
    assert seen == sorted(ips), "ties resolve by address, the same way every time"


class TestAPagePastTheEnd:
    """?page=9999 rendered an empty table under a header still stating the real
    total — "3 IPs", no rows, "Page 9999 / 1". /incidents/case clamps and says
    why; the three paged pages now send the reader to their last page."""

    @pytest.fixture
    def client(self, dashboard_db):  # noqa: F811
        with patch("src.config.settings.db_path", dashboard_db):
            yield TestClient(app)

    @pytest.mark.parametrize(
        "url, last",
        [
            ("/visitors?range=all&page=9999", "/visitors?range=all&page=1"),
            ("/visitors?group=asn&range=all&page=50", "/visitors?group=asn&range=all&page=1"),
            ("/visitors/203.0.113.10?page=9999", "/visitors/203.0.113.10?page=1"),
        ],
    )
    def test_it_redirects_to_the_last_page(self, client, url, last):
        resp = client.get(url, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == last

    def test_a_page_that_exists_is_served(self, client):
        assert client.get("/visitors?range=all&page=1", follow_redirects=False).status_code == 200
