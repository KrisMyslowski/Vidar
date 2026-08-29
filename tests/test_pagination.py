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
