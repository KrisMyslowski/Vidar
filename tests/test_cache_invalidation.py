"""A write the dashboard made itself must show on the next page it renders.

The aggregate cache holds for a minute and the earliest-date floor for an hour,
both to keep slow summaries off the event loop. Neither was cleared by the
Settings actions that change what they summarise: after restoring or deleting a
month the Overview kept serving the numbers from before for up to a minute, and
the date picker's floor pointed at a day that no longer existed for up to an
hour — on the one change the operator had just made and was looking for.
"""

from fastapi.testclient import TestClient

from src.db import get_conn
from src.main import app
from src.queries import insert_visit
from src.routes import _cache


def _visit(conn, day):
    insert_visit(conn, ip="203.0.113.1", timestamp=f"{day}T10:00:00+00:00", path="/")


def test_deleting_a_month_refreshes_the_cached_summaries(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "2026-04-05")
        _visit(conn, "2026-08-05")
    _cache._load_earliest_date()
    _cache._cached("stats:probe", lambda: "before")
    assert _cache._earliest_date() == "2026-04-05"

    resp = TestClient(app).post("/settings/storage/delete-month/2026-04", follow_redirects=False)

    assert resp.status_code == 303
    assert _cache._earliest_date() == "2026-08-05", "the floor moved with the data"
    assert _cache._cached("stats:probe", lambda: "after") == "after", "no stale summary"
