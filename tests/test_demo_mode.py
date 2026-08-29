"""DEMO_MODE serves synthetic traffic so the dashboard can be tried without a
server behind it. Two things have to hold: it must never write over real data,
and nobody looking at it may mistake it for real.
"""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient

from src import config
from src.db import get_conn
from src.main import _seed_demo, app
from src.queries import insert_visit


@pytest.fixture(autouse=True)
def _leave_app_state_as_found():
    """`app` is a module-level singleton and the lifespan hangs a queue off it.

    These are the first tests in the suite to run a lifespan against it, so
    without this the queue outlives them and the next file to assert on a
    lifespan-less app finds one anyway."""
    yield
    app.state.__dict__["_state"].pop("new_ips_queue", None)


@pytest.fixture
def demo(tmp_db, tmp_path, monkeypatch):
    """Demo mode with a log file present, so "the tailer did not run" is testable."""
    log = tmp_path / "access.log"
    log.write_text(
        json.dumps(
            {
                "time": "2026-06-13T10:00:00+00:00",
                "remote_addr": "198.51.100.200",
                "request": "GET /from-the-log HTTP/1.1",
                "status": 200,
                "body_bytes_sent": 10,
                "request_method": "GET",
                "request_uri": "/from-the-log",
            }
        )
        + "\n"
    )
    monkeypatch.setattr(config.settings, "demo_mode", True)
    monkeypatch.setattr(config.settings, "log_path", log)
    monkeypatch.setattr(config.settings, "ingest_existing_backlog", True)
    monkeypatch.setattr(config.settings, "poll_interval_seconds", 0.01)
    return log


def _visits() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]


class TestItSeedsOnlyAnEmptyDatabase:
    def test_an_empty_database_gets_traffic(self, tmp_db, monkeypatch):
        monkeypatch.setattr(config.settings, "demo_mode", True)
        _seed_demo()
        assert _visits() > 1000

    def test_a_database_holding_visits_is_left_alone(self, tmp_db, monkeypatch, caplog):
        """Pointing DEMO_MODE at a real database must not write into it."""
        monkeypatch.setattr(config.settings, "demo_mode", True)
        with get_conn() as conn:
            insert_visit(
                conn,
                ip="198.51.100.1",
                timestamp="2026-06-10T10:00:00+00:00",
                method="GET",
                path="/",
                status=200,
            )
        with caplog.at_level(logging.INFO, logger="vidar.main"):
            _seed_demo()
        assert _visits() == 1, "the one real visit, and nothing added"
        assert "seeding nothing" in caplog.text


class TestNothingRealIsReadOrCalled:
    def test_the_log_is_not_ingested(self, demo):
        """Everything the lifespan skips either reads a log that is not there or
        asks a provider about an address that does not exist. Here the log *is*
        there, which is the only way to tell the tailer did not start."""
        with TestClient(app):
            pass
        with get_conn() as conn:
            from_log = conn.execute(
                "SELECT COUNT(*) FROM visits WHERE path = '/from-the-log'"
            ).fetchone()[0]
        assert from_log == 0
        assert _visits() > 1000, "the synthetic traffic is there, the log line is not"


class TestTheStatusPageDoesNotCryWolf:
    """Demo mode reads no log and runs no worker, so the page must not report
    that as breakage. "no — No such file or directory" beside a tooltip saying
    nothing is being ingested is exactly what a first-time reader should not
    see on the page they open to check whether it works."""

    def test_the_log_is_not_read_rather_than_unreadable(self, demo):
        with TestClient(app) as client:
            body = client.get("/settings/status").text
        assert "not read — DEMO_MODE" in body
        assert "No such file or directory" not in body

    def test_the_queue_says_it_is_not_running(self, demo):
        """Nothing drains it in demo mode, so the page's existing branch for a
        missing queue is the honest one."""
        with TestClient(app) as client:
            body = client.get("/settings/status").text
        assert "not running" in body


class TestEveryPageSaysSo:
    @pytest.mark.parametrize("path", ["/", "/visitors", "/analysis", "/settings/status"])
    def test_the_banner_is_on_it(self, demo, path):
        with TestClient(app) as client:
            body = client.get(path).text
        assert "Demo mode." in body
        assert "RFC 5737" in body

    def test_a_real_deployment_has_no_banner(self, tmp_db, monkeypatch):
        monkeypatch.setattr(config.settings, "demo_mode", False)
        with TestClient(app) as client:
            assert "Demo mode." not in client.get("/").text
