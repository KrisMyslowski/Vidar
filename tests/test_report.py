"""The monthly report — the one surface that is read rather than interrogated.

A report is believed or it is discarded, and the way it loses that is by
disagreeing with the pages it summarises. So the tests here are mostly about
agreement: between the page and the Markdown, between the report and the
queries the dashboard already runs, and between a sentence and the number it
claims to describe.
"""

from __future__ import annotations

import re

import pytest

from src.db import get_conn
from src.queries import insert_visit, set_visitor_class, upsert_ip_intel
from src.report import available_months, build_report, month_bounds, month_label, previous_month
from src.report_text import render_markdown

HUMAN = "humans/browser-direct"
PROBER = "bots/vulnerability-probers"


def _hit(
    conn, ip, path="/", ts="2026-08-10T12:00:00+00:00", status=200, cls=PROBER, bytes_sent=100
):
    upsert_ip_intel(conn, {"ip": ip})
    set_visitor_class(conn, ip, cls)
    insert_visit(conn, ip=ip, timestamp=ts, path=path, status=status, bytes_sent=bytes_sent)


# ── The month, as a window ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "month,expected",
    [
        ("2026-08", ("2026-08-01", "2026-08-31")),
        ("2026-04", ("2026-04-01", "2026-04-30")),
        ("2024-02", ("2024-02-01", "2024-02-29")),  # leap year
        ("2026-02", ("2026-02-01", "2026-02-28")),
    ],
)
def test_the_window_covers_the_whole_month(month, expected):
    """Both ends inclusive, which is what the query layer's window means. A
    report that stopped at the 30th would under-count seven months a year."""
    assert month_bounds(month) == expected


def test_the_previous_month_crosses_the_year():
    assert previous_month("2026-01") == "2025-12"
    assert previous_month("2026-08") == "2026-07"


def test_the_label_is_a_month_somebody_says_out_loud():
    assert month_label("2026-08") == "August 2026"


# ── What the report states ───────────────────────────────────────────────────


def test_the_headline_share_is_addresses_not_requests(tmp_db):
    """The sentence says "of the addresses that reached this server", and that
    is the number it has to be: one person reading forty pages is one address,
    and counting requests would report them as forty per cent of a quiet month.
    """
    with get_conn(tmp_db) as conn:
        for n in range(40):
            _hit(conn, "203.0.113.1", path=f"/page-{n}", cls=HUMAN)
        for n in range(3):
            _hit(conn, f"198.51.100.{n}", path="/.env", status=404)
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    assert r["addresses"] == 4 and r["humans"] == 1
    assert r["human_share"] == 25.0, "one address of four, not forty requests of forty-three"


def test_a_first_month_is_not_a_rise_from_nothing(tmp_db):
    """The previous month is empty, so every share would read as an increase
    against zero. The report withholds the comparison instead of inventing it."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1")
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    assert r["previous"]["comparable"] is False
    assert r["visits_delta"] is None
    assert all(row["delta"] is None for row in r["composition"])
    assert "no traffic" in render_markdown(r)


def test_a_month_compares_against_the_one_before_it(tmp_db):
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", ts="2026-07-10T12:00:00+00:00")
        _hit(conn, "203.0.113.2", ts="2026-08-10T12:00:00+00:00")
        _hit(conn, "203.0.113.3", ts="2026-08-11T12:00:00+00:00")
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    assert r["previous"]["label"] == "July 2026"
    assert r["visits_delta"] == 100, "two requests against one"


def test_a_finding_is_new_against_the_database_not_the_window(tmp_db):
    """Otherwise every finding is new in every month it appears in, and the one
    line an operator actually wants — something started being served — is
    drowned by the ones that have been served all along.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "198.51.100.1", path="/old.bak", ts="2026-07-02T12:00:00+00:00")
        _hit(conn, "198.51.100.1", path="/old.bak", ts="2026-08-02T12:00:00+00:00")
        _hit(conn, "198.51.100.2", path="/fresh.sql", ts="2026-08-03T12:00:00+00:00")
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    new = {f["path"] for f in r["new_findings"]}
    assert new == {"/fresh.sql"}, "/old.bak has been served since July"
    assert r["finding_total"] == 2, "both are still findings this month"


def test_an_empty_month_names_the_log_not_the_site(tmp_db):
    """Zero requests is almost always a broken log path or an archived month,
    and a report that said "a quiet month" would send the reader looking in the
    wrong place."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", ts="2026-07-10T12:00:00+00:00")
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    assert r["empty"] is True
    text = render_markdown(r)
    assert "No requests were logged" in text
    assert "statement about the log" in text


def test_repeat_runs_of_one_program_are_named_as_such(tmp_db):
    """Eleven incidents from one signature is one program that kept coming back;
    the table cannot show it, because every row reads the same."""
    from tests.test_incidents import TOOL, _probe

    with get_conn(tmp_db) as conn:
        for run in range(2):
            for n in range(3):
                _probe(conn, f"203.0.113.{run}{n}", TOOL, offset_s=run * 90000 + n * 60)
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    assert r["incident_total"] == 2
    assert r["incident_programs"] == 1, "the same five paths, in the same order, twice"
    assert "1 distinct program" in render_markdown(r)


def test_an_address_in_two_incidents_is_one_address(tmp_db):
    """ "N incidents, M addresses between them" summed each incident's own distinct
    count, so the same three machines running the same tool on two days read as
    six addresses — one campaign reported at twice its size."""
    from tests.test_incidents import TOOL, _probe

    with get_conn(tmp_db) as conn:
        for run in range(2):
            for n in range(3):
                _probe(conn, f"203.0.113.{n}", TOOL, offset_s=run * 90000 + n * 60)
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    assert r["incident_total"] == 2
    assert r["incident_addresses"] == 3
    assert "2 incidents, 3 addresses between them" in render_markdown(r)


# ── Page and Markdown are one report ─────────────────────────────────────────


@pytest.fixture
def client(tmp_db):
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from src.config import settings
    from src.main import app

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def test_the_markdown_states_the_same_figures_as_the_page(client, tmp_db):
    """The whole reason build_report exists apart from both. A forwarded copy
    that quietly disagreed with the dashboard it came from would discredit the
    dashboard, not the copy.
    """
    with get_conn(tmp_db) as conn:
        for n in range(12):
            _hit(conn, f"198.51.100.{n}", path="/.env", status=404)
        _hit(conn, "203.0.113.1", cls=HUMAN)
        _hit(conn, "198.51.100.99", path="/leak.sql")

    page = client.get("/report?month=2026-08").text
    md = client.get("/report?month=2026-08&format=md").text
    with get_conn(tmp_db) as conn:
        r = build_report(conn, "2026-08")

    for figure in (f"{r['visits']:,}", f"{r['addresses']:,}", f"{r['humans']:,}"):
        assert figure in page, figure
        assert figure in md, figure
    # The headline share, which is the sentence both are built around.
    share = f"{r['human_share']:g} %"
    assert share in md
    assert share.replace(" ", "&nbsp;") in page or share in page


def test_the_markdown_downloads_as_a_file(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1")
    r = client.get("/report?month=2026-08&format=md")

    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert 'filename="vidar-2026-08.md"' in r.headers["content-disposition"]
    assert r.text.startswith("# Vidar — August 2026")


# ── The route ────────────────────────────────────────────────────────────────


def test_the_month_defaults_to_the_most_recent_one_with_traffic(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", ts="2026-07-10T12:00:00+00:00")
        _hit(conn, "203.0.113.2", ts="2026-08-10T12:00:00+00:00")
    assert "August 2026" in client.get("/report").text


def test_a_month_the_database_no_longer_holds_is_refused(client, tmp_db):
    """Retention moves whole months out to a zip. Rendering one as a month in
    which nothing happened would be a false statement about the site."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1")
    assert client.get("/report?month=2020-01").status_code == 404
    assert client.get("/report?month=nonsense").status_code == 422


def test_the_page_says_so_when_no_month_has_traffic(client, tmp_db):
    body = client.get("/report").text
    assert "No month holds any traffic yet" in body
    assert available_months  # the picker is fed from the database, not a calendar


def test_the_report_is_in_the_navigation(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1")
    assert re.search(r'href="/report"[^>]*>Report<', client.get("/").text)


def test_the_incident_rule_states_the_window_the_code_applies(client, tmp_db, monkeypatch):
    """Both renderings once said "inside an hour" while incidents.py clustered at a
    day — the value an hour was replaced with because it found nothing on a real
    week. "None" beside a rule the code does not apply cannot tell a quiet month
    from a broken feature, which is the one job that sentence has.

    Moved to seven days here so the test cannot pass on a lucky hardcoded string.
    """
    import src.report

    monkeypatch.setattr(src.report, "INCIDENT_GAP_SECONDS", 7 * 86400)
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1")

    page = client.get("/report?month=2026-08").text
    md = client.get("/report?month=2026-08&format=md").text

    for text in (page, md):
        assert "within 7 d of each other" in text
        assert "inside an hour" not in text
