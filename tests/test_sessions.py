"""What an address did, cut into sessions.

The third axis. Identity says what something is and the signals say where it
sits; neither could say that a search visitor read three pages and then walked
eleven paths that do not exist. That sentence is what these tests are about.

Two things here are model decisions rather than facts — the 30-minute gap and
the behaviour thresholds — and both are tested at their edges, because a
threshold nobody has written a case for is a number that drifts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.db import get_conn
from src.queries import count_sessions, get_sessions, upsert_ip_intel
from src.sessions import SESSION_GAP_SECONDS, behaviour_for

BASE = datetime(2026, 8, 20, 3, 12, tzinfo=timezone.utc)
HOST = "https://example.com"


@pytest.fixture(autouse=True)
def site(monkeypatch):
    """internal_nav needs a host; without one the signal is lost, not inverted."""
    from src import config

    monkeypatch.setattr(config.settings, "site_base_url", HOST)


def _req(conn, ip, offset_s, path="/", status=200, method="GET", referer=""):
    from src.queries import insert_visit

    upsert_ip_intel(conn, {"ip": ip})
    insert_visit(
        conn,
        ip=ip,
        timestamp=(BASE + timedelta(seconds=offset_s)).isoformat(),
        method=method,
        path=path,
        status=status,
        referer=referer,
    )


# ── Where the cut falls ──────────────────────────────────────────────────────


def test_requests_close_together_are_one_session(tmp_db):
    with get_conn(tmp_db) as conn:
        for k in range(4):
            _req(conn, "203.0.113.1", k * 60)
    with get_conn(tmp_db) as conn:
        assert count_sessions(conn, "203.0.113.1") == 1
        assert get_sessions(conn, "203.0.113.1")[0]["requests"] == 4


def test_a_gap_longer_than_the_threshold_starts_a_new_session(tmp_db):
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0)
        _req(conn, "203.0.113.1", SESSION_GAP_SECONDS + 1)
    with get_conn(tmp_db) as conn:
        assert count_sessions(conn, "203.0.113.1") == 2


def test_a_gap_of_exactly_the_threshold_does_not(tmp_db):
    """The boundary is `>`, and a boundary nobody tested is a boundary that moves."""
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0)
        _req(conn, "203.0.113.1", SESSION_GAP_SECONDS)
    with get_conn(tmp_db) as conn:
        assert count_sessions(conn, "203.0.113.1") == 1


def test_a_steady_poller_stays_one_session(tmp_db):
    """Ten-minute polling never opens a wide enough gap. That is not a bug.

    It is the shape that makes the duration column need a unit that scales —
    such a session legitimately spans the whole retention window.
    """
    with get_conn(tmp_db) as conn:
        for k in range(20):
            _req(conn, "203.0.113.1", k * 600)
    with get_conn(tmp_db) as conn:
        sessions = get_sessions(conn, "203.0.113.1")
    assert len(sessions) == 1
    assert sessions[0]["duration"] == 19 * 600


def test_another_address_is_another_session_series(tmp_db):
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0)
        _req(conn, "203.0.113.2", 5)
    with get_conn(tmp_db) as conn:
        assert count_sessions(conn, "203.0.113.1") == 1
        assert get_sessions(conn, "203.0.113.1")[0]["requests"] == 1


def test_sessions_come_back_newest_first(tmp_db):
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0, path="/first")
        _req(conn, "203.0.113.1", SESSION_GAP_SECONDS * 2, path="/second")
    with get_conn(tmp_db) as conn:
        assert [s["entry_path"] for s in get_sessions(conn, "203.0.113.1")] == [
            "/second",
            "/first",
        ]


def test_the_entry_is_the_first_request_not_an_arbitrary_one(tmp_db):
    """The whole narrative hangs on this: where the session came in."""
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0, path="/", referer="https://www.google.com/search?q=x")
        _req(conn, "203.0.113.1", 20, path="/about", referer=f"{HOST}/")
        _req(conn, "203.0.113.1", 40, path="/cv", referer=f"{HOST}/about")
    with get_conn(tmp_db) as conn:
        session = get_sessions(conn, "203.0.113.1")[0]
    assert session["entry_path"] == "/"
    assert session["entry_referer"] == "https://www.google.com/search?q=x"


def test_the_limit_bounds_the_page_and_not_the_truth(tmp_db):
    with get_conn(tmp_db) as conn:
        for k in range(6):
            _req(conn, "203.0.113.1", k * (SESSION_GAP_SECONDS + 1))
    with get_conn(tmp_db) as conn:
        assert count_sessions(conn, "203.0.113.1") == 6
        assert len(get_sessions(conn, "203.0.113.1", limit=2)) == 2


def test_an_unknown_address_has_no_sessions(tmp_db):
    with get_conn(tmp_db) as conn:
        assert get_sessions(conn, "203.0.113.9") == []
        assert count_sessions(conn, "203.0.113.9") == 0


# ── What the session did ─────────────────────────────────────────────────────


def _session(**over):
    base = {
        "requests": 0,
        "max_path_repeats": 0,
        "post_requests": 0,
        "refused": 0,
        "distinct_404_paths": 0,
        "probe_404": 0,
        "distinct_2xx_paths": 0,
        "internal_nav": 0,
        "ok_requests": 0,
    }
    return {**base, **over}


def test_one_request_is_an_event_not_a_behaviour(tmp_db):
    """Most sessions on a quiet site are this, and labelling them would make the
    majority label an artefact of the threshold rather than of the traffic."""
    assert behaviour_for(_session(requests=1, ok_requests=1, distinct_2xx_paths=1)) == ""


def test_the_same_door_many_times_is_brute_force():
    assert (
        behaviour_for(_session(requests=12, max_path_repeats=12, post_requests=12, refused=12))
        == "brute-force"
    )


def test_repetition_without_refusal_or_posting_is_not_brute_force():
    """A reload loop on a page that works is not an attack on it."""
    assert (
        behaviour_for(
            _session(requests=12, max_path_repeats=12, ok_requests=12, distinct_2xx_paths=1)
        )
        != "brute-force"
    )


def test_many_paths_that_do_not_exist_is_enumeration():
    assert (
        behaviour_for(_session(requests=14, distinct_404_paths=11, probe_404=11)) == "enumeration"
    )


def test_a_site_whose_own_pages_404_is_not_enumerated():
    """Eight misses inside a long session of real reading is a broken deployment.

    This is why the ratio is there beside the count: without it, a site with
    stale links would report every visitor as an enumerator.
    """
    assert (
        behaviour_for(
            _session(
                requests=60,
                distinct_404_paths=9,
                probe_404=9,
                internal_nav=40,
                ok_requests=51,
                distinct_2xx_paths=20,
            )
        )
        != "enumeration"
    )


def test_a_short_look_for_the_usual_things_is_recon():
    assert behaviour_for(_session(requests=4, probe_404=3, distinct_404_paths=3)) == "recon"


def test_recon_becomes_enumeration_when_it_gets_systematic():
    """The two differ in size, not in kind, and the chain reaches the larger first."""
    assert (
        behaviour_for(_session(requests=20, probe_404=18, distinct_404_paths=18)) == "enumeration"
    )


def test_many_real_pages_without_following_links_is_scraping():
    assert (
        behaviour_for(_session(requests=20, ok_requests=20, distinct_2xx_paths=20)) == "scraping"
    )


def test_the_same_pages_reached_from_one_another_is_browsing():
    """Identical counts to the case above but for the navigation. That one
    difference is the whole distinction, so it gets its own case."""
    assert (
        behaviour_for(
            _session(requests=20, ok_requests=20, distinct_2xx_paths=20, internal_nav=15)
        )
        == "browsing"
    )


def test_a_session_that_says_nothing_is_left_blank():
    """Two requests, both refused, no paths, no navigation. There is no story."""
    assert behaviour_for(_session(requests=2, refused=2)) == ""


# ── The table ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_db):
    from fastapi.testclient import TestClient

    from src.config import settings
    from src.main import app

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def test_the_table_tells_the_story_the_dashboard_could_not(client, tmp_db):
    """The sentence from the plan, as a row: arrived from a search engine, read
    three pages, then tried eleven paths that do not exist."""
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.60", 0, "/", referer="https://www.google.com/search?q=x")
        _req(conn, "203.0.113.60", 18, "/about", referer=f"{HOST}/")
        _req(conn, "203.0.113.60", 95, "/cv", referer=f"{HOST}/about")
        for k in range(11):
            _req(conn, "203.0.113.60", 140 + k * 4, f"/wp-admin/p{k}.php", status=404)
    text = client.get("/visitors/203.0.113.60").text
    assert "Sessions" in text and "1 session" in text
    assert "https://www.google.com/search?q=x" in text
    assert ">Enumeration</span>" in text


def test_a_cut_list_says_it_was_cut(client, tmp_db):
    """A page showing 25 of 40 must not read as an address with 25 sessions."""
    with get_conn(tmp_db) as conn:
        for k in range(30):
            _req(conn, "203.0.113.1", k * (SESSION_GAP_SECONDS + 1))
    text = client.get("/visitors/203.0.113.1").text
    assert "30 sessions" in text and "newest 25 shown" in text


def test_the_count_headers_stay_short_enough_for_their_column(client, tmp_db):
    """A fixed-layout table clips cells but not headers.

    "Requests" and "Not found" each widened their own c-num column past its
    neighbours — 97 px and 107 px against 89 px — which the layout suite in
    Docker catches and nothing else does. This is the cheap guard that runs
    everywhere, so the short forms cannot quietly grow back.
    """
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0)
    text = client.get("/visitors/203.0.113.1").text
    # Anchored on the title markup, not on the word: "Sessions" also occurs in
    # the Started tooltip, and splitting on it lands in the middle of an
    # attribute. And ">Requests<" appears on the page anyway — as a stat card —
    # so the header check has to be scoped to this thead or it means nothing.
    head = text.split('table-block-title">Sessions')[1].split("</thead>")[0]
    for label in (">Hits<", ">Paths<", ">Read<", ">404s<"):
        assert label in head
    assert ">Requests<" not in head and ">Not found<" not in head
