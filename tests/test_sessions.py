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


def test_a_protocol_error_is_not_a_page(tmp_db):
    """The classifier's unique_paths already excluded these, because a failed
    handshake plus `/` read as someone exploring two pages. The session query,
    feeding a field of the same name, did not — and unserved_paths counted the
    pseudo-path too, making enumeration easier to reach."""
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0, path="[handshake on HTTP port]", status=400)
        _req(conn, "203.0.113.1", 5, path="[binary payload]", status=400)
        _req(conn, "203.0.113.1", 10, path="/")
    with get_conn(tmp_db) as conn:
        session = get_sessions(conn, "203.0.113.1")[0]
    assert session["requests"] == 3
    assert session["unique_paths"] == 1
    assert session["unserved_paths"] == 0


def test_the_entry_survives_the_first_request_being_a_protocol_error(tmp_db):
    """The entry is the first request, whatever it was; excluding pseudo-paths from
    the page count must not move it."""
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0, path="[empty request]", status=400)
        _req(conn, "203.0.113.1", 5, path="/about", referer="https://example.org/")
    with get_conn(tmp_db) as conn:
        session = get_sessions(conn, "203.0.113.1")[0]
    assert session["entry_path"] == "[empty request]"
    assert session["entry_referer"] == ""


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
    """A session with nothing in it, for each case to put one thing back.

    `unserved_paths` is what the rules read: distinct paths that never came
    back 2xx. The query derives it as unique_paths - distinct_2xx_paths, so a
    case that sets one has to keep the others consistent with it.
    """
    base = {
        "requests": 0,
        "content_requests": 0,
        "unique_paths": 0,
        "unserved_paths": 0,
        "probe_404": 0,
        "distinct_2xx_paths": 0,
        "ok_requests": 0,
        "internal_nav": 0,
        "max_path_repeats": 0,
        "post_requests": 0,
        "refused": 0,
    }
    return {**base, **over}


def test_one_request_is_an_event_not_a_behaviour():
    """Most sessions on a quiet site are this, and labelling them would make the
    majority label an artefact of the threshold rather than of the traffic."""
    assert (
        behaviour_for(
            _session(
                requests=1, content_requests=1, ok_requests=1, unique_paths=1, distinct_2xx_paths=1
            )
        )
        == ""
    )


def test_the_same_door_many_times_is_brute_force():
    assert (
        behaviour_for(
            _session(
                requests=12,
                content_requests=12,
                unique_paths=1,
                unserved_paths=1,
                max_path_repeats=12,
                post_requests=12,
                refused=12,
            )
        )
        == "brute-force"
    )


def test_repetition_without_refusal_or_posting_is_not_brute_force():
    """A reload loop on a page that works is not an attack on it."""
    assert (
        behaviour_for(
            _session(
                requests=12,
                content_requests=12,
                unique_paths=1,
                ok_requests=12,
                distinct_2xx_paths=1,
                max_path_repeats=12,
            )
        )
        != "brute-force"
    )


def test_many_paths_the_server_never_served_is_enumeration():
    assert (
        behaviour_for(
            _session(requests=14, content_requests=14, unique_paths=14, unserved_paths=11)
        )
        == "enumeration"
    )


def test_a_site_whose_own_links_have_gone_stale_is_not_enumerated():
    """Nine dead links inside a long session of real reading is a broken
    deployment. Without the share beside the count, every visitor to a site with
    stale links would be reported as an enumerator."""
    assert (
        behaviour_for(
            _session(
                requests=60,
                content_requests=60,
                unique_paths=29,
                unserved_paths=9,
                distinct_2xx_paths=20,
                internal_nav=40,
                ok_requests=51,
            )
        )
        != "enumeration"
    )


def test_a_scanner_that_only_ever_got_redirected_is_still_enumerating():
    """The case that made this rule what it is.

    One address made 117 036 requests, every one a port-80 redirect it never
    followed — 527 distinct paths a session, names like /Aqua.arm6, a botnet
    looking for somewhere to drop a payload. Not one 404, because not one
    request ever reached the site, so a rule counting 404s saw a session that
    had done nothing at all.
    """
    assert (
        behaviour_for(
            _session(requests=529, content_requests=0, unique_paths=527, unserved_paths=527)
        )
        == "enumeration"
    )


def test_probing_hard_enough_to_be_refused_is_still_enumerating():
    """The other production case, and the more embarrassing one.

    2 837 of 6 029 requests answered 404 and 3 181 answered 503 — the server
    refusing under the load. The 404 share fell to 47 % and slid under a 50 %
    threshold, so probing *harder* made it less likely to be called an
    enumerator. Asking the question of the request rather than the response
    removes the perverse incentive.
    """
    assert (
        behaviour_for(
            _session(
                requests=6029,
                content_requests=6020,
                unique_paths=3006,
                unserved_paths=3005,
                distinct_2xx_paths=1,
                ok_requests=1,
            )
        )
        == "enumeration"
    )


def test_a_short_look_for_the_usual_things_is_recon():
    """Keyed on paths that do not exist, not on paths that were merely not
    served: a redirect is not a short look for anything."""
    assert (
        behaviour_for(
            _session(requests=4, content_requests=4, unique_paths=4, unserved_paths=3, probe_404=3)
        )
        == "recon"
    )


def test_a_redirect_inside_the_site_is_not_recon():
    """A person whose /about answers 301 to /about/ has a path that was never
    served, and it must not read as reconnaissance.

    Recon is keyed on paths that do not *exist* — 404s — and not on paths that
    were merely not served, which is what keeps this case out of it. Reading it
    the other way moved seventeen real browsing sessions out of their label on
    one week of production.
    """
    assert (
        behaviour_for(
            _session(
                requests=4,
                content_requests=4,
                unique_paths=3,
                unserved_paths=1,
                distinct_2xx_paths=2,
                ok_requests=3,
                internal_nav=2,
            )
        )
        == "browsing"
    )


def test_recon_becomes_enumeration_when_it_gets_systematic():
    """The two differ in size, not in kind, and the chain reaches the larger first."""
    assert (
        behaviour_for(
            _session(
                requests=20, content_requests=20, unique_paths=18, unserved_paths=18, probe_404=18
            )
        )
        == "enumeration"
    )


def test_two_redirects_are_not_a_short_look_at_anything():
    """Recon needs a request that reached the site. Without that guard a session
    of two port-80 redirects — where nothing is known about anything — would be
    called a short look for the usual things."""
    assert (
        behaviour_for(_session(requests=2, content_requests=0, unique_paths=2, unserved_paths=2))
        == ""
    )


def test_many_real_pages_without_following_links_is_scraping():
    assert (
        behaviour_for(
            _session(
                requests=20,
                content_requests=20,
                unique_paths=20,
                distinct_2xx_paths=20,
                ok_requests=20,
            )
        )
        == "scraping"
    )


def test_the_same_pages_reached_from_one_another_is_browsing():
    """Identical counts to the case above but for the navigation. That one
    difference is the whole distinction, so it gets its own case."""
    assert (
        behaviour_for(
            _session(
                requests=20,
                content_requests=20,
                unique_paths=20,
                distinct_2xx_paths=20,
                ok_requests=20,
                internal_nav=15,
            )
        )
        == "browsing"
    )


def test_a_session_that_says_nothing_is_left_blank():
    """Two requests, both refused, no paths served, no navigation."""
    assert behaviour_for(_session(requests=2, content_requests=2, refused=2)) == ""


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


def test_the_count_headers_match_the_words_the_rest_of_the_dashboard_uses(client, tmp_db):
    """A fixed-layout table clips cells but not headers, and the first answer to
    that was to shorten the word: "Requests" measured 97px against 89px for its
    neighbours, so the column became "Hits".

    That was the wrong trade. A column width is not a reason to invent a second
    word for something the rest of the dashboard already names — the column is
    `c-num-wide` now and the header says what it counts. The layout suite in
    Docker measures the widths; this is the cheap guard that the vocabulary
    does not drift back.
    """
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0)
    text = client.get("/visitors/203.0.113.1").text
    # Anchored on the title markup, not on the word: "Sessions" also occurs in
    # the Started tooltip, and splitting on it lands in the middle of an
    # attribute.
    head = text.split('table-block-title">Sessions')[1].split("</thead>")[0]
    for label in (">Requests<", ">Paths<", ">Read<", ">Unserved<"):
        assert label in head
    assert ">Hits<" not in head, "a column width is not a reason to invent a word"
    assert ">Not found<" not in head


def test_read_and_unserved_add_up_to_paths(tmp_db):
    """The row has to be readable as arithmetic, or the columns invite doubt.

    An earlier definition counted error paths, which put a path that answered
    only 3xx in neither column and one that answered both 200 and 404 in both.
    51 of 1 568 real sessions did not add up.
    """
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0, "/a", status=200)
        _req(conn, "203.0.113.1", 5, "/b", status=301)
        _req(conn, "203.0.113.1", 10, "/c", status=404)
        _req(conn, "203.0.113.1", 15, "/a", status=500)
    with get_conn(tmp_db) as conn:
        s = get_sessions(conn, "203.0.113.1")[0]
    assert s["unique_paths"] == 3
    assert s["distinct_2xx_paths"] + s["unserved_paths"] == s["unique_paths"]


# ── The drawer ───────────────────────────────────────────────────────────────
#
# The session row is a claim and the drawer is the evidence behind it. What
# makes it possible without storing anything is that a session's own bounds
# select exactly its requests — verified below, and against all 1 568 sessions
# in a week of production.


def _drawer(client, ip, session):
    from urllib.parse import quote

    return client.get(
        f"/visitors/{ip}/session?from={quote(session['started'])}&to={quote(session['ended'])}"
    )


def test_a_session_addresses_its_own_requests(client, tmp_db):
    """No stored id, and none needed: sessions partition an address's timeline."""
    with get_conn(tmp_db) as conn:
        for k in range(3):
            _req(conn, "203.0.113.1", k * 60, f"/first{k}")
        for k in range(4):
            _req(conn, "203.0.113.1", SESSION_GAP_SECONDS * 2 + k * 60, f"/second{k}")
    with get_conn(tmp_db) as conn:
        newest, oldest = get_sessions(conn, "203.0.113.1")
    body = _drawer(client, "203.0.113.1", oldest).text
    assert "/first0" in body and "/first2" in body
    assert "/second0" not in body, "a neighbouring session must not leak in"
    assert "3 requests" in body


def test_the_drawer_keeps_arrival_order(client, tmp_db):
    """In a session the order *is* the information — it is what makes a
    scanner's signature visible, and what the incidents page reads to identify
    a program. Sorting it away would be the one thing this panel must not do."""
    with get_conn(tmp_db) as conn:
        for k, path in enumerate(("/zebra", "/alpha", "/middle")):
            _req(conn, "203.0.113.1", k * 30, path)
    with get_conn(tmp_db) as conn:
        session = get_sessions(conn, "203.0.113.1")[0]
    body = _drawer(client, "203.0.113.1", session).text
    assert body.index("/zebra") < body.index("/alpha") < body.index("/middle")


def test_a_long_session_says_it_is_showing_a_prefix(client, tmp_db):
    """A prefix handed over quietly is a reader drawing conclusions from part
    of the picture without being told."""
    with get_conn(tmp_db) as conn:
        for k in range(140):
            _req(conn, "203.0.113.1", k * 5, f"/p{k}")
    with get_conn(tmp_db) as conn:
        session = get_sessions(conn, "203.0.113.1")[0]
    body = _drawer(client, "203.0.113.1", session).text
    assert "140 requests" in body and "showing the first 100" in body


def test_the_bounds_are_moments_and_not_dates(client, tmp_db):
    """The date window the rest of the dashboard uses rounds its upper bound up
    to the end of that day, deliberately. Reused here it pulled in every later
    session of the same day — 1 043 requests for a session of 514."""
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0, "/morning")
        _req(conn, "203.0.113.1", SESSION_GAP_SECONDS * 2, "/evening")
    with get_conn(tmp_db) as conn:
        _, oldest = get_sessions(conn, "203.0.113.1")
    body = _drawer(client, "203.0.113.1", oldest).text
    assert "/morning" in body and "/evening" not in body


def test_a_window_that_is_not_a_timestamp_is_refused(client, tmp_db):
    """Both bounds reach a comparison against the timestamp column."""
    assert client.get("/visitors/203.0.113.1/session?from=nonsense&to=x").status_code == 400
    assert (
        client.get("/visitors/203.0.113.1/session?from=2026-08-20&to=2026-08-21").status_code
        == 400
    ), "a date is not a session bound"


def test_an_unknown_behaviour_label_is_dropped_rather_than_raised(client, tmp_db):
    """It arrives from the URL and lands in a dict lookup. Anything else is a
    500 for whoever mistypes it; it only labels the panel."""
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0)
        _req(conn, "203.0.113.1", 30)
    with get_conn(tmp_db) as conn:
        session = get_sessions(conn, "203.0.113.1")[0]
    from urllib.parse import quote

    resp = client.get(
        f"/visitors/203.0.113.1/session?from={quote(session['started'])}"
        f"&to={quote(session['ended'])}&behaviour=<script>alert(1)</script>"
    )
    assert resp.status_code == 200
    assert "<script>" not in resp.text


def test_the_row_carries_the_link_to_its_own_drawer(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _req(conn, "203.0.113.1", 0)
        _req(conn, "203.0.113.1", 30)
    body = client.get("/visitors/203.0.113.1").text
    assert 'data-drawer-src="/visitors/203.0.113.1/session?from=' in body
    assert "click a row for its requests" in body
