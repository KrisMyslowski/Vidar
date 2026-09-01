"""Addresses that ran the same program at the same time.

The qualitative jump: from a list of visitors to a list of events. Which means
the failure that matters is not missing an event — it is reporting one that is
not there. A security page that cries wolf is read once; the thresholds are all
set on the under-reporting side, and most of what follows checks that they hold.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.db import get_conn
from src.incidents import INCIDENT_GAP_SECONDS, MIN_ADDRESSES, SIGNATURE_PATHS, score, score_parts
from src.queries import get_incident_paths, get_incident_sessions, get_incidents, upsert_ip_intel

BASE = datetime(2026, 8, 20, 3, 12, tzinfo=timezone.utc)
TOOL = ["/.env", "/.git/config", "/wp-login.php", "/admin/", "/phpinfo.php", "/server-status"]


def _probe(conn, ip, paths, offset_s=0, status=404, **intel):
    """One session: `paths` requested in order, three seconds apart."""
    from src.queries import insert_visit

    upsert_ip_intel(conn, {"ip": ip, "asn": intel.get("asn", "AS64496"), **intel})
    for k, path in enumerate(paths):
        insert_visit(
            conn,
            ip=ip,
            timestamp=(BASE + timedelta(seconds=offset_s + k * 3)).isoformat(),
            path=path,
            status=status,
        )


def _campaign(conn, count, paths=None, spread_s=60, **intel):
    for n in range(count):
        _probe(conn, f"203.0.113.{n + 1}", paths or TOOL, offset_s=n * spread_s, **intel)


def test_the_limit_keeps_the_worst_incidents_not_an_arbitrary_handful(tmp_db):
    """The score orders these rows and is computed after the query, so a SQL
    LIMIT cut before the ordering existed and kept whichever rows the plan
    happened to produce. Asking for three returned incidents scoring 44, 39 and
    37 on a real month while the actual top three scored 135, 104 and 101 — a
    page whose purpose is to surface the worst, dropping exactly the worst."""
    with get_conn(tmp_db) as conn:
        # Three programs of increasing reach, so their scores are ordered.
        for n, size in enumerate((MIN_ADDRESSES, MIN_ADDRESSES + 2, MIN_ADDRESSES + 4)):
            paths = [f"/tool{n}/{p}" for p in ("a", "b", "c", "d", "e")]
            for k in range(size):
                _probe(
                    conn,
                    f"198.51.{n}.{k + 1}",
                    paths,
                    offset_s=n * 7200 + k * 60,
                    asn=f"AS{n}00{k}",
                )

    with get_conn(tmp_db) as conn:
        every = get_incidents(conn, limit=100)
        top_one = get_incidents(conn, limit=1)
    assert len(every) == 3
    scores = [i["score"] for i in every]
    assert scores == sorted(scores, reverse=True), scores
    # The limit takes from the top of that order, not from the middle of it.
    assert [i["score"] for i in top_one] == scores[:1]
    assert top_one[0]["digest"] == every[0]["digest"]


# ── When it is an event ──────────────────────────────────────────────────────


def test_the_same_program_from_several_addresses_is_one_event(tmp_db):
    with get_conn(tmp_db) as conn:
        _campaign(conn, MIN_ADDRESSES)
    with get_conn(tmp_db) as conn:
        found = get_incidents(conn)
    assert len(found) == 1
    assert found[0]["addresses"] == MIN_ADDRESSES
    assert found[0]["paths"] == TOOL[:SIGNATURE_PATHS]


def test_the_incident_names_the_addresses_it_is_made_of(tmp_db):
    """A count is a claim; the addresses are what makes it showable."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
    with get_conn(tmp_db) as conn:
        found = get_incidents(conn)
    assert found[0]["members"] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]


def test_the_window_of_the_incident_spans_its_members(tmp_db):
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3, spread_s=120)
    with get_conn(tmp_db) as conn:
        found = get_incidents(conn)
    assert found[0]["started"] < found[0]["ended"]


# ── When it is not ───────────────────────────────────────────────────────────


def test_one_address_short_of_the_threshold_is_not_an_event(tmp_db):
    """Correlation without volume is noise, and "incident" has to mean something."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, MIN_ADDRESSES - 1)
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


def test_the_same_program_a_week_apart_is_not_one_run(tmp_db):
    """Three addresses running one tool in three different weeks is the tool
    being popular, not a campaign.

    A *day* apart is one run, and that is measured rather than assumed: on the
    reference deployment eighteen addresses ran the same five-path probe over a
    week, one or two at a time, and never three within an hour. An hour-wide
    window reported nothing at all there. See INCIDENT_GAP_SECONDS.
    """
    with get_conn(tmp_db) as conn:
        for n in range(3):
            _probe(conn, f"203.0.113.{n + 1}", TOOL, offset_s=n * 7 * 86400)
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


def test_a_campaign_spread_over_days_is_still_one_run(tmp_db):
    """The case an hour-wide window could not see, and the reason it changed."""
    with get_conn(tmp_db) as conn:
        for n in range(4):
            _probe(conn, f"203.0.113.{n + 1}", TOOL, offset_s=n * 20 * 3600)
    with get_conn(tmp_db) as conn:
        found = get_incidents(conn)
    assert len(found) == 1
    assert found[0]["addresses"] == 4


def test_a_gap_just_over_the_incident_window_splits_the_run(tmp_db):
    with get_conn(tmp_db) as conn:
        _probe(conn, "203.0.113.1", TOOL, 0)
        _probe(conn, "203.0.113.2", TOOL, 60)
        _probe(conn, "203.0.113.3", TOOL, INCIDENT_GAP_SECONDS + 120)
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


def test_different_programs_are_not_one_event(tmp_db):
    """Three addresses probing at the same moment for different things is three
    scanners noticing the same site, which is a Tuesday."""
    with get_conn(tmp_db) as conn:
        for n in range(3):
            _probe(conn, f"203.0.113.{n + 1}", [f"/x{n}/{k}.php" for k in range(6)])
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


def test_the_same_paths_in_a_different_order_are_a_different_program(tmp_db):
    """Order is part of the signature: it is what a program's start looks like."""
    with get_conn(tmp_db) as conn:
        _probe(conn, "203.0.113.1", TOOL, 0)
        _probe(conn, "203.0.113.2", TOOL, 60)
        _probe(conn, "203.0.113.3", list(reversed(TOOL)), 120)
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


def test_too_few_paths_to_identify_anything_is_not_a_signature(tmp_db):
    """Three addresses that each asked for /.env once are not a campaign."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 5, paths=TOOL[: SIGNATURE_PATHS - 1])
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


def test_paths_that_exist_are_not_probes(tmp_db):
    """Three crawlers reading the same six pages in the same order is a sitemap."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 5, status=200)
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


def test_convention_files_are_excluded_here_too(tmp_db):
    """robots.txt and /.well-known/ are asked for by everything, so agreeing on
    them is not evidence of anything. Same list as the 404 ratio uses."""
    conventions = [
        "/robots.txt",
        "/.well-known/security.txt",
        "/ads.txt",
        "/llms.txt",
        "/favicon.ico",
        "/sitemap.xml",
    ]
    with get_conn(tmp_db) as conn:
        _campaign(conn, 5, paths=conventions)
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


# ── The window ───────────────────────────────────────────────────────────────


def test_the_date_window_narrows_rather_than_emptying(tmp_db):
    """The window sits in the first of five CTEs while every other parameter sits
    elsewhere. get_exposures bound that arrangement positionally and returned
    nothing under every range while all its tests passed."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
    with get_conn(tmp_db) as conn:
        assert len(get_incidents(conn, "2026-08-01", "2026-08-31")) == 1
        assert get_incidents(conn, "2026-01-01", "2026-01-31") == []


def test_both_forms_of_the_window_say_the_same_thing():
    """This is the only caller of the named form, so the drift lands here.

    Two spellings of one rule is how the rule stops being one — `until` is
    inclusive of its whole day, and if only one form kept the '+1 day' the
    difference would show up as a page quietly missing its most recent day.
    """
    from src.queries._shared import _date_conditions

    positional, values = _date_conditions("2026-08-01", "2026-08-31", "v.timestamp")
    named, bound = _date_conditions("2026-08-01", "2026-08-31", "v.timestamp", named=True)
    assert [c.replace(":since", "?").replace(":until", "?") for c in named] == positional
    assert list(bound.values()) == values
    assert bound == {"since": "2026-08-01", "until": "2026-08-31"}


# ── The sort key ─────────────────────────────────────────────────────────────


def test_the_score_is_the_sum_of_the_parts_it_shows(tmp_db):
    """The page prints the arithmetic. If it does not add up, the page lies."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4, is_hosting=1, dnsbl_listed=1)
    with get_conn(tmp_db) as conn:
        found = get_incidents(conn)[0]
    assert sum(points for _, _, points in score_parts(found)) == found["score"]


def test_volume_alone_cannot_sort_the_page(tmp_db):
    """An address hammering all night is a large number and not an event. The
    probe term is capped so it cannot outweigh how many places took part."""
    small = {"addresses": 3, "asns": 3, "blocklisted": 0, "probe_404": 10}
    huge = {"addresses": 3, "asns": 3, "blocklisted": 0, "probe_404": 5_000_000}
    assert score(huge) - score(small) <= 10


def test_more_addresses_outrank_more_requests():
    spread = {"addresses": 20, "asns": 15, "blocklisted": 0, "probe_404": 100}
    loud = {"addresses": 3, "asns": 1, "blocklisted": 0, "probe_404": 100_000}
    assert score(spread) > score(loud)


def test_incidents_come_back_in_score_order(tmp_db):
    with get_conn(tmp_db) as conn:
        _probe(conn, "198.51.100.1", TOOL, 0)
        _probe(conn, "198.51.100.2", TOOL, 60)
        _probe(conn, "198.51.100.3", TOOL, 120)
        other = ["/actuator/env", "/telescope/requests", "/api/v1/pods", "/config.json", "/x.bak"]
        for n in range(8):
            _probe(conn, f"203.0.113.{n + 1}", other, offset_s=n * 30)
    with get_conn(tmp_db) as conn:
        found = get_incidents(conn)
    assert [i["addresses"] for i in found] == [8, 3]
    assert found[0]["score"] > found[1]["score"]


# ── The page ─────────────────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_db):
    from fastapi.testclient import TestClient

    from src.config import settings
    from src.main import app

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def _row_values(html, col):
    return re.findall(rf'data-col="{col}"[^>]*>\s*([^<\s][^<]*?)\s*<', html)


def test_the_score_is_the_named_default_and_the_column_is_visible(client, tmp_db):
    """It was the ordering already, on a column hidden by default — a list
    ordered by something the reader could neither name nor restore."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4, dnsbl_listed=1)
    text = client.get("/incidents?range=all").text
    # Marked as the active sort, and not among the columns the picker starts off.
    assert 'data-col="score" class="c-num sort-desc"' in text
    assert "{'key': 'score'" not in text
    assert 'data-col="score"' in text


def test_sorting_reorders_the_rows_and_carries_the_window(client, tmp_db):
    """Two runs of different reach, so any ordering is observable."""
    with get_conn(tmp_db) as conn:
        for n, size in enumerate((MIN_ADDRESSES, MIN_ADDRESSES + 3)):
            paths = [f"/prog{n}/{p}" for p in ("a", "b", "c", "d", "e")]
            for k in range(size):
                _probe(
                    conn,
                    f"198.51.{n}.{k + 1}",
                    paths,
                    offset_s=n * 7200 + k * 60,
                    asn=f"AS{n}00{k}",
                )

    high_first = _row_values(client.get("/incidents?range=all").text, "addresses")
    low_first = _row_values(
        client.get("/incidents?range=all&sort=addresses&order=ASC").text, "addresses"
    )
    assert high_first == sorted(high_first, key=int, reverse=True), high_first
    assert low_first == list(reversed(high_first)), low_first
    # A sort link keeps the window, or clicking a header widens the page.
    assert "&amp;range=all" in client.get("/incidents?range=all").text


def test_the_signature_and_the_member_list_are_not_sortable(client, tmp_db):
    """A signature is an *ordered* path list and that order is its identity;
    From is a truncated eight of N. Sorting either offers to throw away the
    thing the column exists to show."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, MIN_ADDRESSES)
    text = client.get("/incidents?range=all").text
    for col in ("signature", "members"):
        header = re.search(rf'<th data-col="{col}"[^>]*>(.*?)</th>', text, re.S)
        assert header, col
        assert "href=" not in header.group(1), col


def test_the_custom_range_form_keeps_the_sort(client, tmp_db):
    """Same rule as Exposure: a GET to the bare path drops what it does not
    carry, and the sort became state on this page when the columns did."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, MIN_ADDRESSES)
    text = client.get("/incidents?range=all&sort=addresses&order=ASC").text
    form = re.search(r"<form[^>]*range-custom-form.*?</form>", text, re.S)
    assert form, "no custom range form"
    hidden = dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', form.group(0)))
    assert hidden == {"sort": "addresses", "order": "ASC"}, hidden


def test_an_unknown_sort_key_falls_back_rather_than_erroring(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _campaign(conn, MIN_ADDRESSES)
    assert client.get("/incidents?range=all&sort=nonsense&order=sideways").status_code == 200


def test_the_page_shows_the_arithmetic_and_not_only_the_number(client, tmp_db):
    """A number whose derivation cannot be opened would put a score where the
    evidence used to be. Every figure in it is a column of the same row, and
    the cell spells the sum out over those figures."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4, dnsbl_listed=1)
    text = client.get("/incidents?range=all").text
    # The header is a sort link now, not a plain span — the column it names is
    # what the list is ordered by, so it can be clicked back to.
    assert ">Score</a>" in text
    assert "4 addresses" in text and "on blocklists" in text
    assert "/.env" in text and "/wp-login.php" in text
    assert 'href="/visitors/203.0.113.1"' in text


def test_the_page_is_a_table_like_every_other_list_here(client, tmp_db):
    """It was a stack of description lists, which read as free text beside the
    rest of the dashboard. A list of things is a table with a column picker."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4)
    text = client.get("/incidents?range=all").text
    assert 'data-table-key="incidents"' in text
    assert 'data-col="signature"' in text and 'data-col="members"' in text
    assert 'class="card-value"' in text  # the tiles every other page opens with


def test_an_empty_page_says_why_it_is_empty(client, tmp_db):
    """On a small site this is the usual result, and an empty page with no words
    cannot be told from a broken one."""
    with get_conn(tmp_db) as conn:
        _probe(conn, "203.0.113.1", TOOL)
    text = client.get("/incidents?range=all").text
    assert "No incidents recorded yet" in text


# ── The panel ────────────────────────────────────────────────────────────────
#
# The row says eighteen addresses ran one program; the panel says which, when
# each joined, and how long each stayed. An incident has no stored id and needs
# none — its signature and its stretch of time name it, the same way a session
# is named by its bounds.


def _panel(conn, incident):
    """The sessions behind one incident. The signature comes back with them —
    only that query knows what the digest names — and the callers that need it
    ask for it directly."""
    _, sessions = get_incident_sessions(
        conn, incident["started"], incident["ended"], incident["digest"]
    )
    return sessions


def test_the_panel_lists_exactly_the_addresses_the_row_counts(tmp_db):
    """A row that says eighteen and a panel that lists seventeen is a page
    nobody trusts again."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 5)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
        rows = _panel(conn, incident)
    assert {r["ip"] for r in rows} == {f"203.0.113.{n + 1}" for n in range(5)}
    assert len(rows) == incident["addresses"]
    assert sum(r["probe_404"] for r in rows) == incident["probe_404"]


def test_another_program_in_the_same_window_is_not_in_the_panel(tmp_db):
    """The window alone does not name an incident — the signature does."""
    other = ["/xiugai.php", "/like.php", "/cns.php", "/ans.php", "/nwflm.php", "/x.php"]
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
        for n in range(3):
            _probe(conn, f"198.51.100.{n + 1}", other, offset_s=n * 60)
    with get_conn(tmp_db) as conn:
        for incident in get_incidents(conn):
            ips = {r["ip"] for r in _panel(conn, incident)}
            assert len({ip.rsplit(".", 2)[0] for ip in ips}) == 1, ips


def test_a_run_that_began_before_the_incident_is_not_part_of_it(tmp_db):
    """This is what the backwards padding is for.

    Session boundaries are found by looking for silence before a request. Cut
    the visits at the incident's first moment and the first surviving request of
    an address that was already busy looks like a fresh start — so a run that
    began before the incident would be split at the cut and its tail could carry
    the signature. Padding by one session gap puts that silence, or the lack of
    it, inside the window.
    """
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3, spread_s=60)
        # A fourth address already running ten minutes earlier, continuously,
        # whose later requests are the same five paths.
        _probe(conn, "198.51.100.9", ["/warmup1", "/warmup2"], offset_s=-600)
        _probe(conn, "198.51.100.9", TOOL, offset_s=0)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
        ips = {r["ip"] for r in _panel(conn, incident)}
    assert "198.51.100.9" not in ips, "its run started before the incident did"


def test_the_digest_names_the_signature_and_nothing_else(tmp_db):
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
        assert len(incident["digest"]) == 16
        assert _panel(conn, incident)
        wrong = {**incident, "digest": "0" * 16}
        assert _panel(conn, wrong) == []


def test_the_row_carries_the_link_to_its_own_panel(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
    body = client.get("/incidents?range=all").text
    assert 'data-drawer-src="/incidents/case?from=' in body
    assert "click a row for the sessions behind it" in body


def test_the_panel_renders_each_address_as_a_link(client, tmp_db):
    """The chain has to keep going: from the event to an address, and from
    there to the session that put it in the event."""
    from urllib.parse import quote

    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
    body = client.get(
        f"/incidents/case?from={quote(incident['started'])}"
        f"&to={quote(incident['ended'])}&sig={incident['digest']}"
    ).text
    assert 'href="/visitors/203.0.113.1"' in body
    assert "3 addresses" in body


def test_a_bound_or_a_digest_that_is_not_one_is_refused(client, tmp_db):
    good = "2026-08-20T03:12:00%2B00:00"
    assert client.get(f"/incidents/case?from=nope&to={good}&sig={'a' * 16}").status_code == 400
    assert client.get(f"/incidents/case?from={good}&to={good}&sig=nope").status_code == 400
    assert client.get(f"/incidents/case?from={good}&to={good}&sig=<script>").status_code == 400


def test_the_panel_says_what_the_incident_asked_for(tmp_db):
    """Without the paths the panel is a list of addresses and says nothing
    about what happened. The incident *is* "these addresses asked for these
    paths"; half of that is not an event."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
        signature, _ = get_incident_sessions(
            conn, incident["started"], incident["ended"], incident["digest"]
        )
        paths = get_incident_paths(conn, incident["started"], incident["ended"], signature)
    assert [p["path"] for p in paths] == TOOL
    assert all(p["addresses"] == 4 for p in paths)


def test_the_paths_add_up_to_the_number_on_the_row(tmp_db):
    """Two totals describing one event is how a page stops being believed.

    Which is why this counts only what the incident is built from — requests
    for something that does not exist — and not every request the member
    sessions happened to make.
    """
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4)
        # The same addresses also fetch a page that exists, in the same run.
        for n in range(4):
            _probe(conn, f"203.0.113.{n + 1}", ["/"], offset_s=n * 60 + 30, status=200)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
        signature, _ = get_incident_sessions(
            conn, incident["started"], incident["ended"], incident["digest"]
        )
        paths = get_incident_paths(conn, incident["started"], incident["ended"], signature)
    assert sum(p["requests"] for p in paths) == incident["probe_404"]
    assert "/" not in [p["path"] for p in paths]


def test_the_signature_is_marked_and_comes_first(tmp_db):
    """The list is in the order the paths arrived, which is the order the
    program walks them — so the five that identify it lead."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
        signature, _ = get_incident_sessions(
            conn, incident["started"], incident["ended"], incident["digest"]
        )
        paths = get_incident_paths(conn, incident["started"], incident["ended"], signature)
    marked = [i for i, p in enumerate(paths) if p["in_signature"]]
    assert marked == [0, 1, 2, 3, 4]
    assert [p["path"] for p in paths[:5]] == TOOL[:SIGNATURE_PATHS]


def test_a_path_only_some_of_them_tried_is_counted_as_such(tmp_db):
    """Where the runs diverged is information: a path all of them tried is the
    program, one a few tried is where it stopped being the same."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4)
        _probe(conn, "203.0.113.1", ["/only-one-tried.php"], offset_s=20)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
        signature, _ = get_incident_sessions(
            conn, incident["started"], incident["ended"], incident["digest"]
        )
        paths = {
            p["path"]: p
            for p in get_incident_paths(conn, incident["started"], incident["ended"], signature)
        }
    assert paths["/only-one-tried.php"]["addresses"] == 1
    assert paths[TOOL[0]]["addresses"] == 4


def test_the_panel_renders_both_tables(client, tmp_db):
    from urllib.parse import quote

    with get_conn(tmp_db) as conn:
        _campaign(conn, 3)
    with get_conn(tmp_db) as conn:
        incident = get_incidents(conn)[0]
    body = client.get(
        f"/incidents/case?from={quote(incident['started'])}"
        f"&to={quote(incident['ended'])}&sig={incident['digest']}"
    ).text
    assert "Asked for" in body and ">From<" in body
    assert "/wp-login.php" in body, "the paths it probed"
    assert 'href="/visitors/203.0.113.1"' in body, "and who probed them"
    assert "3 addresses" in body and "paths" in body


# ── The panel's own sorting and paging ───────────────────────────────────────
#
# The panel is 736px wide and a campaign here asks for 266 distinct paths, so
# both had to exist before it could show what it holds. What is checked below is
# the part that is easy to get wrong and impossible to see: that paging reaches
# every path exactly once, that re-ordering does not cost the arrival order the
# signature is made of, and that the two tables do not move each other.


def _case_url(incident, **params):
    from urllib.parse import quote, urlencode

    url = (
        f"/incidents/case?from={quote(incident['started'])}"
        f"&to={quote(incident['ended'])}&sig={incident['digest']}"
    )
    return f"{url}&{urlencode(params)}" if params else url


def _paths_shown(body):
    """The (position, path) pairs of the panel's first table, in render order."""
    rows = re.findall(
        r'<td data-label="#" class="num">\s*(\d+).*?'
        r'<td data-label="Path" class="col-path"><code>(.*?)</code>',
        body,
        re.S,
    )
    return [(int(pos), path) for pos, path in rows]


@pytest.fixture
def _long_campaign(tmp_db):
    """A run long enough to page: 90 paths across the four addresses."""
    paths = TOOL + [f"/wp-content/plugins/p{n}/readme.txt" for n in range(84)]
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4, paths=paths, spread_s=600)
    with get_conn(tmp_db) as conn:
        return get_incidents(conn)[0], paths


def test_paging_the_panel_reaches_every_path_exactly_once(client, _long_campaign):
    """The list used to stop at forty with a line saying so, which put the tail
    of the longest runs out of reach entirely."""
    incident, paths = _long_campaign
    seen, page = [], 1
    while True:
        body = client.get(_case_url(incident, page=page)).text
        seen += [p for _, p in _paths_shown(body)]
        if f"page={page + 1}&" not in body:
            break
        page += 1
    assert page > 1, "90 paths at 40 a page is more than one page"
    assert seen == paths, "in arrival order, all of them, none twice"


def test_the_position_column_survives_a_re_sort(client, _long_campaign):
    """Why this table may be sorted where the page's Signature column may not:
    the order the paths arrived is written into the row, so re-ordering the
    rows moves it along instead of destroying it."""
    incident, paths = _long_campaign
    arrival = {path: n for n, path in enumerate(paths, 1)}
    shown = _paths_shown(client.get(_case_url(incident, sort="path", order="ASC")).text)

    assert [p for _, p in shown] == sorted(p for _, p in shown), "sorted by path"
    assert [pos for pos, _ in shown] != list(range(1, len(shown) + 1)), (
        "and the numbering is no longer 1..n — it would be if the column were "
        "the loop counter, which is exactly the bug this guards"
    )
    assert all(pos == arrival[path] for pos, path in shown)


def test_the_two_tables_do_not_move_each_other(client, _long_campaign):
    """They share a URL, so they need separate parameters: sorting the addresses
    must not throw the reader back to page one of the paths."""
    incident, _ = _long_campaign
    body = client.get(
        _case_url(incident, page=2, sort="path", order="ASC", ssort="probes", sorder="DESC")
    ).text
    shown = _paths_shown(body)

    assert shown, "still on page 2 of the paths"
    assert [p for _, p in shown] == sorted(p for _, p in shown), "still sorted by path"
    probes = [int(n) for n in re.findall(r'data-label="Probes" class="num">(\d+)', body)]
    assert probes == sorted(probes, reverse=True), "and the addresses took their own order"


def test_the_header_counts_the_whole_incident_not_the_page(client, _long_campaign):
    """The three figures in the header are what the row on the page states. A
    panel showing forty of ninety paths still happened ninety paths' worth, and
    the probe total still sums every address rather than the ones on screen."""
    incident, paths = _long_campaign

    def _header(**params):
        body = client.get(_case_url(incident, **params)).text
        return " ".join(
            re.search(r'class="table-block-count">(.*?)</span>', body, re.S).group(1).split()
        )

    heads = {
        _header(),
        _header(page=2),
        _header(sort="requests", order="DESC"),
        _header(ssort="probes", sorder="DESC"),
    }
    assert len(heads) == 1, "the same three figures on every page and every order"
    assert f"{len(paths)} paths" in heads.pop()


def test_a_sort_or_page_the_panel_does_not_have_falls_back(client, _long_campaign):
    """A hand-edited URL is a 200 with the default order, the way every other
    surface here treats one — not a 500 behind a drawer that only says
    "Could not load this"."""
    incident, paths = _long_campaign
    for bad in ({"sort": "; DROP"}, {"ssort": "nope"}, {"order": "sideways"}, {"page": 900}):
        r = client.get(_case_url(incident, **bad))
        assert r.status_code == 200, bad
        assert _paths_shown(r.text), bad


def test_the_panel_links_back_at_its_own_route(client, _long_campaign):
    """Sort and pager links inside the drawer address the fragment, not the page
    behind it — drawer.js re-fetches on exactly the ones that do.

    Read as the browser reads them: the tail comes through the macro as a
    variable, so its separators are written &amp; the way an attribute encodes a
    literal ampersand, and are an ampersand again by the time anything follows
    the link."""
    from html import unescape
    from urllib.parse import parse_qs, urlparse

    incident, _ = _long_campaign
    body = client.get(_case_url(incident)).text
    hrefs = [unescape(h) for h in re.findall(r'<th[^>]*><a[^>]*href="([^"]+)"', body)]
    assert len(hrefs) == 9, "four path columns, five address columns, Signals not sortable"

    for href in hrefs:
        parsed = urlparse(href)
        assert parsed.path == "/incidents/case", href
        q = parse_qs(parsed.query)
        assert q["sig"] == [incident["digest"]], "every link carries the incident it belongs to"
        assert q["from"] == [incident["started"]] and q["to"] == [incident["ended"]]


def test_each_panel_table_can_scroll_sideways(client, _long_campaign):
    """The addresses table is 768px of fixed columns in a 736px panel. Without a
    container of its own it hung past the edge and the whole drawer scrolled
    instead — heading, labels and pager with it."""
    incident, _ = _long_campaign
    body = client.get(_case_url(incident)).text
    assert body.count('<div class="drawer-scroll">') == 2
    assert body.count("<table") == 2
