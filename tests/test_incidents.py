"""Addresses that ran the same program at the same time.

The qualitative jump: from a list of visitors to a list of events. Which means
the failure that matters is not missing an event — it is reporting one that is
not there. A security page that cries wolf is read once; the thresholds are all
set on the under-reporting side, and most of what follows checks that they hold.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.db import get_conn
from src.incidents import INCIDENT_GAP_SECONDS, MIN_ADDRESSES, SIGNATURE_PATHS, score, score_parts
from src.queries import get_incidents, upsert_ip_intel

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


def test_the_same_program_a_day_apart_is_not_one_run(tmp_db):
    """Three addresses running one tool on three different days is the tool being
    popular. Each day is its own cluster, and each is below the threshold."""
    with get_conn(tmp_db) as conn:
        for n in range(3):
            _probe(conn, f"203.0.113.{n + 1}", TOOL, offset_s=n * 86400)
    with get_conn(tmp_db) as conn:
        assert get_incidents(conn) == []


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


def test_the_page_shows_the_arithmetic_and_not_only_the_number(client, tmp_db):
    """A number whose derivation cannot be opened would put a score where the
    evidence used to be. Every figure in it is a column of the same row, and
    the cell spells the sum out over those figures."""
    with get_conn(tmp_db) as conn:
        _campaign(conn, 4, dnsbl_listed=1)
    text = client.get("/incidents?range=all").text
    assert ">Score</span>" in text
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
