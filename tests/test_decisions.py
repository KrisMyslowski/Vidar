"""What somebody needs in order to decide, and nothing that decides for them.

The line this feature is not allowed to cross runs through every test here.
Vidar exports; something else acts. Which means the selection has to travel
with the answer, every address has to carry its reason, and nothing may be
ranked by a number a reader cannot open.

A feed whose membership rule is invisible is a blocklist, and a blocklist
nobody can review is the thing the rest of this dashboard argues against.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.db import get_conn
from src.queries import DEFAULT_GROUPS, upsert_ip_intel
from src.queries.decisions import get_decisions, valid_selection

RECENT = datetime.now(timezone.utc) - timedelta(days=1)
OLD = datetime.now(timezone.utc) - timedelta(days=60)


def _seen(conn, ip, cls, when=RECENT, path="/x.php", status=404, **intel):
    from src.queries import insert_visit, set_visitor_class

    upsert_ip_intel(conn, {"ip": ip, **intel})
    set_visitor_class(conn, ip, cls)
    insert_visit(conn, ip=ip, timestamp=when.isoformat(), path=path, status=status)


# ── The selection ────────────────────────────────────────────────────────────


def test_a_group_selects_its_classes(tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers")
        _seen(conn, "203.0.113.2", "humans/browser-direct", status=200)
    with get_conn(tmp_db) as conn:
        assert [r["ip"] for r in get_decisions(conn, groups=("threats",))] == ["203.0.113.1"]


def test_a_class_selects_only_itself(tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers")
        _seen(conn, "203.0.113.2", "threats/protocol-abusers")
    with get_conn(tmp_db) as conn:
        rows = get_decisions(conn, classes=("threats/exploit-probers",))
    assert [r["ip"] for r in rows] == ["203.0.113.1"]


def test_no_selection_selects_nothing(tmp_db):
    """The empty selection must be empty, not everything. A feed that widens
    when its criteria go missing is the one dangerous failure mode here."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers")
    with get_conn(tmp_db) as conn:
        assert get_decisions(conn) == []


def test_an_unknown_name_is_dropped_rather_than_matched(tmp_db):
    """Silently, because an unknown name selects nothing anyway — keeping it
    could only ever widen the feed by accident. The response reports what it
    used, so a typo shows up as a selection that does not say what was asked."""
    assert valid_selection(("threats/made-up",), ("nonsense", "threats")) == ((), ("threats",))


def test_the_window_narrows_the_feed(tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers", when=RECENT)
        _seen(conn, "203.0.113.2", "threats/exploit-probers", when=OLD)
    with get_conn(tmp_db) as conn:
        recent = get_decisions(
            conn,
            groups=("threats",),
            since=(datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d"),
        )
    assert [r["ip"] for r in recent] == ["203.0.113.1"]


# ── The evidence ─────────────────────────────────────────────────────────────


def test_every_address_carries_its_reason(tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers", is_hosting=1, dnsbl_listed=1)
    with get_conn(tmp_db) as conn:
        row = get_decisions(conn, groups=("threats",))[0]
    assert row["visitor_class"] == "threats/exploit-probers"
    assert row["probes"] == 1 and row["requests"] == 1
    assert row["hosting"] == 1 and row["blocklisted"] == 1
    assert row["first_seen"] and row["last_seen"]


def test_nothing_is_ranked_by_a_number_a_reader_cannot_open(tmp_db):
    """Ordered by what the address did here — probes, then requests. A score
    would collapse the evidence into a rank that has to be trusted."""
    with get_conn(tmp_db) as conn:
        for n, probes in ((1, 1), (2, 5), (3, 3)):
            for k in range(probes):
                _seen(conn, f"203.0.113.{n}", "threats/exploit-probers", path=f"/p{k}.php")
    with get_conn(tmp_db) as conn:
        rows = get_decisions(conn, groups=("threats",))
    assert [r["probes"] for r in rows] == [5, 3, 1]
    assert all("score" not in r for r in rows)


# ── The feed ─────────────────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_db):
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from src.config import settings
    from src.main import app

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def test_the_default_is_a_recommendation_and_says_so(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers")
    body = client.get("/api/decisions").text
    assert "does not decide what is blocked" in body
    assert f"Selection: {DEFAULT_GROUPS[0]}/* (the recommended default)" in body
    assert "203.0.113.1" in body


def test_the_selection_travels_with_the_answer(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "bots/vulnerability-probers")
    body = client.get("/api/decisions?group=bots").text
    assert "Selection: bots/*" in body
    assert "recommended default" not in body


def test_a_line_is_an_address_then_a_comment(client, tmp_db):
    """The Spamhaus/CrowdSec convention: consumers strip after the #, and a
    person reading the same file still sees why the address is in it."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers", is_tor=1)
    body = client.get("/api/decisions").text
    line = next(ln for ln in body.splitlines() if not ln.startswith("#"))
    address, _, reason = line.partition("#")
    assert address.strip() == "203.0.113.1"
    assert "threats/exploit-probers" in reason and "Tor exit" in reason


def test_counts_in_the_reason_read_as_english(client, tmp_db):
    """The line is read by people as well as parsed, so "1 probes" is a bug."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers")
    body = client.get("/api/decisions").text
    assert "1 probe ·" in body and "1 probes" not in body
    assert "1 request" in body and "1 requests" not in body


def test_the_json_form_carries_the_same_selection(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", "threats/exploit-probers")
    data = client.get("/api/decisions?format=json&group=threats").json()
    assert data["selection"]["groups"] == ["threats"]
    assert data["selection"]["recommended_default"] is False
    assert data["count"] == 1
    assert data["addresses"][0]["ip"] == "203.0.113.1"


def test_an_empty_feed_still_states_its_selection(client, tmp_db):
    """Zero addresses is an answer, and it has to say which question it answered."""
    body = client.get("/api/decisions?group=threats").text
    assert "Selection: threats/*" in body
    assert "Addresses: 0" in body


def test_a_capped_answer_says_it_was_capped(client, tmp_db, monkeypatch):
    """A prefix delivered quietly is worse than a short answer: the caller
    cannot tell it is acting on part of the picture."""
    import src.routes.api as api

    monkeypatch.setattr(api, "MAX_ADDRESSES", 2)
    with get_conn(tmp_db) as conn:
        for n in range(3):
            _seen(conn, f"203.0.113.{n + 1}", "threats/exploit-probers")
    body = client.get("/api/decisions").text
    assert "capped at 2" in body and "narrow the selection" in body
    assert len([ln for ln in body.splitlines() if not ln.startswith("#")]) == 2


def test_the_api_page_carries_the_sentence_about_who_decides(client, tmp_db):
    """It belongs next to the endpoint, not in a tooltip: this is the one
    endpoint whose reader may then act on what it says."""
    body = client.get("/settings/api").text
    assert "/api/decisions" in body
    assert "Vidar does not decide what is blocked" in body
