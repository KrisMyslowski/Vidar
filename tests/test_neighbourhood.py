"""What Vidar already knows about the addresses next to this one.

The cold start: a verdict needs history and a first request has none. Its
neighbours have been judged though, and nothing new has to be fetched to ask
them — this is `ip_intel` read by range and by operator.

Most of what can go wrong here is a bar that reads as evidence without being
one, so the tests are largely about what is *not* reported: a scope with no
peers, a plurality mistaken for a character, the address counting itself.
"""

from __future__ import annotations

import pytest

from src.db import get_conn, network_of
from src.queries import get_neighbourhood, set_visitor_class, upsert_ip_intel


def _seen(conn, ip, cls="bots/vulnerability-probers", asn="AS64496", org="Example"):
    from src.queries import insert_visit

    upsert_ip_intel(conn, {"ip": ip, "asn": asn, "org": org})
    set_visitor_class(conn, ip, cls)
    insert_visit(conn, ip=ip, timestamp="2026-08-20T10:00:00+00:00", path="/", status=200)


def _scope(result, name):
    return next((s for s in result if s["scope"] == name), None)


# ── The key itself ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("203.0.113.42", "203.0.113.0/24"),
        ("203.0.113.0", "203.0.113.0/24"),
        ("198.51.100.255", "198.51.100.0/24"),
        ("2001:db8::1", "2001:db8::/64"),
    ],
)
def test_the_key_is_the_range_the_family_is_handed_out_in(ip, expected):
    assert network_of(ip) == expected


def test_two_spellings_of_one_address_give_one_key():
    """nginx logs whichever form the client presented.

    This is why the key is parsed rather than cut off the stored string: a LIKE
    would put `2001:db8::99` and `2001:0db8:0:0:0:0:0:99` in different
    neighbourhoods, and they are the same address.
    """
    assert network_of("2001:db8::99") == network_of("2001:0db8:0:0:0:0:0:99")


@pytest.mark.parametrize(
    "value", ["", None, "nonsense", "203.0.113.999", "::/0", 5, 3.5, b"\x01\x02\x03\x04"]
)
def test_something_that_is_not_an_address_has_no_neighbourhood(value):
    """None, so a malformed value groups with nothing rather than with itself.

    The int and the bytes are not hypothetical shapes. `ip_address` accepts
    both as valid addresses — 5 is 0.0.0.5 — so they pass the parse and fail on
    the string form used to build the network. Raising there raises out of a
    SQL function, which fails the whole query rather than one row.
    """
    assert network_of(value) is None


def test_the_key_is_available_to_sql(tmp_db):
    with get_conn(tmp_db) as conn:
        row = conn.execute("SELECT net('203.0.113.7'), net('bogus')").fetchone()
    assert row[0] == "203.0.113.0/24"
    assert row[1] is None


# ── The neighbourhood ────────────────────────────────────────────────────────


def test_peers_in_the_same_range_are_counted(tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1")
        _seen(conn, "203.0.113.2")
        _seen(conn, "203.0.113.3")
    with get_conn(tmp_db) as conn:
        network = _scope(get_neighbourhood(conn, "203.0.113.1"), "network")
    assert network["label"] == "203.0.113.0/24"
    assert network["unique_ips"] == 2


def test_the_address_does_not_count_itself(tmp_db):
    """One address alone is not a neighbourhood, and must not look like one."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1")
    with get_conn(tmp_db) as conn:
        assert _scope(get_neighbourhood(conn, "203.0.113.1"), "network") is None


def test_a_different_range_is_a_different_neighbourhood(tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1")
        _seen(conn, "198.51.100.1", asn="AS64497")
    with get_conn(tmp_db) as conn:
        assert _scope(get_neighbourhood(conn, "203.0.113.1"), "network") is None


def test_the_operator_reaches_across_ranges(tmp_db):
    """The two scopes answer different questions, which is why there are two."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1")
        _seen(conn, "198.51.100.1")  # same ASN, other /24
    with get_conn(tmp_db) as conn:
        result = get_neighbourhood(conn, "203.0.113.1")
    assert _scope(result, "network") is None
    assert _scope(result, "asn")["unique_ips"] == 1


def test_an_address_with_no_asn_gets_no_asn_scope(tmp_db):
    """Unenriched is a normal state, not a neighbourhood of everything blank."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", asn="")
        _seen(conn, "203.0.113.2", asn="")
    with get_conn(tmp_db) as conn:
        result = get_neighbourhood(conn, "203.0.113.1")
    assert _scope(result, "asn") is None
    assert _scope(result, "network")["unique_ips"] == 1


def test_an_empty_neighbourhood_is_absent_rather_than_zero(tmp_db):
    """A bar over nothing reads as evidence. There is none, so there is no bar."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1")
    with get_conn(tmp_db) as conn:
        assert get_neighbourhood(conn, "203.0.113.1") == []


def test_an_unknown_address_asks_and_gets_nothing(tmp_db):
    """The detail route rejects unknown IPs, but the query must not raise."""
    with get_conn(tmp_db) as conn:
        assert get_neighbourhood(conn, "203.0.113.9") == []


# ── The one sentence ─────────────────────────────────────────────────────────


def test_a_majority_is_named(tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", cls="humans/browser-direct")
        for octet in range(2, 8):
            _seen(conn, f"203.0.113.{octet}")
    with get_conn(tmp_db) as conn:
        network = _scope(get_neighbourhood(conn, "203.0.113.1"), "network")
    assert (network["dominant_group"], network["dominant_ips"]) == ("bots", 6)


def test_a_majority_of_two_is_not_a_majority_of_anything(tmp_db):
    """ "1 of 1 are Bots" reached the page — one data point in the grammar of a
    finding. The share alone cannot catch that; the peer count has to.

    The bar and the count still render. They show how thin the evidence is,
    which is the honest version of the same information.
    """
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", cls="humans/browser-direct")
        _seen(conn, "203.0.113.2")
    with get_conn(tmp_db) as conn:
        network = _scope(get_neighbourhood(conn, "203.0.113.1"), "network")
    assert network["unique_ips"] == 1
    assert network["bots_ips"] == 1
    assert network["dominant_group"] == ""


def test_an_even_split_names_nothing(tmp_db):
    """Half is not a majority. The bar shows the split; no sentence claims one."""
    with get_conn(tmp_db) as conn:
        # The subject is excluded from its own peers, so the split has to be
        # even among the other four — not among all five.
        _seen(conn, "203.0.113.1", cls="humans/browser-direct")
        _seen(conn, "203.0.113.2", cls="humans/browser-direct")
        _seen(conn, "203.0.113.3", cls="humans/browser-direct")
        _seen(conn, "203.0.113.4")
        _seen(conn, "203.0.113.5")
    with get_conn(tmp_db) as conn:
        network = _scope(get_neighbourhood(conn, "203.0.113.1"), "network")
    assert network["unique_ips"] == 4
    assert (network["humans_ips"], network["bots_ips"]) == (2, 2)
    assert network["dominant_group"] == ""


def test_a_plurality_is_not_a_character(tmp_db):
    """Four groups, the largest at 40%: nothing here characterises the range."""
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", cls="humans/browser-direct")
        _seen(conn, "203.0.113.2", cls="bots/scanning-tools")
        _seen(conn, "203.0.113.3", cls="bots/scanning-tools")
        _seen(conn, "203.0.113.4", cls="threats/exploit-probers")
        _seen(conn, "203.0.113.5", cls="automated/http-clients")
        _seen(conn, "203.0.113.6", cls="unknown")
    with get_conn(tmp_db) as conn:
        network = _scope(get_neighbourhood(conn, "203.0.113.1"), "network")
    assert network["dominant_group"] == ""


# ── The panel ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_db):
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from src.config import settings
    from src.main import app

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def test_the_panel_names_the_range_and_the_operator(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", cls="humans/browser-direct")
        for octet in range(2, 8):
            _seen(conn, f"203.0.113.{octet}")
    text = client.get("/visitors/203.0.113.1").text
    assert "Neighbourhood" in text
    assert "203.0.113.0/24" in text
    assert "6 of 6 are Bots" in text
    # The operator is a filter that already exists, so the row is a way in.
    assert 'href="/visitors?asn=AS64496"' in text


def test_the_panel_says_so_when_there_is_nothing_yet(client, tmp_db):
    """Empty is the normal state of a new deployment and has to read as one.

    An empty panel with no words is indistinguishable from a broken one, and
    this is the feature most likely to be met empty — it needs history it does
    not have on day one.
    """
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", asn="")
    text = client.get("/visitors/203.0.113.1").text
    assert "No neighbouring addresss recorded yet" in text


def test_no_sentence_where_there_is_no_majority(client, tmp_db):
    with get_conn(tmp_db) as conn:
        _seen(conn, "203.0.113.1", cls="humans/browser-direct")
        _seen(conn, "203.0.113.2", cls="humans/browser-direct")
        _seen(conn, "203.0.113.3", cls="humans/browser-direct")
        _seen(conn, "203.0.113.4")
        _seen(conn, "203.0.113.5")
    text = client.get("/visitors/203.0.113.1").text
    assert "203.0.113.0/24" in text
    assert " are Humans" not in text and " are Bots" not in text
