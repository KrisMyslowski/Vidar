"""Direct tests for the four functions the release-UI rebuild added.

They were covered only through rendered HTML, which is why C3 (range presets
discarding the filter state) shipped: _visitors_url is a pure function and a
single assertion on it would have caught the missing parameters.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.db import get_conn
from src.queries import get_attention_items, get_rate_limit_timeline, insert_visit
from src.routes._range import DEFAULT_RANGE, _resolve_range
from src.routes._urls import _visitors_url

# ── _resolve_range ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("preset,days", [("24h", 1), ("7d", 7), ("30d", 30), ("90d", 90)])
def test_preset_spans_that_many_days_ending_today(preset, days):
    date_from, date_to, active = _resolve_range(preset, None, None)
    today = datetime.now(timezone.utc).date()
    assert date_to == today.isoformat()
    assert date_from == (today - timedelta(days=days - 1)).isoformat()
    assert active == preset


def test_explicit_dates_win_over_a_preset():
    """Both in the URL means the user typed the dates — the preset is stale."""
    date_from, date_to, active = _resolve_range("7d", "2026-01-01", "2026-01-31")
    assert (date_from, date_to) == ("2026-01-01", "2026-01-31")
    assert active == "custom"  # so the Custom disclosure opens on reload


def test_a_single_bound_still_counts_as_custom():
    assert _resolve_range(None, "2026-01-01", None)[2] == "custom"
    assert _resolve_range(None, None, "2026-01-31")[2] == "custom"


@pytest.mark.parametrize("bogus", [None, "", "yesterday", "7", "1y", "24H"])
def test_nothing_usable_means_the_default_window(bogus):
    """There is no "no window" outcome any more.

    Every number on every page is scoped to what this returns, so an empty
    result would be a dashboard claiming a filter it is not applying. Anything
    unrecognised lands on the default rather than silently showing everything.
    """
    date_from, date_to, active = _resolve_range(bogus, None, None)
    today = datetime.now(timezone.utc).date()
    assert active == DEFAULT_RANGE
    assert (date_from, date_to) == ((today - timedelta(days=89)).isoformat(), today.isoformat())


def test_all_is_the_unfiltered_window_and_has_to_be_asked_for():
    """The only way to an unbounded view, and a state the strip shows as active."""
    assert _resolve_range("all", None, None) == (None, None, "all")


def test_the_remembered_window_applies_when_the_url_says_nothing():
    date_from, date_to, active = _resolve_range(None, None, None, "7d")
    today = datetime.now(timezone.utc).date()
    assert active == "7d"
    assert (date_from, date_to) == (
        (today - timedelta(days=6)).isoformat(),
        today.isoformat(),
    )


def test_a_remembered_custom_window_comes_back_whole():
    assert _resolve_range(None, None, None, "custom:2026-01-01:2026-01-31") == (
        "2026-01-01",
        "2026-01-31",
        "custom",
    )


@pytest.mark.parametrize(
    "url_range,url_from,url_to,expected",
    [
        ("24h", None, None, "24h"),
        ("all", None, None, "all"),
        (None, "2026-01-01", "2026-01-31", "custom"),
    ],
)
def test_the_url_beats_the_remembered_window(url_range, url_from, url_to, expected):
    """A shared or bookmarked link has to show the window it names, whatever
    this browser happened to look at last."""
    assert _resolve_range(url_range, url_from, url_to, "30d")[2] == expected


# ── _visitors_url ─────────────────────────────────────────────────────────────


def test_empty_params_give_a_bare_path():
    assert _visitors_url({}) == "/visitors"
    assert _visitors_url({"group": "", "q": None, "class": []}) == "/visitors"


def test_falsy_values_are_omitted_not_serialised():
    """0 and "" mean "not set" for every parameter the page carries."""
    url = _visitors_url({"min_visits": 0, "port": 0, "q": "", "group": "asn"})
    assert url == "/visitors?group=asn"


def test_multi_value_params_keep_every_value():
    url = _visitors_url({"class": ["humans", "bots"], "signal": ["is_tor"]})
    assert url.count("class=") == 2
    assert "class=humans" in url and "class=bots" in url and "signal=is_tor" in url


def test_drop_removes_exactly_one_key():
    params = {"group": "asn", "asn": "AS1", "class": ["bots"]}
    url = _visitors_url(params, drop="asn")
    assert "asn=AS1" not in url
    assert "group=asn" in url and "class=bots" in url


def test_overrides_replace_and_can_clear():
    params = {"group": "asn", "page": "3"}
    assert _visitors_url(params, group="country") == "/visitors?group=country&page=3"
    assert _visitors_url(params, page="") == "/visitors?group=asn"


def test_values_are_percent_encoded():
    """Paths and search terms reach an href — they must not break out of it."""
    url = _visitors_url({"path": "/a b&c=d", "q": "<script>"})
    assert " " not in url and "<" not in url
    assert "%20" in url or "%2520" in url
    assert "&c=d" not in url  # the ampersand belongs to the value, not the URL


# ── get_attention_items ───────────────────────────────────────────────────────


def _visit(conn, ip, **kw):
    kw.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    kw.setdefault("path", "/")
    kw.setdefault("status", 200)
    insert_visit(conn, ip=ip, **kw)


def test_no_data_means_no_findings(tmp_db):
    with get_conn(tmp_db) as conn:
        assert get_attention_items(conn) == []


def test_probe_finding_names_the_path_and_counts_distinct_ips(tmp_db):
    with get_conn(tmp_db) as conn:
        for i in range(4):
            _visit(conn, f"203.0.113.{i}", path="/.env", status=404)
        _visit(conn, "203.0.113.0", path="/.env", status=404)  # same IP again
    with get_conn(tmp_db) as conn:
        probe = next(i for i in get_attention_items(conn) if i["tag"] == "Probe")
    assert "/.env" in probe["text"]
    assert "4 distinct" in probe["text"]  # five requests, four IPs
    assert probe["value"] == 5
    assert probe["href"].startswith("/visitors?group=path")


def test_probe_finding_ignores_traffic_older_than_a_day(tmp_db):
    """A finding is a snapshot; last week's scan is not something to act on."""
    old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    with get_conn(tmp_db) as conn:
        _visit(conn, "203.0.113.1", path="/.env", status=404, timestamp=old)
    with get_conn(tmp_db) as conn:
        assert not [i for i in get_attention_items(conn) if i["tag"] == "Probe"]


def test_rate_limit_finding_reports_events_not_only_rejections(tmp_db):
    with get_conn(tmp_db) as conn:
        for _ in range(3):
            _visit(conn, "203.0.113.9", limit_req_status="DELAYED")
        _visit(conn, "203.0.113.9", limit_req_status="REJECTED")
    with get_conn(tmp_db) as conn:
        rate = next(i for i in get_attention_items(conn) if i["tag"] == "Rate limit")
    assert rate["value"] == 4
    assert "4 rate-limited" in rate["text"] and "1 rejected" in rate["text"]


def test_every_finding_links_somewhere_and_carries_a_colour_key(tmp_db):
    """A finding the user cannot follow is only noise."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "203.0.113.1", path="/.env", status=404)
        _visit(conn, "203.0.113.2", limit_req_status="REJECTED")
    with get_conn(tmp_db) as conn:
        items = get_attention_items(conn)
    assert items
    for item in items:
        assert item["href"].startswith("/")
        assert item["tag"] and item["text"]
        assert item["signal"] in {"threats", "tor", "hosting", "dnsbl"}


# ── get_rate_limit_timeline ───────────────────────────────────────────────────


def test_timeline_splits_days_into_rejected_and_delayed(tmp_db):
    day = "2026-07-01T10:00:00"
    with get_conn(tmp_db) as conn:
        _visit(conn, "203.0.113.1", timestamp=day, limit_req_status="REJECTED")
        _visit(conn, "203.0.113.2", timestamp=day, limit_req_status="DELAYED")
        _visit(conn, "203.0.113.3", timestamp=day, limit_req_status="DELAYED")
        _visit(conn, "203.0.113.4", timestamp=day)  # not rate limited at all
    with get_conn(tmp_db) as conn:
        rows = get_rate_limit_timeline(conn)
    assert len(rows) == 1
    assert rows[0]["day"] == "2026-07-01"
    assert (rows[0]["rejected"], rows[0]["delayed"], rows[0]["total"]) == (1, 2, 3)


def test_timeline_honours_the_date_window(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "203.0.113.1", timestamp="2026-06-01T10:00:00", limit_req_status="REJECTED")
        _visit(conn, "203.0.113.2", timestamp="2026-07-15T10:00:00", limit_req_status="REJECTED")
    with get_conn(tmp_db) as conn:
        rows = get_rate_limit_timeline(conn, since="2026-07-01T00:00:00")
    assert [r["day"] for r in rows] == ["2026-07-15"]


def test_a_backwards_custom_window_is_turned_around():
    """The two date inputs do not constrain each other.

    Left as typed, From-after-To selects nothing and the Overview's delta then
    compares it against a span lying in the future.
    """
    assert _resolve_range(None, "2026-08-07", "2026-08-01") == (
        "2026-08-01",
        "2026-08-07",
        "custom",
    )
