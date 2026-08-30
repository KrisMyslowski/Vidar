"""What an ordinary hour holds, so an unusual one can be recognised.

The operator has to go and look; a baseline is what lets Vidar say *when*. Most
of these tests are about the two ways a baseline lies.

It lies by using a mean, which is raised by exactly the thing it is meant to
detect — one busy day sets a bar the next spike sits under, and the finding goes
quiet precisely when something is happening repeatedly. That is not
hypothetical: the Tor finding did it, and the case is below.

And it lies by dropping the hours with no traffic. Those are absent from the
table, not from the week, and leaving them out makes a site that is busy for two
hours a day look as though two busy hours is its normal.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.db import get_conn
from src.queries import get_attention_items, upsert_ip_intel
from src.queries.baseline import (
    MIN_ABSOLUTE,
    MIN_BASELINE_DAYS,
    _median_with_zeros,
    get_hourly_baseline,
    get_typical_hour,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _hit(conn, ip, when, path="/", status=200, tor=False, seq=0):
    from src.queries import insert_visit

    upsert_ip_intel(conn, {"ip": ip, "is_tor": 1 if tor else 0})
    insert_visit(
        conn,
        ip=ip,
        timestamp=when.isoformat(),
        path=path,
        status=status,
        connection=abs(hash((ip, when.isoformat(), path, seq))) % 2_000_000_000,
    )


def _steady(conn, hours, per_hour, probers=1, end=NOW):
    """`hours` hours of even traffic ending just before `end`."""
    for h in range(hours, 0, -1):
        hour = end - timedelta(hours=h)
        for k in range(per_hour):
            _hit(conn, f"198.51.100.{k % 250}", hour + timedelta(minutes=k % 59), seq=k)
        for k in range(probers):
            _hit(
                conn,
                f"203.0.113.{k % 250}",
                hour + timedelta(seconds=k),
                path=f"/.env{k}",
                status=404,
                seq=1000 + k,
            )


# ── The median itself ────────────────────────────────────────────────────────


def test_an_empty_hour_counts_as_an_empty_hour():
    """Three busy hours in a day do not make the typical hour busy."""
    assert _median_with_zeros([100, 120, 110], 24) == 0.0
    assert _median_with_zeros([100, 120, 110], 3) == 110.0


def test_the_median_is_not_moved_by_one_spike():
    """The whole reason it is a median. The mean of these is 118; the median 10.

    A mean has the wrong failure mode for a spike detector: today's spike sets
    tomorrow's bar, so the second one in a row is never reported.
    """
    days = [10, 10, 10, 10, 10, 10, 760]
    assert _median_with_zeros(days, 7) == 10.0
    assert sum(days) / len(days) > 100


def test_an_even_number_of_slots_takes_the_middle_pair():
    assert _median_with_zeros([10, 20, 30, 40], 4) == 25.0


def test_nothing_at_all_is_zero_and_not_an_error():
    assert _median_with_zeros([], 0) == 0.0
    assert _median_with_zeros([], 24) == 0.0


# ── The hourly baseline ──────────────────────────────────────────────────────


def test_a_short_log_has_no_baseline(tmp_db):
    """Under a fortnight there is nothing to be typical about, and a comparison
    against noise is worse than silence — it has the shape of evidence."""
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=48, per_hour=20)
    with get_conn(tmp_db) as conn:
        base = get_hourly_baseline(conn, now=NOW)
    assert base["enough_history"] is False
    assert base["days"] < MIN_BASELINE_DAYS


def test_an_empty_database_has_no_baseline(tmp_db):
    with get_conn(tmp_db) as conn:
        assert get_hourly_baseline(conn, now=NOW)["enough_history"] is False


def test_a_quiet_hour_is_not_unusual(tmp_db):
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=20 * 24, per_hour=20)
    with get_conn(tmp_db) as conn:
        base = get_hourly_baseline(conn, now=NOW)
    assert base["enough_history"] is True
    assert base["requests"]["typical"] == 21.0  # 20 pages plus one probe
    assert base["requests"]["unusual"] is False


def test_a_burst_in_the_last_complete_hour_is_unusual(tmp_db):
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=20 * 24, per_hour=20)
        burst = NOW - timedelta(hours=1)
        for k in range(200):
            _hit(conn, f"10.0.0.{k % 250}", burst + timedelta(seconds=k), seq=k)
    with get_conn(tmp_db) as conn:
        base = get_hourly_baseline(conn, now=NOW)
    assert base["requests"]["unusual"] is True
    assert base["requests"]["factor"] > 3


def test_the_hour_still_filling_is_not_the_one_compared(tmp_db):
    """A partial hour always compares low and would report a quiet site hourly."""
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=20 * 24, per_hour=20)
        for k in range(500):
            _hit(conn, f"10.0.1.{k % 250}", NOW + timedelta(seconds=k), seq=k)
    with get_conn(tmp_db) as conn:
        base = get_hourly_baseline(conn, now=NOW)
    assert base["requests"]["unusual"] is False


def test_a_multiple_of_almost_nothing_is_not_an_event(tmp_db):
    """On a quiet site the typical hour can be one request, and three would
    otherwise be 300 % of normal."""
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=20 * 24, per_hour=0, probers=1)
        spike = NOW - timedelta(hours=1)
        for k in range(MIN_ABSOLUTE - 2):
            _hit(conn, f"10.0.2.{k}", spike + timedelta(seconds=k), seq=k)
    with get_conn(tmp_db) as conn:
        base = get_hourly_baseline(conn, now=NOW)
    assert base["requests"]["factor"] > 3
    assert base["requests"]["unusual"] is False


def test_a_site_with_no_normal_hour_says_so(tmp_db):
    """Most hours empty means there is nothing to be a multiple of, and that is
    a property of the site rather than a feature that failed."""
    with get_conn(tmp_db) as conn:
        for day in range(20):
            hour = NOW - timedelta(days=day + 1)
            for k in range(30):
                _hit(conn, f"10.0.3.{k}", hour + timedelta(seconds=k), seq=k)
    with get_conn(tmp_db) as conn:
        base = get_hourly_baseline(conn, now=NOW)
    assert base["requests"]["usable"] is False
    assert base["requests"]["unusual"] is False


# ── The typical hour of a window ─────────────────────────────────────────────


def test_the_typical_hour_of_a_window(tmp_db):
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=10 * 24, per_hour=20, probers=2)
    with get_conn(tmp_db) as conn:
        typical = get_typical_hour(conn)
    assert typical["probing_addresses"] == 2.0
    assert typical["requests"] == 22.0


def test_the_typical_hour_of_nothing_is_zero(tmp_db):
    with get_conn(tmp_db) as conn:
        assert get_typical_hour(conn)["probing_addresses"] == 0.0


def test_one_unparseable_timestamp_does_not_take_the_page_down(tmp_db):
    """LogEntry.time is an unvalidated string, so a broken log_format can put
    anything in the column and a restored archive keeps whatever was there.

    Falling back to the hours that have rows makes the median optimistic rather
    than absent, which is the safe direction: it can only report something as
    *less* unusual than it is, never more.
    """
    from src.queries import insert_visit

    with get_conn(tmp_db) as conn:
        _steady(conn, hours=30, per_hour=4)
        upsert_ip_intel(conn, {"ip": "203.0.113.99"})
        insert_visit(conn, ip="203.0.113.99", timestamp="not-a-timestamp", path="/", status=200)
    with get_conn(tmp_db) as conn:
        assert get_typical_hour(conn)["requests"] > 0


# ── What it produces ─────────────────────────────────────────────────────────


def test_an_unusual_hour_becomes_something_to_look_at(tmp_db):
    # Anchored on the real clock, not on NOW: get_attention_items() reads it
    # directly, because it answers "right now" and has no window to be given.
    real = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=20 * 24, per_hour=20, probers=1, end=real)
        burst = real - timedelta(hours=1)
        for k in range(60):
            _hit(
                conn,
                f"10.0.4.{k}",
                burst + timedelta(seconds=k),
                path=f"/x{k}.php",
                status=404,
                seq=k,
            )
    with get_conn(tmp_db) as conn:
        items = [i for i in get_attention_items(conn) if i["tag"] == "This hour"]
    assert len(items) == 1
    assert "probing in the last hour" in items[0]["text"]


def test_an_ordinary_hour_produces_nothing(tmp_db):
    """A finding that always fires is a finding nobody reads."""
    real = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=20 * 24, per_hour=20, probers=1, end=real)
    with get_conn(tmp_db) as conn:
        assert [i for i in get_attention_items(conn) if i["tag"] == "This hour"] == []


def test_tor_is_measured_against_its_median_day(tmp_db):
    """The finding it replaces used a seven-day mean, so one loud day hid the
    next. Six quiet days, one enormous one, then a real spike today."""
    today = datetime.now(timezone.utc).replace(hour=6, minute=0, second=0, microsecond=0)
    with get_conn(tmp_db) as conn:
        for day in range(1, 7):
            for k in range(5):
                _hit(conn, "203.0.113.9", today - timedelta(days=day, seconds=k), tor=True, seq=k)
        for k in range(700):
            _hit(conn, "203.0.113.9", today - timedelta(days=7, seconds=k), tor=True, seq=k)
        for k in range(40):
            _hit(conn, "203.0.113.9", today + timedelta(seconds=k), tor=True, seq=k)
    with get_conn(tmp_db) as conn:
        items = [i for i in get_attention_items(conn) if i["tag"] == "Tor"]
    assert len(items) == 1, "the mean of the week would have hidden this"
    assert "typical day" in items[0]["text"]


@pytest.mark.parametrize("addresses,usual,expected", [(11, 3.0, 3.7), (4, 3.0, 1.3)])
def test_an_incident_is_placed_against_an_ordinary_hour(addresses, usual, expected):
    """Including when the answer is "barely above". A page that shows the
    multiple only when it flatters the finding is arguing, not informing."""
    from src.routes.incidents import _against_normal

    assert _against_normal({"addresses": addresses}, {"probing_addresses": usual}) == expected


def test_an_incident_says_nothing_where_there_is_no_normal():
    from src.routes.incidents import _against_normal

    assert _against_normal({"addresses": 11}, {"probing_addresses": 0}) is None


# ── What it must not cost ────────────────────────────────────────────────────


def test_the_findings_list_does_not_recompute_the_baseline(tmp_db):
    """The list sits behind the nav badge, which renders on every page.

    COUNT(DISTINCT ip) per hour over four weeks measured 290 ms on 520 000
    visits, against 6 ms for every other finding together. The answer changes
    once an hour, so the caller caches it on the hour and passes it in; taking
    the argument away would put the 290 ms back on every page.
    """
    calls = []
    with get_conn(tmp_db) as conn:
        _steady(conn, hours=48, per_hour=5)
    import src.queries.stats as stats

    original = stats.get_hourly_baseline
    stats.get_hourly_baseline = lambda *a, **k: calls.append(1) or original(*a, **k)
    try:
        with get_conn(tmp_db) as conn:
            get_attention_items(conn, {"enough_history": False})
        assert calls == [], "a supplied baseline must not be recomputed"
        with get_conn(tmp_db) as conn:
            get_attention_items(conn)
        assert calls == [1], "and without one it still works on its own"
    finally:
        stats.get_hourly_baseline = original


def test_a_log_without_a_timezone_does_not_silence_every_finding(tmp_db):
    """A naive timestamp makes the subtraction raise, and the caller turns any
    exception into an empty findings list — so one unusable timestamp would
    remove *all* of them and not just this one. It ends in the baseline."""
    from src.queries import insert_visit

    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "203.0.113.1"})
        insert_visit(conn, ip="203.0.113.1", timestamp="2026-06-01T10:00:00", path="/", status=200)
    with get_conn(tmp_db) as conn:
        assert get_hourly_baseline(conn)["enough_history"] is False
        get_attention_items(conn)  # must not raise
