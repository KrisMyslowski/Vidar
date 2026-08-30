"""What an ordinary hour looks like here, so an unusual one can be recognised.

The operator has to go and look. A baseline is what lets Vidar say *when* —
and it is deliberately not a chart. A chart is another thing to read; this
produces at most one sentence, and only when there is something to say.

**The median, not the mean.** The one baseline that existed before this
compared today's Tor traffic against a seven-day average, and an average has
the wrong failure mode for exactly this job: one busy day raises the bar, so
the *next* spike sits under it and is never reported. A median moves only when
most hours move.

**Hours with no traffic count as zero.** They are absent from the table, not
absent from the week, and dropping them makes the typical hour on a quiet site
look like its busiest one — after which everything ordinary reads as a spike.
The zeros are counted back in rather than queried, because a row that does not
exist cannot be selected.

**Too little history means no baseline at all.** Under two weeks there is
nothing to be typical about, and a comparison against noise is worse than
silence: it is the shape of evidence without being any.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from ..classifier.patterns import _CONVENTION_404_MATCH
from ._shared import _date_conditions

# How far back "normal" is drawn from. Four weeks covers four of each weekday,
# so a Sunday is compared against a month of hours and not only against
# weekdays. Longer would start averaging over changes to the site itself.
BASELINE_DAYS = 28

# Below this there is nothing to be typical about. Two weeks is where each hour
# of the day has a fortnight of samples behind it.
MIN_BASELINE_DAYS = 14

# What counts as worth saying. Three times the typical hour, and the existing
# Tor finding used two — but that one compared against a mean, which is already
# inflated by whatever it is trying to detect. Against a median, three is the
# same strictness.
UNUSUAL_FACTOR = 3.0

# And a floor, because a multiple of a very small number is not an event. On a
# quiet site the typical hour can be one request, and "300% of normal" would
# then fire on three.
MIN_ABSOLUTE = 10


def _median_with_zeros(values: list[int], total_slots: int) -> float:
    """Median of `values` padded with zeros up to `total_slots` entries.

    The padding is the point: an hour with no traffic writes no row, and
    leaving those out makes a site that is busy for two hours a day look as
    though two hours a day is its normal.
    """
    if total_slots <= 0:
        return 0.0
    zeros = max(total_slots - len(values), 0)
    ordered = [0] * zeros + sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2


def get_hourly_baseline(conn: sqlite3.Connection, now: datetime | None = None) -> dict:
    """What a typical hour holds, and what the last complete hour held.

    Returns `enough_history: False` and nothing else when the log is too short
    to be typical about. Every caller has to handle that state; it is the
    normal one for the first fortnight of any deployment.
    """
    now = now or datetime.now(timezone.utc)
    # The hour that just ended. The current one is still filling and would
    # always compare low — a partial hour looks like a quiet one.
    hour_end = now.replace(minute=0, second=0, microsecond=0)
    hour_start = hour_end - timedelta(hours=1)
    window_start = hour_start - timedelta(days=BASELINE_DAYS)

    earliest = conn.execute("SELECT MIN(timestamp) FROM visits").fetchone()[0]
    if not earliest:
        return {"enough_history": False, "days": 0}
    try:
        first = datetime.fromisoformat(earliest)
        have_days = (hour_start - first).total_seconds() / 86400
    except (ValueError, TypeError):
        # A log_format without a timezone parses to a naive datetime, and
        # subtracting it raises. It has to end here rather than propagate:
        # the caller turns any exception into an empty findings list, so one
        # unusable timestamp would silently remove *every* finding from the
        # Overview and not just this one. The preflight names the real problem.
        return {"enough_history": False, "days": 0}
    if have_days < MIN_BASELINE_DAYS:
        return {"enough_history": False, "days": int(have_days)}

    rows = conn.execute(
        f"""
        SELECT strftime('%Y-%m-%dT%H', v.timestamp) AS hour,
               COUNT(*) AS requests,
               COUNT(DISTINCT CASE WHEN v.status = 404
                                    AND NOT ({_CONVENTION_404_MATCH})
                                   THEN v.ip END) AS probing_addresses
        FROM visits v
        WHERE v.timestamp >= ? AND v.timestamp < ?
        GROUP BY hour
    """,
        (window_start.isoformat(), hour_end.isoformat()),
    ).fetchall()

    current_key = hour_start.strftime("%Y-%m-%dT%H")
    history = [r for r in rows if r["hour"] != current_key]
    current = next((r for r in rows if r["hour"] == current_key), None)

    slots = int(min(have_days, BASELINE_DAYS) * 24)
    measures = {}
    for name in ("requests", "probing_addresses"):
        typical = _median_with_zeros([r[name] for r in history], slots)
        seen = (current[name] if current else 0) or 0
        measures[name] = {
            "typical": typical,
            "current": seen,
            "factor": round(seen / typical, 1) if typical else None,
            # A site whose median hour is empty has no hourly normal — most of
            # its hours are zero, so any traffic at all would read as unusual.
            # That is a property of the site rather than a missing feature, and
            # it is reported instead of left as a comparison that never fires.
            "usable": bool(typical),
            "unusual": bool(typical and seen >= MIN_ABSOLUTE and seen >= typical * UNUSUAL_FACTOR),
        }

    return {
        "enough_history": True,
        "days": int(min(have_days, BASELINE_DAYS)),
        "hour": hour_start.isoformat(),
        **measures,
    }


def get_typical_hour(
    conn: sqlite3.Connection, since: str | None = None, until: str | None = None
) -> dict:
    """What an ordinary hour held over a window, as a median.

    Separate from get_hourly_baseline() because it answers a different question:
    that one asks whether *now* is unusual, this one asks what usual *was* over
    a stretch, so a past event can be placed against it. One query, computed
    once and reused for every row that needs it — a comparison per incident
    would be a full baseline pass per incident.

    Zeros for empty hours as above, but the slot count comes from the window
    itself rather than from a fixed number of days.
    """
    conds, params = _date_conditions(since, until, column="v.timestamp")
    where = " AND " + " AND ".join(conds) if conds else ""
    rows = conn.execute(
        f"""
        SELECT strftime('%Y-%m-%dT%H', v.timestamp) AS hour,
               COUNT(*) AS requests,
               COUNT(DISTINCT CASE WHEN v.status = 404
                                    AND NOT ({_CONVENTION_404_MATCH})
                                   THEN v.ip END) AS probing_addresses
        FROM visits v
        WHERE 1=1{where}
        GROUP BY hour
    """,
        params,
    ).fetchall()
    if not rows:
        return {"hours": 0, "requests": 0.0, "probing_addresses": 0.0}
    span = conn.execute(
        f"SELECT MIN(v.timestamp), MAX(v.timestamp) FROM visits v WHERE 1=1{where}", params
    ).fetchone()
    try:
        first, last = datetime.fromisoformat(span[0]), datetime.fromisoformat(span[1])
        slots = max(int((last - first).total_seconds() // 3600) + 1, len(rows))
    except (ValueError, TypeError):
        # `LogEntry.time` is an unvalidated string, so a broken log_format can
        # put anything in the column and a restored archive keeps whatever was
        # there. One such row must not take a page down: falling back to the
        # hours that actually have rows makes the median optimistic rather than
        # absent, which is the safe direction — it can only report *less*
        # unusual, never more.
        slots = len(rows)
    return {
        "hours": slots,
        "requests": _median_with_zeros([r["requests"] for r in rows], slots),
        "probing_addresses": _median_with_zeros([r["probing_addresses"] for r in rows], slots),
    }
