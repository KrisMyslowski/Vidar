"""Shaping between a query's rows and the chart blocks that draw them.

None of this is page-specific, and it used to live in overview.py, which meant
two other route modules imported helpers out of a third one — the same knot
api.py had around fetch(). It has its own module now, so a page importing it is
importing from the layer below rather than sideways.
"""

from __future__ import annotations

import math
from datetime import date, timedelta

from ..taxonomy import GROUP_COLOR_VARS, GROUPS_WITH_UNKNOWN

# Below this many days a daily axis has too few points to say anything, so the
# activity chart works in hours instead. Both ends use it: the route picks the
# bucket the page ships with, and timeline.js picks the one a zoom drops to.
# It reaches the browser inside the chart's own payload rather than as a second
# literal in the JS — one number, one place.
HOUR_SWITCH_DAYS = 3


def pick_bucket(date_from: str | None, date_to: str | None) -> str:
    """The bucket a window of this length deserves: "hour" when short, else "day".

    A 24-hour window bucketed by day is one or two points, which is not a chart
    — and zooming could not fix it either, because a drag inside a single bucket
    has nothing to zoom into. So the window decides the resolution up front, and
    zooming stays what it is for: going finer than the page already shows.

    An open-ended window ("all") is days: it is the longest span there is.
    """
    if not date_from or not date_to:
        return "day"
    try:
        span = (date.fromisoformat(date_to[:10]) - date.fromisoformat(date_from[:10])).days
    except ValueError:
        return "day"
    # <=, matching pickBucket() in timeline.js. At exactly the threshold the two
    # would otherwise disagree: the page would ship days and the first zoom would
    # immediately refetch the same span as hours.
    return "hour" if abs(span) <= HOUR_SWITCH_DAYS else "day"


# Stacking order for every day-column chart, bottom to top. Colors come from the
# taxonomy single source, so the bars match the legend and every table.
# `color` is the CSS value the legend uses; `token` is the same colour for the
# timeline's SVG, which cannot take a var() in a presentation attribute and has
# to resolve it through cssVar() instead. One source either way.
ACTIVITY_SERIES = [
    {
        "key": g,
        "label": g.title(),
        "color": GROUP_COLOR_VARS[g],
        "token": GROUP_COLOR_VARS[g].removeprefix("var(--").removesuffix(")"),
        "href": f"/visitors?class={g}",
    }
    for g in GROUPS_WITH_UNKNOWN
]


def overlay_new(rows: list[dict], new_rows: list[dict]) -> list[dict]:
    """Fold the New series into the All series, as `<key>_new` beside each key.

    Under the All + New comparison the charts draw both, and the gap between
    them is the returning traffic — 40 % of one day's requests were from
    addresses seen before, 8 % of another's, and a single line cannot say which
    kind of day it was.

    Two passes of the same query rather than one query counting both. The
    single query is faster — 47 ms against 113 on a month of real traffic — and
    it would be a second way of computing a number this page already computes,
    free to drift from what the All and New views show on their own. The
    comparison has to agree with the two things it is comparing.

    New is always a subset of All: an address whose first request is inside the
    window is an address inside the window. So the series nest, and the drawing
    can rely on it.
    """
    by_day = {r["day"]: r for r in new_rows}
    out = []
    for row in rows:
        fresh = by_day.get(row["day"], {})
        out.append({**row, **{f"{k}_new": fresh.get(k, 0) for k in row if k != "day"}})
    return out


def day_rows(rows: list[dict], label_key: str = "day") -> list[dict]:
    """Shape a timeline query's rows for the stacked_bars block."""
    return [{**r, "label": r.get(label_key, "")} for r in rows]


def bar_rows(items: list[dict], label_key: str, value_key: str, href=None) -> list[dict]:
    """Shape a top-N list for the bar_rows block."""
    return [
        {
            "label": i.get(label_key) or "—",
            "value": i.get(value_key) or 0,
            "href": href(i) if href else "",
        }
        for i in items
    ]


def heat_ramp(value: int, low: int, high: int) -> float:
    """A cell's position on the colour ramp, 0..1, logarithmically.

    Traffic per weekday-hour is far too skewed for a linear division. Measured
    over a month of real traffic: median 456, p90 901, one cell at 6 875 — and
    dividing by the maximum put 134 of 168 cells below 0.10 and 162 below 0.25.
    A 170-visit cell and a 637-visit cell resolved to colours no eye separates,
    so the grid read as one bright square in a uniform field, which is not a
    rhythm.

    map.js already solved this for the map's heat layer and wrote down why: on
    a linear ramp one busy cell makes every quiet one invisible. Two blocks on
    the same page disagreed about how to encode a count.

    Normalised between the observed extremes rather than against the maximum
    alone, because plain log(v+1)/log(max+1) still compressed this data into
    the top half of the ramp. Against the same month the quartiles land at
    0.20 / 0.27 / 0.36 instead of 0.05 / 0.07 / 0.09.
    """
    if value <= 0 or high <= 0:
        return 0.0
    if high <= low:
        return 1.0
    span = math.log(high) - math.log(max(low, 1))
    if span <= 0:
        return 1.0
    return max(0.0, min(1.0, (math.log(value) - math.log(max(low, 1))) / span))


def _weekdays_in(since: str | None, until: str | None) -> set[int]:
    """Which SQLite weekday numbers the window actually covers.

    All seven when it is open-ended, and all seven once it is a week or longer.
    A three-day window covers three, and the other four rows are an absence of
    calendar rather than an absence of traffic.
    """
    every = set(range(7))
    if not since or not until:
        return every
    try:
        a, b = date.fromisoformat(since[:10]), date.fromisoformat(until[:10])
    except ValueError:
        return every
    if b < a or (b - a).days >= 6:
        return every
    # strftime('%w') is Sunday-zero; date.weekday() is Monday-zero.
    return {(a + timedelta(days=n)).isoweekday() % 7 for n in range((b - a).days + 1)}


def build_heatmap_grid(
    rows: list[dict], since: str | None = None, until: str | None = None
) -> tuple[list[dict], dict[str, int]]:
    """Pivot get_hourly_heatmap() rows into Monday-first display rows for the
    traffic-rhythm heatmap.

    Each cell carries its count and its ramp position, so the template renders
    a number the arithmetic already settled rather than doing the arithmetic in
    Jinja. Returns ([{label, cells: [24 dicts]}], {group: max_count, ...}) —
    `maxes` also carries `low`, the smallest non-empty cell, which the legend
    names as the bottom of the ramp.
    """
    by_cell = {(r["dow"], r["hr"]): r["total"] for r in rows}
    days = [(1, "Mon"), (2, "Tue"), (3, "Wed"), (4, "Thu"), (5, "Fri"), (6, "Sat"), (0, "Sun")]
    high = max((r["total"] for r in rows), default=0)
    low = min((r["total"] for r in rows if r["total"]), default=0)
    covered = _weekdays_in(since, until)
    grid = [
        {
            "label": label,
            # A weekday the window does not reach is not a quiet weekday. Seven
            # rows of near-invisible zero cells said the same thing for both.
            "in_range": dow in covered,
            "cells": [
                {
                    "total": by_cell.get((dow, h), 0),
                    "ramp": heat_ramp(by_cell.get((dow, h), 0), low, high),
                }
                for h in range(24)
            ],
        }
        for dow, label in days
    ]
    return grid, {"total": high, "low": low}
