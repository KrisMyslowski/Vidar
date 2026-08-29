"""Shaping between a query's rows and the chart blocks that draw them.

None of this is page-specific, and it used to live in overview.py, which meant
two other route modules imported helpers out of a third one — the same knot
api.py had around fetch(). It has its own module now, so a page importing it is
importing from the layer below rather than sideways.
"""

from __future__ import annotations

from datetime import date

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


# Heatmap intensity series: overall total plus each taxonomy group. The toggle
# above the grid picks which one drives cell intensity (default: total).
HEATMAP_GROUPS = ("total", *GROUPS_WITH_UNKNOWN)

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


def build_heatmap_grid(rows: list[dict]) -> tuple[list[dict], dict[str, int]]:
    """Pivot get_hourly_heatmap() rows into Monday-first display rows for the
    traffic-rhythm heatmap. Each cell is a {group: count} dict; returns
    ([{label, cells: [24 dicts]}], {group: max_count})."""
    by_cell = {(r["dow"], r["hr"]): r for r in rows}
    days = [(1, "Mon"), (2, "Tue"), (3, "Wed"), (4, "Thu"), (5, "Fri"), (6, "Sat"), (0, "Sun")]
    grid = [
        {
            "label": label,
            "cells": [
                {g: (by_cell.get((dow, h)) or {}).get(g, 0) for g in HEATMAP_GROUPS}
                for h in range(24)
            ],
        }
        for dow, label in days
    ]
    maxes = {g: max((r[g] for r in rows), default=0) for g in HEATMAP_GROUPS}
    return grid, maxes
