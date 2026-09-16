"""The monthly report — one month, read in three minutes, handed to somebody else.

A dashboard has to be visited. This is the other direction: a page that states
what a month was, in the order somebody actually asks it, and a Markdown copy of
the same thing that can be pasted into a mail or a ticket.

It answers four questions and stops:

  who came, what happened, what did this server hand out, what moved

Everything here is assembled from the queries the dashboard already runs. A
report computing its own figures would be a second opinion on numbers the pages
beside it already state, and the first time the two disagreed the report would
be the one nobody believed. That constraint is the reason this module is thin:
its work is choosing, comparing and phrasing, not counting.

What it deliberately does not do: send mail. That is an SMTP configuration, a
credential and a delivery failure mode, for a file the operator can already
forward. The plan said "file or mail"; the file is the half that costs nothing.
"""

from __future__ import annotations

import calendar
import sqlite3

from .incidents import INCIDENT_GAP_SECONDS, MIN_ADDRESSES, SIGNATURE_PATHS
from .queries import (
    get_exposures,
    get_incidents,
    get_stats,
    get_visit_months,
    get_visitor_ip_counts,
)

# The identity groups, in the order the report reads them: the headline first,
# then descending by how much of the traffic they usually are. Same keys and the
# same order as the legend on /visitors, so a reader moving between the two is
# not re-learning the vocabulary.
GROUPS = ("humans", "bots", "automated", "threats", "unknown")

# How much of each list the report prints. A report is not a table dump: past
# these the reader is scrolling rather than reading, and the dashboard is one
# click away with all of it.
INCIDENTS_SHOWN = 5
FINDINGS_SHOWN = 5

# How many incidents are fetched before the five are chosen. Not a display
# limit — the report states how many there *were*, and get_incidents applies its
# limit after scoring, so a low one would cap the count rather than the table.
# High enough that no month reaches it: the reference deployment's worst is 12.
INCIDENTS_COUNTED = 1000


def month_bounds(month: str) -> tuple[str, str]:
    """First and last day of `YYYY-MM`, both inclusive.

    Inclusive at both ends because that is what the query layer's window means —
    `until` covers its whole day — and a report that quietly stopped at midnight
    on the 31st would under-count the last day of every month it describes.
    """
    year, mon = (int(p) for p in month.split("-"))
    last = calendar.monthrange(year, mon)[1]
    return f"{month}-01", f"{month}-{last:02d}"


def previous_month(month: str) -> str:
    """The month before `YYYY-MM`."""
    year, mon = (int(p) for p in month.split("-"))
    return f"{year - 1}-12" if mon == 1 else f"{year}-{mon - 1:02d}"


def month_label(month: str) -> str:
    """`2026-08` as `August 2026`, for a heading somebody reads aloud."""
    year, mon = (int(p) for p in month.split("-"))
    return f"{calendar.month_name[mon]} {year}"


def available_months(conn: sqlite3.Connection) -> list[str]:
    """Months the database still holds visits for, newest first.

    Retention takes whole months out to a zip, so this shrinks from the back.
    A report for a month that has been archived would be silently empty, which
    is why the caller picks from this list rather than from a calendar.
    """
    return [row["month"] for row in reversed(get_visit_months(conn))]


def _share(part: int, whole: int) -> float | None:
    """`part` as a percentage of `whole`, or None when there is no whole.

    None rather than 0.0: a month with no traffic has no composition, and
    printing 0 % human of nothing states something the data does not.
    """
    return round(part / whole * 100, 1) if whole else None


def _delta(now: float | None, before: float | None) -> float | None:
    """Change in percentage points, or None where either side is unknown."""
    if now is None or before is None:
        return None
    return round(now - before, 1)


def _composition(counts: dict[str, int]) -> list[dict]:
    """The identity mix as rows: group, addresses, share of all addresses."""
    total = counts.get("all", 0)
    return [
        {
            "group": g,
            "addresses": counts.get(g, 0),
            "share": _share(counts.get(g, 0), total),
        }
        for g in GROUPS
    ]


def _new_findings(month_rows: list[dict], first_ever: dict[str, str], start: str) -> list[dict]:
    """Findings whose first successful fetch *ever* falls inside this month.

    The distinction the report exists to make. A path that has been served for
    three months is not news in the third; one that answered for the first time
    on the 12th is the line an operator wants to see, and "new" has to be asked
    of the whole database rather than of the window, or every finding is new in
    every month it appears in.
    """
    out = []
    for row in month_rows:
        ever = first_ever.get(row["path"])
        row = {**row, "first_ever": ever}
        row["is_new"] = bool(ever) and ever[:10] >= start
        out.append(row)
    return out


def _uncached(_key: str, produce):
    """The default `cache`: run it. Keeps this module callable without a route."""
    return produce()


def build_report(conn: sqlite3.Connection, month: str, cache=_uncached) -> dict:
    """Everything one month's report states, as data.

    Kept apart from the route and from the template so the page and the Markdown
    are two renderings of one thing rather than two reports that happen to agree
    today. The tests read this, not the HTML.

    `cache` is the route's `_cached`, passed in rather than imported: this module
    has no business knowing about HTTP, and the tests want the queries to
    actually run. Two of the six calls carry most of the cost — get_stats at
    273 ms on the reference month against 8 ms for the exposure pair — and a
    month that has ended never changes, so caching them is both the cheapest and
    the safest place to spend the seam.
    """
    start, end = month_bounds(month)
    prev = previous_month(month)
    prev_start, prev_end = month_bounds(prev)

    # Same key shape the Overview uses for the same call, so whichever page is
    # opened first pays for the window and the other one does not.
    stats = cache(f"stats:{start}:{end}", lambda: get_stats(conn, since=start, until=end))
    prev_stats = cache(
        f"stats:{prev_start}:{prev_end}",
        lambda: get_stats(conn, since=prev_start, until=prev_end),
    )
    counts = get_visitor_ip_counts(conn, start, end)
    prev_counts = get_visitor_ip_counts(conn, prev_start, prev_end)

    composition = _composition(counts)
    prev_composition = {r["group"]: r["share"] for r in _composition(prev_counts)}
    # The previous month is only a comparison if it holds anything. A first
    # month compares against an empty database and would report every share as
    # a rise from nothing.
    comparable = prev_stats["total_visits"] > 0
    for row in composition:
        row["prev_share"] = prev_composition.get(row["group"]) if comparable else None
        row["delta"] = _delta(row["share"], row["prev_share"])

    # A key of its own, not /incidents'. That page asks for the default 50 and
    # this asks for INCIDENTS_COUNTED; one key over two different results is how
    # a cache starts answering the wrong question.
    incidents = cache(
        f"report-incidents:{start}:{end}",
        lambda: get_incidents(conn, start, end, limit=INCIDENTS_COUNTED),
    )
    findings_month = [f for f in get_exposures(conn, start, end) if f["is_finding"]]
    first_ever = {f["path"]: f["first_seen"] for f in get_exposures(conn)}
    findings = _new_findings(findings_month, first_ever, start)

    visits, prev_visits = stats["total_visits"], prev_stats["total_visits"]
    return {
        "month": month,
        "label": month_label(month),
        "start": start,
        "end": end,
        "previous": {"month": prev, "label": month_label(prev), "comparable": comparable},
        "visits": visits,
        "addresses": counts.get("all", 0),
        "countries": stats["total_countries"],
        "humans": counts.get("humans", 0),
        "human_share": _share(counts.get("humans", 0), counts.get("all", 0)),
        "composition": composition,
        "visits_delta": (
            round((visits - prev_visits) / prev_visits * 100) if comparable else None
        ),
        "incidents": incidents[:INCIDENTS_SHOWN],
        "incident_total": len(incidents),
        # Distinct across incidents. Summing each incident's own count reported
        # the same machines running the same tool on two days twice over.
        "incident_addresses": len({ip for i in incidents for ip in i["members"]}),
        # Distinct signatures, not distinct events. Eleven incidents from one
        # digest is one program that kept coming back, and eleven from eleven is
        # eleven different tools — the same count, and not the same month. The
        # table cannot show it: every row would read the same and the reader
        # would have to notice.
        "incident_programs": len({i["digest"] for i in incidents}),
        "findings": sorted(findings, key=lambda f: (not f["is_new"], -f["ips"]))[:FINDINGS_SHOWN],
        "finding_total": len(findings),
        "new_findings": [f for f in findings if f["is_new"]],
        # The two thresholds the "what happened" section is built on. Printed
        # with it, because "no incidents" is only informative next to what would
        # have counted as one.
        "incident_rule": {
            "addresses": MIN_ADDRESSES,
            "paths": SIGNATURE_PATHS,
            "window": INCIDENT_GAP_SECONDS,
        },
        "empty": visits == 0,
    }
