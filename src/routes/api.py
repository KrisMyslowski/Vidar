"""JSON API routes.

GET /api/stats    — summary statistics
GET /api/activity — visits per day or hour, split by identity group
GET /api/visits   — paginated visit list with IP/country filters
GET /api/export   — full export as JSON or CSV (streamed, date-filtered, rate-limited)
GET /api/decisions — the addresses matching a stated selection, with the evidence
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse, StreamingResponse

from .. import __version__
from ..db import get_conn
from ..queries import (
    DEFAULT_DAYS,
    DEFAULT_GROUPS,
    MAX_ADDRESSES,
    SEEN_BOTH,
    SEEN_NEW,
    SEEN_TOTAL,
    SEEN_VALUES,
    VISIT_SORT_MAP,
    count_visits,
    get_activity_timeline,
    get_decisions,
    get_export_page,
    get_stats,
    get_visitor_timeline,
    get_visits,
    valid_selection,
)
from ..taxonomy import VALID_CLASSES, VALID_GROUPS, VALID_SIGNALS
from ..validators import valid_country, valid_date, valid_ip, valid_order, valid_search
from ._cache import fetch
from ._charts import overlay_new
from ._helpers import total_pages

router = APIRouter()

# Whatever get_visits() can sort by — the same map it resolves the key against,
# rather than a copy of its keys that could fall out of step.
_VALID_SORTS = frozenset(VISIT_SORT_MAP)

_EXPORT_FIELDS = [
    "id",
    "ip",
    "timestamp",
    "method",
    "path",
    "server_port",
    "status",
    "bytes_sent",
    "user_agent",
    "referer",
    "request_time",
    "ssl_protocol",
    "browser",
    "os",
    "device",
    "country",
    "country_code",
    "city",
    "isp",
    "is_proxy",
    "is_hosting",
    "is_mobile",
]


# ── Helpers ──────────────────────────────────────────────────────────────────


def _sanitize_csv_cell(value: Any) -> str:
    """Prefix formula characters to prevent CSV injection in spreadsheets."""
    s = str(value) if value is not None else ""
    s = s.replace("\r", "").replace("\n", " ")
    if s and s[0] in "=+@-":
        return "'" + s
    return s


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/stats")
async def stats(
    date_from: str | None = Query(default=None, alias="from"),
    date_to: str | None = Query(default=None, alias="to"),
):
    """Return summary statistics as JSON.

    Takes the same `from`/`to` window as /api/activity. Without it the answer is
    all-time — the Overview's own default is 90 days, so a caller comparing the
    two has to name the window it wants.
    """
    since = valid_date(date_from)
    until = valid_date(date_to)
    data = await fetch(lambda conn: get_stats(conn, since=since, until=until))
    # Added here rather than in get_stats(): the version is not a fact about the
    # database, and queries/ answers only for what it read out of one.
    return {"version": __version__, **data}


@router.get("/activity")
async def activity(
    date_from: str | None = Query(default=None, alias="from"),
    date_to: str | None = Query(default=None, alias="to"),
    bucket: str = "day",
    cls: list[str] = Query(default=[], alias="class"),
    signal: list[str] = Query(default=[]),
    q: str | None = None,
    seen: str | None = None,
    metric: str = "visits",
):
    """Requests or addresses per bucket, split by identity group.

    Two charts on /visitors?view=timeline read from here — one counting
    requests, one counting the distinct addresses that made them — and both
    refetch through this when a zoom goes finer than the page shipped. The
    metric has to travel with them, or zooming the Addresses chart would answer
    with the Activity chart's numbers under the Addresses chart's labels.

    The page ships its daily rows inline, so this is only called once a reader
    zooms in far enough that days become single points and the chart wants
    hours. Same filters as /visitors?view=timeline, so both show one selection —
    `seen` included, or zooming past three days would answer for every address
    while the page still said New.

    SEEN_BOTH needs the same two passes the page makes. It filters nothing, so
    handing it straight to the query returns the All series alone: the chart
    shipped with two series and lost one the moment a zoom crossed into hours,
    silently, under a control still reading All + New.
    """
    if bucket not in ("day", "hour"):
        bucket = "day"
    seen = seen if seen in SEEN_VALUES else SEEN_TOTAL
    # Normalised, not echoed: the response names the metric it answered with,
    # and handing an unknown value straight back would have it say "addresses"
    # over a column of request counts.
    metric = "addresses" if metric == "addresses" else "visits"
    timeline = get_visitor_timeline if metric == "addresses" else get_activity_timeline
    args = {
        "since": valid_date(date_from),
        "until": valid_date(date_to),
        "class_filter": [c for c in cls if c in VALID_CLASSES or c in VALID_GROUPS],
        "signal_filter": [s for s in signal if s in VALID_SIGNALS],
        "bucket": bucket,
        "q": valid_search(q),
    }

    def _load(conn):
        rows = timeline(conn, seen=seen, **args)
        if seen != SEEN_BOTH:
            return rows
        # Both passes on one connection and one thread hop, the way the page
        # route does it — and with one `args`, so the two series cannot end up
        # describing different selections.
        return overlay_new(rows, timeline(conn, seen=SEEN_NEW, **args))

    return {"bucket": bucket, "metric": metric, "rows": await fetch(_load)}


@router.get("/visits")
async def visits(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=500),
    sort: str = "timestamp",
    order: str = "DESC",
    ip: str | None = None,
    country: str | None = None,
):
    """Paginated visit list with optional IP/country filters."""
    if sort not in _VALID_SORTS:
        sort = "timestamp"
    order = valid_order(order)
    ip = valid_ip(ip)
    country = valid_country(country)
    rows, total = await fetch(
        lambda conn: (
            get_visits(conn, page, limit, sort, order, ip, country),
            count_visits(conn, ip, country),
        )
    )
    return {
        "data": rows,
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages(total, limit),
    }


@router.get("/export")
async def export(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    from_date: str | None = Query(default=None, alias="from"),
    to_date: str | None = Query(default=None, alias="to"),
):
    """Export all visits as JSON or CSV. Supports date range filtering."""
    from_date = valid_date(from_date)
    to_date = valid_date(to_date)

    def row_generator():
        """Stream rows, a page at a time, each page on its own connection.

        Deliberately synchronous: StreamingResponse iterates a sync generator in
        the thread pool, so this stays off the event loop. But it does so one
        next() at a time, and each may run on a different worker thread. The
        connection used to stay open across the yields, and SQLite refuses a
        connection on any thread but its own — the download failed mid-stream
        whenever the pool handed a step to another worker. Every connection now
        opens and closes between two yields, so it lives and dies on one thread,
        and an abandoned download holds nothing open.
        """
        after = None
        while True:
            with get_conn() as conn:
                page = get_export_page(conn, from_date, to_date, after)
            if not page:
                return
            yield from page
            after = (page[-1]["timestamp"], page[-1]["id"])

    if format == "csv":

        def csv_generator():
            """Generate CSV with headers on first row (always), then data rows."""
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=_EXPORT_FIELDS, extrasaction="ignore")
            writer.writeheader()
            yield output.getvalue()

            for row in row_generator():
                output.seek(0)
                output.truncate()
                writer.writerow({k: _sanitize_csv_cell(v) for k, v in row.items()})
                yield output.getvalue()

        return StreamingResponse(
            csv_generator(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=export.csv"},
        )

    # JSON format: stream as a JSON array
    def json_generator():
        """Generate a JSON array, row by row."""
        yield "[\n"
        first = True
        for row in row_generator():
            if not first:
                yield ",\n"
            yield json.dumps(row)
            first = False
        yield "\n]"

    return StreamingResponse(
        json_generator(),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=export.json"},
    )


@router.get("/decisions")
async def decisions(
    format: str = Query(default="txt", pattern="^(txt|json)$"),
    cls: list[str] = Query(default=[], alias="class"),
    group: list[str] = Query(default=[]),
    from_date: str | None = Query(default=None, alias="from"),
    to_date: str | None = Query(default=None, alias="to"),
):
    """The addresses matching a stated selection, with what is known about each.

    Vidar does not decide what is blocked. It says what somebody needs in order
    to decide, in a form another tool can read — CrowdSec, nftables, a shell
    script. The brain, not the hand.

    Which is why the selection travels with the answer. Asked nothing in
    particular it answers for `threats/*` over the last week, and says so; a
    feed whose membership rule is invisible is a blocklist, and a blocklist
    nobody can open is what this project argues against.
    """
    classes, groups = valid_selection(tuple(cls), tuple(group))
    if not classes and not groups:
        groups = DEFAULT_GROUPS
        default = True
    else:
        default = False
    since = valid_date(from_date)
    until = valid_date(to_date)
    if since is None and default:
        since = (datetime.now(timezone.utc) - timedelta(days=DEFAULT_DAYS)).strftime("%Y-%m-%d")

    def load(conn):
        # The cap is passed rather than left to the default, so the number the
        # response reports and the number the query used are the same one.
        return get_decisions(conn, classes, groups, since, until, limit=MAX_ADDRESSES)

    rows = await fetch(load)
    selection = {
        "classes": list(classes),
        "groups": list(groups),
        "from": since,
        "to": until,
        "recommended_default": default,
        "truncated": len(rows) >= MAX_ADDRESSES,
    }
    if format == "json":
        return {"selection": selection, "count": len(rows), "addresses": rows}
    return PlainTextResponse(_as_text(rows, selection), media_type="text/plain; charset=utf-8")


def _as_text(rows: list[dict], selection: dict) -> str:
    """One address per line, with its reason after a `#`.

    The convention Spamhaus DROP and the CrowdSec blocklists use, so the usual
    consumers already strip it — and the reason stays visible to a person
    reading the same file. A feed of bare addresses is one nobody can review.
    """
    what = ", ".join(selection["classes"] + [f"{g}/*" for g in selection["groups"]]) or "nothing"
    head = [
        f"# Vidar {__version__} — addresses matching a selection, not a verdict.",
        "# Vidar does not decide what is blocked. Review before you act on it.",
        f"# Selection: {what}"
        + (" (the recommended default)" if selection["recommended_default"] else ""),
        f"# Window: {selection['from'] or 'all data'} to {selection['to'] or 'now'}",
        f"# Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"# Addresses: {len(rows)}"
        + (
            f" (capped at {MAX_ADDRESSES}; narrow the selection)" if selection["truncated"] else ""
        ),
        "#",
        "# Everything after a # is a comment.",
    ]
    for r in rows:
        marks = [r["visitor_class"]]
        if r["probes"]:
            marks.append(f"{r['probes']} probe" + ("" if r["probes"] == 1 else "s"))
        marks.append(f"{r['requests']} request" + ("" if r["requests"] == 1 else "s"))
        if r["blocklisted"]:
            marks.append("on a blocklist")
        if r["tor"]:
            marks.append("Tor exit")
        if r["hosting"]:
            marks.append("hosting range")
        head.append(f"{r['ip']}  # {' · '.join(marks)}")
    return "\n".join(head) + "\n"
