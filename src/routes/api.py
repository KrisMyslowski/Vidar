"""JSON API routes.

GET /api/stats    — summary statistics
GET /api/activity — visits per day or hour, split by identity group
GET /api/visits   — paginated visit list with IP/country filters
GET /api/export   — full export as JSON or CSV (streamed, date-filtered, rate-limited)
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from .. import __version__
from ..db import get_conn
from ..queries import (
    VISIT_SORT_MAP,
    count_visits,
    get_activity_timeline,
    get_stats,
    get_visits,
    stream_visits_for_export,
)
from ..taxonomy import VALID_CLASSES, VALID_GROUPS, VALID_SIGNALS
from ..validators import valid_country, valid_date, valid_ip, valid_order, valid_search
from ._cache import fetch
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
):
    """Visits per bucket, split by identity group — the activity chart's data.

    The page ships its daily rows inline, so this is only called once a reader
    zooms in far enough that days become single points and the chart wants
    hours. Same filters as /visitors?view=timeline, so both show one selection.
    """
    if bucket not in ("day", "hour"):
        bucket = "day"
    rows = await fetch(
        lambda conn: get_activity_timeline(
            conn,
            since=valid_date(date_from),
            until=valid_date(date_to),
            class_filter=[c for c in cls if c in VALID_CLASSES or c in VALID_GROUPS],
            signal_filter=[s for s in signal if s in VALID_SIGNALS],
            bucket=bucket,
            q=valid_search(q),
        )
    )
    return {"bucket": bucket, "rows": rows}


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
        """Stream rows while keeping the connection open for the response lifetime.

        Deliberately synchronous: StreamingResponse iterates a sync generator in
        a threadpool, so this already stays off the event loop.
        """
        with get_conn() as conn:
            yield from stream_visits_for_export(conn, from_date, to_date)

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
