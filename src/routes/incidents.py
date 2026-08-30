"""GET /incidents — what happened, rather than who came.

Every other surface answers "who visited". This one answers "what happened",
which is the question somebody actually has when they open a dashboard at
three in the morning. Nine thousand rows cannot answer it; ten events can.

Cached, and it is the one page here that has to be. The query sessionises every
address in the window — the expensive shape VID-14 avoided everywhere else —
and takes hundreds of milliseconds where the rest take single digits.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Query, Request

from ..incidents import INCIDENT_GAP_SECONDS, MIN_ADDRESSES, SIGNATURE_PATHS, score_parts
from ..queries import get_incidents, get_typical_hour
from ..validators import valid_date
from ._app import templates
from ._cache import _cached, fetch
from ._range import _remember_range, _remembered_range, _resolve_range

router = APIRouter()

# How many member addresses a row shows before the cell starts scrolling. Eight
# fits the column; the rest are still in the incident and one click away on any
# of the addresses shown.
_MEMBERS_SHOWN = 8


@router.get("/incidents")
async def incidents(
    request: Request,
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
):
    """Runs of one program across several addresses, most notable first.

    An empty list is a valid result and the common one on a small site. The
    page says so in words: correlation without volume is noise, and a surface
    that lowers its own bar to avoid looking idle stops being worth opening.
    """
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    date_from, date_to, active_range = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )

    def _load(conn):
        return _cached(
            f"incidents:{date_from}:{date_to}",
            lambda: (
                get_incidents(conn, date_from, date_to),
                get_typical_hour(conn, date_from, date_to),
            ),
        )

    found, typical = await fetch(_load)
    rows = [
        {
            **i,
            # Spelled out here rather than assembled in the template: it is a
            # sentence, and a template joining tuples produced "addresses 4 12".
            "score_explained": _explain_score(i),
            "against_normal": _against_normal(i, typical),
            # overflow_cell takes badge descriptors, so the links are built here
            # rather than in the template: a route owns its URLs, and a template
            # assembling hrefs is a second place they live.
            # Both wide cells are badge lists, the same shape the visitor table
            # uses for ports and tags — so they scroll inside their column
            # instead of stacking one item per line.
            "path_cells": [{"label": p, "cls": "badge-muted"} for p in i["paths"]],
            "member_cells": [
                {"label": ip, "href": f"/visitors/{quote(ip)}", "cls": "badge-muted"}
                for ip in i["members"][:_MEMBERS_SHOWN]
            ],
        }
        for i in found
    ]
    return _remember_range(
        templates.TemplateResponse(
            request,
            "incidents.html",
            {
                "incidents": rows,
                "typical_hour": typical,
                # Summed from the rows the page is showing rather than queried
                # again: a second query for them could disagree with the table
                # under it.
                "totals": {
                    "addresses": sum(i["addresses"] for i in rows),
                    "asns": sum(i["asns"] for i in rows),
                    "probe_404": sum(i["probe_404"] for i in rows),
                },
                "signature_paths": SIGNATURE_PATHS,
                "min_addresses": MIN_ADDRESSES,
                "incident_gap_minutes": INCIDENT_GAP_SECONDS // 60,
                "active_range": active_range,
                "date_from": date_from or "",
                "date_to": date_to or "",
                "range_params": "",
            },
        ),
        active_range,
        date_from,
        date_to,
    )


def _against_normal(incident: dict, typical: dict) -> float | None:
    """How many times the usual number of probing addresses this incident held.

    None when the window has no usable normal — a site whose median hour sees
    nobody probing has nothing to be a multiple of, and "infinitely more than
    usual" is not a sentence anybody can act on.

    Against the addresses rather than the requests, because that is what an
    incident *is*: several places doing one thing. A single machine sending ten
    thousand requests is loud and is not an incident.
    """
    usual = typical.get("probing_addresses") or 0
    if not usual:
        return None
    return round(incident["addresses"] / usual, 1)


def _explain_score(incident: dict) -> str:
    """The sort key written out over the figures in the row it belongs to.

    Every count named here is a column of the same row, so a reader can check
    the total against what is in front of them rather than trusting it. That is
    the whole reason the number is allowed to exist.
    """
    terms = " + ".join(
        f"{count:,} {what} \u2192 {points}" for what, count, points in score_parts(incident)
    )
    return f"{terms} = {incident['score']}"
