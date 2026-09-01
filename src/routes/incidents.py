"""GET /incidents — what happened, rather than who came.

Every other surface answers "who visited". This one answers "what happened",
which is the question somebody actually has when they open a dashboard at
three in the morning. Nine thousand rows cannot answer it; ten events can.

Cached, and it is the one page here that has to be. The query sessionises every
address in the window — the expensive shape VID-14 avoided everywhere else —
and takes hundreds of milliseconds where the rest take single digits.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request

from ..incidents import INCIDENT_GAP_SECONDS, MIN_ADDRESSES, SIGNATURE_PATHS, score_parts
from ..queries import get_incident_paths, get_incident_sessions, get_incidents, get_typical_hour
from ..template_filters import fmtduration
from ..validators import valid_choice, valid_date, valid_order, valid_timestamp
from ._app import templates
from ._cache import _cached, fetch
from ._filters import (
    INCIDENT_DEFAULT_SORT,
    INCIDENT_PATH_DEFAULT_SORT,
    INCIDENT_PATH_SORTS,
    INCIDENT_SESSION_DEFAULT_SORT,
    INCIDENT_SESSION_SORTS,
    INCIDENT_SORTS,
    apply_sort,
)
from ._helpers import total_pages
from ._range import _remember_range, _remembered_range, _resolve_range
from ._urls import window_fields, window_params

router = APIRouter()

# How many member addresses a row shows before the cell starts scrolling. Eight
# fits the column; the rest are still in the incident and one click away on any
# of the addresses shown.
_MEMBERS_SHOWN = 8

# What a signature digest looks like. Checked before it reaches the query so a
# caller cannot put arbitrary text where a name belongs; it selects nothing
# either way, but an empty panel and a rejected request say different things.
_DIGEST_RE = re.compile(r"[0-9a-f]{16}")

# How much of the path list one page of the panel draws. This used to be a hard
# cut at forty with a line underneath saying what was lost — on the reference
# deployment the largest campaign asks for 266 distinct paths, so 226 of them
# were unreachable. It is a page size now: the same forty are still what you
# see first, and the rest is a click away rather than gone.
_PATHS_PER_PAGE = 40


@router.get("/incidents")
async def incidents(
    request: Request,
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
    sort: str = "",
    order: str = "DESC",
):
    """Runs of one program across several addresses, most notable first.

    An empty list is a valid result and the common one on a small site. The
    page says so in words: correlation without volume is noise, and a surface
    that lowers its own bar to avoid looking idle stops being worth opening.
    """
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    sort = valid_choice(sort, frozenset(INCIDENT_SORTS), INCIDENT_DEFAULT_SORT)
    order = valid_order(order)
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
    # After the decoration, not inside the cached load: `against_normal` is added
    # here, and the cache key names the window only — so sorting there would
    # serve one reader's order to the next.
    rows = apply_sort(rows, INCIDENT_SORTS, sort, order, INCIDENT_DEFAULT_SORT)
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
                # Spelled, not divided: the tile said "within 1440 minutes",
                # which nobody converts in a hover. docs/usage.md calls the
                # same constant "a day" and spends a paragraph on why.
                "incident_window": fmtduration(INCIDENT_GAP_SECONDS),
                "active_range": active_range,
                "date_from": date_from or "",
                "date_to": date_to or "",
                "sort": sort,
                "order": order,
                "range_params": f"&sort={sort}&order={order}",
                "sort_params": window_params(active_range, date_from, date_to),
                # So submitting a custom range keeps the sort instead of
                # silently falling back to the default.
                "range_fields": window_fields(sort, order),
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
    # A term whose count is unknown is left out rather than printed as zero.
    # "0 networks → 0" reads as a measurement that contributed nothing, when
    # what happened is that nothing was measured.
    terms = " + ".join(
        f"{count:,} {what} \u2192 {points}"
        for what, count, points in score_parts(incident)
        if count or points
    )
    return f"{terms} = {incident['score']}"


@router.get("/incidents/case")
async def incident_case(
    request: Request,
    from_: str = Query(alias="from"),
    to: str = Query(...),
    sig: str = Query(...),
    page: int = Query(default=1, ge=1),
    sort: str = INCIDENT_PATH_DEFAULT_SORT,
    order: str = "ASC",
    ssort: str = INCIDENT_SESSION_DEFAULT_SORT,
    sorder: str = "ASC",
):
    """The sessions one incident is made of, as a drawer fragment.

    An incident is named by its signature and its stretch of time, the same way
    a session is named by its bounds — neither has a stored id and neither
    needs one. The signature travels as a digest because five paths do not fit
    comfortably in a URL; one of them on this deployment is a 120-character PHP
    payload.

    Two segments, so it cannot be confused with /incidents itself.

    The panel sorts and pages itself: its two tables carry their own parameters
    (`sort`/`order` and `page` for the paths, `ssort`/`sorder` for the
    sessions), and drawer.js re-fetches this route rather than letting the link
    navigate the page underneath. Only the paths page — the sessions of an
    incident are the addresses in it, twenty at the widest here, and the probe
    total in the header is summed from them, so a page of them would put a
    partial sum under a heading that states a whole one.
    """
    if not (valid_timestamp(from_) and valid_timestamp(to)):
        raise HTTPException(status_code=400, detail="Incident bounds must be ISO timestamps")
    if not _DIGEST_RE.fullmatch(sig):
        raise HTTPException(status_code=400, detail="Signature must be a digest")

    def _load(conn):
        # The signature comes back from the first query because only it knows
        # what the digest names, and the second needs it to ask what those
        # sessions requested.
        signature, sessions = get_incident_sessions(conn, from_, to, sig)
        paths = get_incident_paths(conn, from_, to, signature) if signature else []
        return sessions, paths

    sessions, paths = await fetch(_load)

    # The arrival position becomes a value in the row before anything reorders
    # them. That is what lets this table be sorted at all: the order the paths
    # came in is the signature, and moving the rows only loses it if the order
    # lives nowhere but in the sequence.
    for i, p in enumerate(paths, 1):
        p["pos"] = i

    sort = valid_choice(sort, frozenset(INCIDENT_PATH_SORTS), INCIDENT_PATH_DEFAULT_SORT)
    ssort = valid_choice(ssort, frozenset(INCIDENT_SESSION_SORTS), INCIDENT_SESSION_DEFAULT_SORT)
    order, sorder = valid_order(order), valid_order(sorder)

    paths = apply_sort(paths, INCIDENT_PATH_SORTS, sort, order, INCIDENT_PATH_DEFAULT_SORT)
    sessions = apply_sort(
        sessions, INCIDENT_SESSION_SORTS, ssort, sorder, INCIDENT_SESSION_DEFAULT_SORT
    )

    path_total = len(paths)
    pages = total_pages(path_total, _PATHS_PER_PAGE)
    # Clamped rather than trusted: ?page=900 on a two-page panel would otherwise
    # render an empty table under a header still counting 266 paths. The lower
    # bound is Query(ge=1)'s, like every other paged route here.
    page = min(page, pages)
    start = (page - 1) * _PATHS_PER_PAGE

    return templates.TemplateResponse(
        request,
        "_incident_rows.html",
        {
            "sessions": sessions,
            "paths": paths[start : start + _PATHS_PER_PAGE],
            "path_total": path_total,
            "page": page,
            "total_pages": pages,
            "sort": sort,
            "order": order,
            "ssort": ssort,
            "sorder": sorder,
            # Summed from what the panel is showing, so it can be checked
            # against the row it came from rather than trusted. Still true with
            # the paths paged: this sums the sessions, and those are all here.
            "probes": sum(s["probe_404"] for s in sessions),
            "started": from_,
            "ended": to,
            # The panel's own address, split the way the table macros take it:
            # a base they put "?" after, and a tail they append. The three name
            # the incident, so every sort and page link inside the panel has to
            # carry them or the re-fetch asks for a different case.
            "case_url": "/incidents/case",
            "case_params": (
                f"&from={quote(from_, safe='')}"
                f"&to={quote(to, safe='')}&sig={quote(sig, safe='')}"
            ),
        },
    )
