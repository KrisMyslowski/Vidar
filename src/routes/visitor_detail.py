"""GET /visitors/{ip} — one IP's full history.

Registered last: the path pattern is a catch-all under /visitors, so every
literal /visitors/* route must already be on the router when this lands."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, HTTPException, Query, Request

from ..queries import (
    VISITOR_REQUEST_SORT_MAP,
    count_sessions,
    count_visitor_requests,
    explain_classification,
    get_neighbourhood,
    get_sessions,
    get_visitor_detail,
    get_visitor_requests,
)
from ..queries.sessions import _duration_seconds
from ..sessions import BEHAVIOUR_BADGES
from ..validators import valid_order, valid_timestamp
from ._app import templates
from ._cache import fetch
from ._helpers import total_pages

router = APIRouter()

# The newest sessions, not all of them. An address with 20 000 visits can carry
# hundreds, and a page that renders every one of them is a page nobody scrolls
# to the end of. The true count is fetched separately and shown, so the cut is
# visible rather than silent.
_SESSION_LIMIT = 25


@router.get("/visitors/{ip}")
async def visitor_detail(
    request: Request,
    ip: str,
    page: int = Query(default=1, ge=1),
    sort: str = "timestamp",
    order: str = "DESC",
):
    """Detail view for a single IP: geo info, flags, paginated request log."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None
    if sort not in VISITOR_REQUEST_SORT_MAP:
        sort = "timestamp"
    order = valid_order(order)

    def _load(conn):
        return (
            get_visitor_detail(conn, ip),
            get_visitor_requests(conn, ip, page, limit=100, sort=sort, order=order),
            explain_classification(conn, ip),
            get_neighbourhood(conn, ip),
            get_sessions(conn, ip, limit=_SESSION_LIMIT),
            count_sessions(conn, ip),
        )

    detail, reqs, evidence, neighbourhood, sessions, session_total = await fetch(_load)
    if not detail:
        raise HTTPException(status_code=404, detail="IP not found")
    total = detail["visit_count"]
    err_share = round((detail.get("err_4xx") or 0) / total * 100) if total else 0
    return templates.TemplateResponse(
        request,
        "visitor_detail.html",
        {
            "detail": detail,
            "requests": reqs,
            "evidence": evidence,
            "neighbourhood": neighbourhood,
            "sessions": sessions,
            "session_total": session_total,
            "err_share": err_share,
            "ip": ip,
            "page": page,
            "sort": sort,
            "order": order,
            "total_pages": total_pages(total, 100),
        },
    )


# What one session's drawer shows before it says it is showing a prefix. A
# session on this deployment reaches 3 472 requests; the point of the panel is
# the shape of the run, and the first hundred carry that.
_SESSION_ROWS = 100


@router.get("/visitors/{ip}/session")
async def visitor_session(
    request: Request, ip: str, from_: str = Query(alias="from"), to: str = Query(...)
):
    """The requests one session is made of, as a drawer fragment.

    A session has no stored id — it is computed on read, which is what keeps it
    free — and it does not need one. It is a contiguous run of an address's
    requests bounded by silence, so its own [started, ended] selects exactly its
    rows: checked against all 1 568 sessions in a week of production.

    Which is also why the window here is an exact timestamp range and not the
    date window the rest of the dashboard uses. That one rounds its upper bound
    up to the end of the day, on purpose; here it counted 1 043 requests for a
    session of 514.

    Registered above /visitors/{ip} in this module's file order for readability
    only — three path segments against two, so neither can shadow the other.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None
    if not (valid_timestamp(from_) and valid_timestamp(to)):
        raise HTTPException(status_code=400, detail="Session bounds must be ISO timestamps")
    # Straight from the URL into a dict lookup otherwise, which is a 500 for
    # anyone who mistypes it. It only labels the panel; an unknown one is no
    # label rather than an error.
    behaviour = request.query_params.get("behaviour", "")
    behaviour = behaviour if behaviour in BEHAVIOUR_BADGES else ""

    def _load(conn):
        return (
            get_visitor_requests(
                conn,
                ip,
                limit=_SESSION_ROWS,
                sort="timestamp",
                order="ASC",
                since=from_,
                until=to,
            ),
            count_visitor_requests(conn, ip, from_, to),
        )

    rows, total = await fetch(_load)
    return templates.TemplateResponse(
        request,
        "_session_rows.html",
        {
            "rows": rows,
            "total": total,
            "limit": _SESSION_ROWS,
            "started": from_,
            "duration": _duration_seconds(from_, to),
            "behaviour": behaviour,
        },
    )
