"""GET /visitors/{ip} — one IP's full history.

Registered last: the path pattern is a catch-all under /visitors, so every
literal /visitors/* route must already be on the router when this lands."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, HTTPException, Query, Request

from ..queries import (
    VISITOR_REQUEST_SORT_MAP,
    explain_classification,
    get_visitor_detail,
    get_visitor_requests,
)
from ..validators import valid_order
from ._app import templates
from ._cache import fetch
from ._helpers import total_pages

router = APIRouter()


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
        )

    detail, reqs, evidence = await fetch(_load)
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
            "err_share": err_share,
            "ip": ip,
            "page": page,
            "sort": sort,
            "order": order,
            "total_pages": total_pages(total, 100),
        },
    )
