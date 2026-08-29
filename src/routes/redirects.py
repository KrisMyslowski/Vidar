"""Every 301, in one place.

Registered before visitor_detail so the literal /visitors/* paths win over
the /visitors/{ip} pattern."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from ._urls import _carry

router = APIRouter()


# The four aggregation tables became groupings of /visitors, the map a view of
# it. Registered before /visitors/{ip} so they aren't swallowed by the catch-all.
@router.get("/visitors/networks")
async def networks_redirect(request: Request):
    return _carry("/visitors?group=asn", request)


@router.get("/visitors/countries")
async def countries_redirect(request: Request):
    return _carry("/visitors?group=country", request)


@router.get("/visitors/clients")
async def clients_redirect(request: Request):
    return _carry("/visitors?group=client", request)


@router.get("/visitors/paths")
async def paths_redirect(request: Request):
    return _carry("/visitors?group=path", request)


@router.get("/visitors/geo")
async def geo_redirect_view(request: Request):
    return _carry("/visitors?view=map", request)


@router.get("/visitors/analysis")
async def visitors_analysis_redirect(request: Request):
    return _carry("/analysis", request)


# The Timeline page was merged into the Overview (same activity chart; the
# traffic-rhythm heatmap moved there too). Registered before /visitors/{ip}.
@router.get("/visitors/timeline")
async def visitors_timeline_redirect():
    return RedirectResponse(url="/", status_code=301)


@router.get("/visitors/analyse")
async def visitors_analyse_redirect():
    # Must be registered before /visitors/{ip} so it isn't swallowed by the IP catch-all.
    return RedirectResponse(url="/analysis", status_code=301)


# The Humans / Not-Humans tables were removed — the unified class/signal legend on
# /visitors filters the same data inline. Old links redirect to the equivalent filter.
# Registered before /visitors/{ip} so they aren't swallowed by the IP catch-all.
@router.get("/visitors/humans")
async def visitors_humans_redirect():
    return RedirectResponse(url="/visitors?class=humans", status_code=301)


@router.get("/visitors/not-humans")
async def visitors_not_humans_redirect():
    return RedirectResponse(url="/visitors", status_code=301)


# The Requests page (scanner paths) was merged into the Path grouping — its
# 4xx-only view is ?status=4xx and its search box is ?q=. Before /visitors/{ip}.
@router.get("/visitors/requests")
async def visitors_requests_redirect(path_q: str | None = None):
    url = "/visitors?group=path&status=4xx"
    if path_q:
        url += f"&q={quote(path_q)}"
    return RedirectResponse(url=url, status_code=301)


@router.get("/tools/shodan")
async def tools_shodan_redirect(request: Request):
    return _carry("/exposure", request)


# ── Backward-compat redirects ─────────────────────────────────────────────────


@router.get("/humans")
async def humans_redirect():
    return RedirectResponse(url="/visitors?class=humans", status_code=301)


@router.get("/not-humans")
async def not_humans_redirect():
    return RedirectResponse(url="/visitors", status_code=301)


@router.get("/geo")
async def geo_redirect():
    return RedirectResponse(url="/visitors?view=map", status_code=301)


@router.get("/threats")
@router.get("/analyse")
async def analyse_redirect():
    return RedirectResponse(url="/analysis", status_code=301)


@router.get("/timeline")
async def timeline_redirect():
    # Straight to the Overview (which absorbed the Timeline page) — no 301 chain.
    return RedirectResponse(url="/", status_code=301)
