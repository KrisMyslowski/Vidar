"""GET /exposure — what this site gave away.

Every other surface describes visitors. This one describes what they got, which
is the operator's own attack surface as reported daily by the people probing it.
No new data is collected: it is the same `visits` table read in the other
direction.

A finding on its own is a fright. `src/families.py` supplies the other half —
what the file is, why it was asked for, how to check it and how to stop serving
it — and the page carries both, because a list of paths nobody can act on is
not help.
"""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Query, Request

from ..config import settings
from ..families import explain_paths, unexplained_paths
from ..queries.analysis import get_exposure_detail, get_exposures, get_probe_echo, get_served_paths
from ..validators import valid_choice, valid_date, valid_order, valid_search
from ._app import templates
from ._cache import fetch
from ._filters import (
    EXPOSURE_DEFAULT_SORT,
    EXPOSURE_SORTS,
    SERVED_DEFAULT_SORT,
    SERVED_SORTS,
    apply_sort,
)
from ._range import _remember_range, _remembered_range, _resolve_range
from ._urls import window_fields, window_params

router = APIRouter()

# What the check commands are addressed to. Blank is a supported state — the
# three site settings ship unset — and it must stay obviously blank rather than
# resolve to something that reads like a real host.
_PLACEHOLDER_HOST = "your-site.example"


def _site_host() -> str:
    return urlparse(settings.site_base_url).netloc or _PLACEHOLDER_HOST


@router.get("/exposure")
async def exposure(
    request: Request,
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
    sort: str = "",
    order: str = "DESC",
    vsort: str = "",
    vorder: str = "ASC",
):
    """Paths that answered 2xx and that no benign visitor ever asked for.

    An empty table is the expected result and the good one — the page says so
    rather than showing an empty table and letting the reader guess whether the
    feature works.
    """
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    sort = valid_choice(sort, frozenset(EXPOSURE_SORTS), EXPOSURE_DEFAULT_SORT)
    order = valid_order(order)
    # Served has its own parameters, so ordering one block does not reorder the
    # other. Two tables on one URL cannot share a `sort`.
    vsort = valid_choice(vsort, frozenset(SERVED_SORTS), SERVED_DEFAULT_SORT)
    vorder = valid_order(vorder)
    date_from, date_to, active_range = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )

    def _load(conn):
        # One result set for both blocks. The findings are the rows of `served`
        # that nothing legitimate asked for, and deriving them here rather than
        # querying twice is what keeps the two tables from disagreeing about a
        # number they share.
        return (
            get_served_paths(conn, date_from, date_to),
            get_probe_echo(conn, date_from, date_to),
        )

    served, echo = await fetch(_load)
    findings = [f for f in served if f["is_finding"]]
    host = _site_host()
    paths = [f["path"] for f in findings]
    families = explain_paths(paths, host)
    # The table marks which rows an explanation covers, by title. One lookup
    # here rather than a second family_for() call per row in the template.
    titles = {path: e.family.title for e in families for path in e.paths}
    for finding in findings:
        finding["family_title"] = titles.get(finding["path"], "")
    # After the family title, because Family is one of the sortable columns; and
    # over the whole list, because there is no pager to slice ahead of.
    findings = apply_sort(findings, EXPOSURE_SORTS, sort, order, EXPOSURE_DEFAULT_SORT)

    return _remember_range(
        templates.TemplateResponse(
            request,
            "exposure.html",
            {
                "findings": findings,
                "served": apply_sort(served, SERVED_SORTS, vsort, vorder, SERVED_DEFAULT_SORT),
                # Summed from the rows the page is showing rather than queried
                # again: a second query for them could disagree with the table.
                "totals": {
                    "ips": sum(f["ips"] for f in findings),
                    # None, not 0, with nothing to take a maximum over: fmtbytes
                    # renders that as an em dash rather than as a response that
                    # was measured and found to be empty.
                    "bytes_sent": max((f["bytes_sent"] or 0 for f in findings), default=None),
                },
                "described": sum(1 for f in findings if f["family_title"]),
                "families": families,
                "unexplained": unexplained_paths(paths, host),
                "echo": echo,
                "active_range": active_range,
                "date_from": date_from or "",
                "date_to": date_to or "",
                "sort": sort,
                "order": order,
                "vsort": vsort,
                "vorder": vorder,
                # The sort rides along, so picking a range does not silently
                # reorder the table back to the default.
                "range_params": f"&sort={sort}&order={order}&vsort={vsort}&vorder={vorder}",
                "sort_params": window_params(active_range, date_from, date_to),
                # So submitting a custom range keeps the sort instead of
                # silently falling back to the default.
                "range_fields": window_fields(sort, order)
                + [("vsort", vsort), ("vorder", vorder)],
            },
        ),
        active_range,
        date_from,
        date_to,
    )


@router.get("/exposure/finding")
async def exposure_finding(
    request: Request,
    path: str = "",
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
):
    """HTML fragment: one finding in full, for the slide-over.

    The findings table lists; this decides. General info first — is it still
    being served, what did the server answer, how big, when, how often, by whom,
    from where — then the same what/why/check/fix the family registry carries,
    which is where per-path advice now lives.

    **The spellings are re-derived here, not passed in.** A finding is the fold
    of every percent-encoded way one resource was asked for, and the fold lives
    in the query layer. Taking a spelling list from the URL would put it in two
    places, and the panel could then describe a different set of requests than
    the row that opened it. So the same query runs, the same fold happens, and
    the row is looked up by its canonical path.
    """
    path = valid_search(path) or ""
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    date_from, date_to, _ = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )

    def _load(conn):
        finding = next(
            (f for f in get_exposures(conn, date_from, date_to) if f["path"] == path), None
        )
        if finding is None:
            return None, {}
        return finding, get_exposure_detail(conn, finding["spellings"], date_from, date_to)

    finding, detail = await fetch(_load)
    if finding is None:
        # Not a 404: the drawer renders whatever comes back, and a status page
        # inside a slide-over reads as a broken panel rather than as an answer.
        return templates.TemplateResponse(
            request, "_exposure_finding.html", {"finding": None, "detail": {}, "family": None}
        )

    host = _site_host()
    explained = explain_paths([finding["path"]], host)
    return templates.TemplateResponse(
        request,
        "_exposure_finding.html",
        {
            "finding": finding,
            "detail": detail,
            "family": explained[0] if explained else None,
            # The one piece of advice that needs no knowledge of the file, for a
            # finding no family describes.
            "generic_check": (
                unexplained_paths([finding["path"]], host)[0][1] if not explained else ""
            ),
        },
    )
