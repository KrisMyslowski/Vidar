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
from ..queries.analysis import get_exposures, get_probe_echo
from ..validators import valid_date
from ._app import templates
from ._cache import fetch
from ._range import _remember_range, _remembered_range, _resolve_range

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
):
    """Paths that answered 2xx and that no benign visitor ever asked for.

    An empty table is the expected result and the good one — the page says so
    rather than showing an empty table and letting the reader guess whether the
    feature works.
    """
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    date_from, date_to, active_range = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )

    def _load(conn):
        return (
            get_exposures(conn, date_from, date_to),
            get_probe_echo(conn, date_from, date_to),
        )

    findings, echo = await fetch(_load)
    host = _site_host()
    paths = [f["path"] for f in findings]
    families = explain_paths(paths, host)
    # The table marks which rows an explanation covers, by title. One lookup
    # here rather than a second family_for() call per row in the template.
    titles = {path: family.title for family, paths in families for path in paths}
    for finding in findings:
        finding["family_title"] = titles.get(finding["path"], "")

    return _remember_range(
        templates.TemplateResponse(
            request,
            "exposure.html",
            {
                "findings": findings,
                # Summed from the rows the page is showing rather than queried
                # again: a second query for them could disagree with the table.
                "totals": {
                    "ips": sum(f["ips"] for f in findings),
                    "bytes_sent": max((f["bytes_sent"] or 0 for f in findings), default=0),
                },
                "described": sum(1 for f in findings if f["family_title"]),
                "families": families,
                "unexplained": unexplained_paths(paths, host),
                "echo": echo,
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
