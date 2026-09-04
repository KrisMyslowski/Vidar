"""GET /report — one month, stated rather than displayed.

The rest of the dashboard answers questions somebody came to ask. This answers
the one nobody thought to: *what was last month*. It is the same figures the
pages beside it carry — see src/report.py for why it computes none of its own —
arranged as prose with the tables underneath, and downloadable as Markdown so it
can leave the machine it was generated on.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from ..report import available_months, build_report
from ..report_text import render_markdown
from ..taxonomy import GROUP_COLOR_VARS
from ._app import templates
from ._cache import _cached, fetch

router = APIRouter()


@router.get("/report")
async def report(
    request: Request,
    month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$"),
    format: str = Query(default="html", pattern="^(html|md)$"),
):
    """The report for one month, as a page or as Markdown.

    The month is picked from what the database still holds rather than from a
    calendar: retention moves whole months out to a zip, and a report for an
    archived month would render as a month in which nothing happened. With none
    given it is the most recent month with traffic — which is the month somebody
    opening this page means.
    """

    def _load(conn):
        # The month list first, and the report only if the month is one of them:
        # building a report for the default and then rejecting the request would
        # spend half a second on an answer nobody receives.
        months = available_months(conn)
        if not months or (month and month not in months):
            return months, None
        return months, build_report(conn, month or months[0], cache=_cached)

    months, data = await fetch(_load)
    if data is None and months and month:
        raise HTTPException(status_code=404, detail=f"No visits stored for {month}")
    if data is None:
        # No month has traffic. Not an error and not an empty report: the page
        # says the log has not been read yet, which is a different sentence and
        # the one that names the actual problem.
        if format == "md":
            raise HTTPException(status_code=404, detail="No month has any traffic yet")
        return templates.TemplateResponse(request, "report.html", {"months": [], "report": None})

    if format == "md":
        return PlainTextResponse(
            render_markdown(data),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="vidar-{data["month"]}.md"'},
        )
    return templates.TemplateResponse(
        request,
        "report.html",
        {"months": months, "report": data, "GROUP_COLOR_VARS": GROUP_COLOR_VARS},
    )
