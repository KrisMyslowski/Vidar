"""Helpers shared across route modules."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import RedirectResponse


def total_pages(total: int, limit: int) -> int:
    """Number of pages needed for `total` items at `limit` per page (minimum 1)."""
    return max(1, (total + limit - 1) // limit)


def past_the_last_page(request: Request, page: int, total: int, limit: int):
    """A redirect to the last page when `page` is beyond it, else None.

    Past the end, a page rendered an empty table under a header still stating
    the real total. /incidents/case clamps in place, because it is a fragment
    with no address bar; a page has one, so it is sent to the page it meant and
    the URL says so. Everything else in the query string is kept.
    """
    last = total_pages(total, limit)
    if page <= last:
        return None
    url = request.url.include_query_params(page=last)
    return RedirectResponse(f"{url.path}?{url.query}", status_code=302)
