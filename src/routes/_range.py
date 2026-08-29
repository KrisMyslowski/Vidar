"""The date window: presets, resolution, and the cookie that remembers it."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Request

from ..validators import valid_date
from ._app import templates

# The range presets, once: key, span in days, tab label. The tabs used to be
# hardcoded in the range_tabs macro while the spans lived here, so adding one
# meant editing two files — and editing only one gives you either a tab that
# does nothing or a window no tab can reach. `all` spans nothing on purpose: it
# is the "no window" state, which had no tab at all before and was therefore
# indistinguishable from a window someone had chosen.
_RANGE_PRESETS = (
    ("all", None, "All"),
    ("24h", 1, "24 h"),
    ("7d", 7, "7 days"),
    ("30d", 30, "30 days"),
    ("90d", 90, "90 days"),
)
_RANGE_DAYS = {key: days for key, days, _ in _RANGE_PRESETS if days}
_RANGE_KEYS = {key for key, _, _ in _RANGE_PRESETS}
# What an untouched dashboard shows. The tab says "90 days" like its neighbours
# rather than "Default": which one is the default is visible from the tab that
# is active on arrival, while the label was the only place the span was not
# stated — the one preset a reader could not read the length of.
DEFAULT_RANGE = "90d"

templates.env.globals["RANGE_PRESETS"] = [(key, label) for key, _, label in _RANGE_PRESETS]

# Carries the chosen window from one page to the next. A session cookie: the
# selection follows you across the sidebar, and a new browser starts clean.
_RANGE_COOKIE = "vidar_range"
_CUSTOM_PREFIX = "custom:"


def _resolve_range(
    range_key: str | None,
    date_from: str | None,
    date_to: str | None,
    remembered: str | None = None,
):
    """Map ?range=… onto a date window, falling back to the remembered one.

    Returns (date_from, date_to, active_range). Explicit dates win over a preset
    and mark the range as "custom", so the Custom disclosure opens on reload.

    `remembered` is the previous page's selection (see _remembered_range). It is
    only consulted when the URL says nothing at all: a `?range=` or a date in the
    address was typed, clicked or bookmarked, and a shared link has to show the
    window it names rather than whatever this browser looked at last.

    There is no "no window" outcome any more. Nothing chosen means DEFAULT_RANGE,
    and the unbounded view is a choice of its own (`all`) — every number on every
    page is scoped to whatever comes back from here, so a silent empty window
    would mean a dashboard that claims a filter it is not applying.
    """
    if not (range_key or date_from or date_to) and remembered:
        if remembered.startswith(_CUSTOM_PREFIX):
            _, _, dates = remembered.partition(_CUSTOM_PREFIX)
            date_from, date_to = (dates.split(":", 1) + [""])[:2]
            date_from, date_to = date_from or None, date_to or None
        else:
            range_key = remembered

    # The two date inputs do not constrain each other, so From-after-To is one
    # mis-click away. Swap rather than reject: it is unambiguous what was meant,
    # and left alone it yields an empty page whose delta compares against a
    # window in the future.
    if date_from and date_to and date_from > date_to:
        date_from, date_to = date_to, date_from

    if not (date_from or date_to) and range_key not in _RANGE_KEYS:
        range_key = DEFAULT_RANGE

    if range_key == "all" and not (date_from or date_to):
        return None, None, "all"
    if range_key in _RANGE_DAYS and not (date_from or date_to):
        today = datetime.now(timezone.utc).date()
        start = today - timedelta(days=_RANGE_DAYS[range_key] - 1)
        return start.isoformat(), today.isoformat(), range_key
    return date_from, date_to, "custom"


def _previous_window(date_from: str | None, date_to: str | None):
    """The same span again, immediately before the given one.

    What the Overview's delta compares against. Returns (None, None) for the
    unbounded view — `all` has no "before", so it gets no delta rather than a
    made-up one.
    """
    if not (date_from and date_to):
        return None, None
    start = datetime.fromisoformat(date_from).date()
    end = datetime.fromisoformat(date_to).date()
    span = (end - start).days + 1
    return (start - timedelta(days=span)).isoformat(), (start - timedelta(days=1)).isoformat()


def _range_span_label(date_from: str | None, date_to: str | None) -> str:
    """ "7 days" / "24 h" for the delta caption — measured, not looked up.

    A custom window has no preset to borrow a label from, and the caption has to
    name the span it compared against either way.
    """
    if not (date_from and date_to):
        return "period"
    days = (datetime.fromisoformat(date_to).date() - datetime.fromisoformat(date_from).date()).days
    return "24 h" if days == 0 else f"{days + 1} days"


def _remembered_range(request: Request) -> str | None:
    """The window carried over from the last page, or None.

    A cookie is input like any other, and this one ends up in a SQL date filter,
    so it goes through the same gates the query string does: the key has to be a
    preset we actually offer, and both dates have to pass valid_date(). Anything
    else is dropped rather than repaired — a mangled cookie means "no memory",
    not "guess what was meant".
    """
    raw = request.cookies.get(_RANGE_COOKIE)
    if not raw:
        return None
    if raw in _RANGE_KEYS:
        return raw
    if raw.startswith(_CUSTOM_PREFIX):
        start, _, end = raw[len(_CUSTOM_PREFIX) :].partition(":")
        # An empty bound is a real state — a custom range may be open at one end.
        # A *malformed* bound is not, and keeping the half that parses would
        # silently hand back a window nobody chose.
        if all(not part or valid_date(part) for part in (start, end)) and (start or end):
            return raw
    return None


def _remember_range(response, active_range: str, date_from: str | None, date_to: str | None):
    """Store the active window so the next page opens on it. Returns `response`.

    Nothing chosen means nothing remembered — an untouched dashboard should not
    start writing cookies, and the absent cookie is what the default falls back
    to anyway.
    """
    if not active_range:
        return response
    value = (
        f"{_CUSTOM_PREFIX}{date_from or ''}:{date_to or ''}"
        if active_range == "custom"
        else active_range
    )
    # No max_age, so it dies with the browser session. No secure flag either:
    # the dashboard is reached over an SSH tunnel at http://localhost:8080, and
    # a Secure cookie on plain HTTP is a cookie the browser silently discards.
    response.set_cookie(_RANGE_COOKIE, value, httponly=True, samesite="lax", path="/")
    return response
