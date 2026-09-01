"""URL building — the visitors URL family and the parameters that carry."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse

from ._range import _RANGE_KEYS


def _form_fields(params: dict, owns: tuple[str, ...]) -> list[tuple[str, str]]:
    """Hidden inputs that carry the rest of the selection through a GET form.

    Built from the same `params` dict `_visitors_url` uses for every link, so
    submitting a form and clicking a link carry identical state. Before this the
    forms kept their own short list and silently dropped everything else: pressing
    Enter in the search box discarded the status band and every drill-down, so a
    search inside a drill-down widened the result instead of narrowing it.

    `owns` names the fields the form supplies itself. Empty values are skipped —
    otherwise every submitted URL grew a stray `?group=&view=`.
    """
    fields: list[tuple[str, str]] = []
    for key, value in params.items():
        if key in owns or not value:
            continue
        if isinstance(value, (list, tuple)):
            fields.extend((key, str(v)) for v in value if v)
        else:
            fields.append((key, str(value)))
    return fields


def _visitors_url(
    params: dict,
    drop: str | None = None,
    drop_value: tuple[str, str] | None = None,
    **overrides,
) -> str:
    """Build a /visitors URL from the active params.

    drop removes one param, drop_value removes a single value from a multi-value
    one (?class= and ?signal= carry several, and a pill removes its own value,
    not the whole selection), overrides replace others (tab links). Empty values
    are omitted so the URL only ever carries what is actually set — including 0,
    which is "unset" for every parameter this page has (min_visits=0 and port=0
    would otherwise come back as an active filter pill).
    """
    merged = {k: v for k, v in params.items() if k != drop}
    if drop_value:
        key, value = drop_value
        merged[key] = [v for v in merged.get(key) or [] if v != value]
    merged.update(overrides)
    parts: list[str] = []
    for key, value in merged.items():
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            parts.extend(f"{key}={quote(str(v))}" for v in value)
        else:
            parts.append(f"{key}={quote(str(value))}")
    return "/visitors" + ("?" + "&".join(parts) if parts else "")


def window_params(active_range: str, date_from: str | None, date_to: str | None) -> str:
    """The active window as a URL tail, for pages whose only other state is it.

    `sortable_th` builds `?page=1&sort=…&order=…` and appends this, so anything
    missing here is dropped by a click on a column header — and the row drawer on
    /exposure appends it too, because a panel that counted a different window
    than the row that opened it would be a second answer to one question.

    /visitors has no use for this: it carries a dozen parameters and builds them
    from its own `params` dict. Exposure and Incidents carry the window and
    nothing else, and each had its own copy of this — one of them even under a
    different name.
    """
    if active_range in _RANGE_KEYS:
        return f"&range={quote(active_range)}"
    return "".join(
        f"&{k}={quote(v)}" for k, v in (("date_from", date_from), ("date_to", date_to)) if v
    )


def window_fields(sort: str, order: str) -> list[tuple[str, str]]:
    """Hidden inputs the Custom-range form needs, so submitting it keeps the sort.

    The form is a GET to the bare path: whatever it does not carry is gone. The
    macro says the rule for the pages that already had state — "the custom range
    must not silently drop the class/signal selection, the drill-downs or the
    search term" — and Exposure and Incidents joined that club the moment their
    columns became sortable.

    The page's *first* sortable table. Exposure has a second one below it and
    appends its two fields to this; a caller with more state than one order to
    keep carries the rest itself.
    """
    return [("sort", sort), ("order", order)]


# Parameters a legacy URL may carry over to its successor. Anything outside this
# set (page, sort, and the grouping/view the target already fixes) is dropped —
# but a filter must survive, or an old bookmark silently widens what you see.
_CARRIED_PARAMS = (
    "class",
    "signal",
    "date_from",
    "date_to",
    "range",
    "q",
    "country",
    "ip",
    "min_visits",
    "asn",
    "path",
    "browser",
    "status",
    "seen",
    # Exposure's own filters — meaningless on /visitors, but a legacy
    # /tools/shodan link carries them and must not lose them on the way.
    "port",
    "vuln",
    "tag",
)


def _carry(target: str, request: Request, extra: str = "") -> RedirectResponse:
    """301 to `target`, keeping the filters the incoming URL carried."""
    parts = [extra] if extra else []
    for key in _CARRIED_PARAMS:
        parts.extend(f"{key}={quote(v)}" for v in request.query_params.getlist(key) if v)
    sep = "&" if "?" in target else "?"
    url = target + (sep + "&".join(parts) if parts else "")
    return RedirectResponse(url=url, status_code=301)
