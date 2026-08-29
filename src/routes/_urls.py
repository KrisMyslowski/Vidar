"""URL building — the visitors URL family and the parameters that carry."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse


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
