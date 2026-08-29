"""GET / — hero tiles, Needs attention, and the Top block."""

from __future__ import annotations

import asyncio
from urllib.parse import quote

from fastapi import APIRouter, Query, Request

from ..queries import get_daily_kpis, get_stats, get_visitor_ip_counts
from ..taxonomy import GROUP_COLOR_VARS, GROUPS_WITH_UNKNOWN, SIGNAL_COLOR_VARS
from ..validators import valid_date
from ._app import templates
from ._cache import _attention_items, _cached, fetch
from ._charts import bar_rows
from ._range import (
    _previous_window,
    _range_span_label,
    _remember_range,
    _remembered_range,
    _resolve_range,
)

router = APIRouter()


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/")
async def overview(
    request: Request,
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
):
    """Dashboard home: triage first, numbers second.

    Two rows of tiles, the class mix, Needs attention (the findings worth acting
    on), and the Top panel. The activity chart and the traffic-rhythm heatmap
    moved to /visitors?view=timeline, where they answer for the page's filters
    instead of always for everything.
    """
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    date_from, date_to, active_range = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )
    # The window the tiles compare against: the same span, immediately before.
    prev_from, prev_to = _previous_window(date_from, date_to)

    def _load(conn):
        """All of the Overview's DB work.

        Every cache key carries the window. It did not, back when `stats` and
        `kpis` were all-time — now that they answer for a range, a shared key
        would hand the first caller's window to everyone else for 60 seconds.
        """
        window = f"{date_from or ''}:{date_to or ''}"
        return (
            # The most expensive block on the page, and the least time-sensitive.
            _cached(f"stats:{window}", lambda: get_stats(conn, since=date_from, until=date_to)),
            _cached(
                f"kpis:{window}", lambda: get_daily_kpis(conn, since=date_from, until=date_to)
            ),
            get_visitor_ip_counts(conn, date_from, date_to),
            (
                _cached(
                    f"prev-visits:{prev_from or ''}:{prev_to or ''}",
                    lambda: sum(
                        k["visits"] for k in get_daily_kpis(conn, since=prev_from, until=prev_to)
                    ),
                )
                if prev_from
                else 0
            ),
        )

    stats, kpis, visitor_counts, prev_visits = await fetch(_load)
    attention = await asyncio.to_thread(_attention_items)
    # Each finding carries a taxonomy/signal key; the color comes from the same
    # single source every other surface uses.
    _finding_colors = {
        "threats": GROUP_COLOR_VARS["threats"],
        "tor": SIGNAL_COLOR_VARS["is_tor"],
        "hosting": SIGNAL_COLOR_VARS["is_hosting"],
        "dnsbl": SIGNAL_COLOR_VARS["dnsbl_listed"],
    }
    for item in attention:
        item["color"] = _finding_colors.get(item["signal"], GROUP_COLOR_VARS["unknown"])
    spark_visits = ",".join(str(k["visits"]) for k in kpis)
    spark_errors = ",".join(
        str(round(k["errors"] / k["visits"] * 100, 1)) if k["visits"] else "0" for k in kpis
    )
    spark_bytes = ",".join(str(k["bytes"]) for k in kpis)
    # The delta compares the window against the same span immediately before it,
    # and says which span that was. It used to be a fixed "vs prior week" no
    # matter what the reader had selected, which was simply a different claim
    # from the number above it.
    visits_delta = ""
    if prev_visits:
        pct = round((stats["total_visits"] - prev_visits) / prev_visits * 100)
        arrow = "\u2197" if pct > 0 else ("\u2198" if pct < 0 else "\u2192")
        visits_delta = f"{arrow} {pct:+d}% vs previous {_range_span_label(date_from, date_to)}"
    return _remember_range(
        templates.TemplateResponse(
            request,
            "overview.html",
            {
                **stats,
                "spark_visits": spark_visits,
                "spark_errors": spark_errors,
                "spark_bytes": spark_bytes,
                "visits_delta": visits_delta,
                "attention": attention,
                "threat_ips": visitor_counts.get("threats", 0),
                # Top-N lists as bar rows — label, bar, count (the release UI's
                # distribution primitive), one dict per tab.
                "top_rows": {
                    "countries": bar_rows(
                        stats["top_countries"],
                        "country_code",
                        "count",
                        href=lambda i: f"/visitors?country={quote(i['country_code'] or '')}",
                    ),
                    "pages": bar_rows(
                        stats["top_pages"],
                        "path",
                        "count",
                        href=lambda i: f"/visitors?path={quote(i['path'] or '')}",
                    ),
                    "referrers": bar_rows(stats["top_referrers"], "domain", "count"),
                    "browsers": bar_rows(
                        stats["top_browsers"],
                        "browser",
                        "count",
                        href=lambda i: f"/visitors?browser={quote(i['browser'] or '')}",
                    ),
                    "oses": bar_rows(stats["top_oses"], "os", "count"),
                },
                # "Who is hitting the site" — the same five groups as everywhere else.
                "class_mix": [
                    {
                        "label": group.title(),
                        "count": visitor_counts.get(group, 0),
                        "color": GROUP_COLOR_VARS[group],
                        "href": f"/visitors?class={group}",
                    }
                    for group in GROUPS_WITH_UNKNOWN
                ],
                "active_range": active_range,
                "date_from": date_from or "",
                "date_to": date_to or "",
            },
        ),
        active_range,
        date_from,
        date_to,
    )
