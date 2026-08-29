"""GET /analysis and GET /exposure."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Query, Request

from ..queries import (
    count_shodan_hosts,
    get_analysis_data,
    get_identity_signal_matrix,
    get_rate_limit_timeline,
    get_shodan_hosts,
    get_top_ports,
    get_top_tags,
    get_top_vulns,
    seen_in_window,
)
from ..taxonomy import GROUP_COLOR_VARS
from ..validators import valid_date
from ._app import templates
from ._cache import fetch
from ._charts import bar_rows, day_rows
from ._helpers import total_pages
from ._range import _RANGE_KEYS, _remember_range, _remembered_range, _resolve_range

router = APIRouter()


@router.get("/analysis")
async def analysis(
    request: Request,
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
):
    """Analysis: identity×signal matrix, distribution cards, rate limits, diagnostics.

    The range scopes everything on the page, the matrix included: its cells are
    IP counts, so a window means the IPs seen in it. The cells link into
    /visitors, and one that offers more IPs than the list behind it is worse
    than no cell at all.
    """
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    date_from, date_to, active_range = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )
    data, identity_signal_matrix, rl_days = await fetch(
        lambda conn: (
            get_analysis_data(conn, since=date_from, until=date_to),
            get_identity_signal_matrix(conn, since=date_from, until=date_to),
            get_rate_limit_timeline(conn, since=date_from, until=date_to),
        )
    )

    status = data.get("status_dist") or {}
    cards = [
        {
            "title": "Status codes",
            "note": "click a bar to filter Visitors by status",
            "color": GROUP_COLOR_VARS["humans"],
            "rows": [
                {
                    "label": band,
                    "value": status.get(f"s{band}") or 0,
                    "href": f"/visitors?group=path&status={band}",
                }
                for band in ("2xx", "3xx", "4xx", "5xx")
                if status.get(f"s{band}")
            ],
        },
        {
            "title": "Unusual methods",
            "note": "anything other than GET, POST, HEAD",
            "color": GROUP_COLOR_VARS["bots"],
            "rows": [
                {"label": m["method"], "value": m["count"]}
                for m in (data.get("unusual_methods") or [])
            ],
        },
        {
            "title": "HTTP version",
            "note": "HTTP/1.0 is a strong bot signal",
            "color": GROUP_COLOR_VARS["automated"],
            "rows": [
                {"label": v["http_version"], "value": v["count"]}
                for v in (data.get("http_version_dist") or [])
            ],
        },
    ]
    rl = data.get("rl_stats") or {}
    return _remember_range(
        templates.TemplateResponse(
            request,
            "analysis.html",
            {
                "date_from": date_from or "",
                "date_to": date_to or "",
                "active_range": active_range,
                "identity_signal_matrix": identity_signal_matrix,
                "cards": cards,
                "rl_days": day_rows(rl_days),
                "rl_series": [
                    {"key": "rejected", "label": "Rejected", "color": GROUP_COLOR_VARS["threats"]},
                    {"key": "delayed", "label": "Delayed", "color": GROUP_COLOR_VARS["automated"]},
                ],
                "rl_rows": bar_rows(
                    data.get("rl_top_ips") or [],
                    "ip",
                    "rl_count",
                    href=lambda i: f"/visitors/{i['ip']}",
                ),
                "rl_summary": " · ".join(
                    filter(
                        None,
                        [
                            f"{rl.get('rl_rejected') or 0:,} rejected",
                            f"{rl.get('rl_delayed') or 0:,} delayed",
                        ],
                    )
                ),
                **data,
            },
        ),
        active_range,
        date_from,
        date_to,
    )


@router.get("/exposure")
async def exposure(
    request: Request,
    page: int = Query(default=1, ge=1),
    port: int | None = Query(default=None, ge=1, le=65535),
    vuln: str | None = Query(default=None, max_length=128),
    tag: str | None = Query(default=None, max_length=64),
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
):
    """Exposure: Shodan InternetDB facets over the visiting IPs, plus the host table.

    The facets and the table share one filter state — the port/vuln/tag filters
    narrow both, so a facet always describes the host set below it. The range
    narrows the same set once more: shown are the hosts that were actually here
    during the window, with their visit counts measured inside it. This page had
    no range control at all and was the one surface where the window did not
    apply.
    """
    limit = 25
    vuln = (vuln or "").strip() or None
    tag = (tag or "").strip() or None
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    date_from, date_to, active_range = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )
    facet_args = {
        "port": port,
        "vuln": vuln,
        "tag": tag,
        "since": date_from,
        "until": date_to,
    }

    def _load(conn):
        seen, seen_params = seen_in_window("ip_intel.ip", date_from, date_to)
        return (
            get_shodan_hosts(
                conn,
                page=page,
                limit=limit,
                port=port,
                vuln=vuln,
                tag=tag,
                since=date_from,
                until=date_to,
            ),
            count_shodan_hosts(
                conn, port=port, vuln=vuln, tag=tag, since=date_from, until=date_to
            ),
            count_shodan_hosts(conn, since=date_from, until=date_to),
            # "X of Y IPs enriched" — Y has to be scoped as well, or the ratio
            # compares a windowed numerator against an all-time denominator.
            conn.execute(
                f"SELECT COUNT(*) FROM ip_intel{f' WHERE {seen}' if seen else ''}", seen_params
            ).fetchone()[0],
            get_top_ports(conn, **facet_args),
            get_top_vulns(conn, **facet_args),
            get_top_tags(conn, **facet_args),
        )

    hosts, total, total_all, enriched_ips, top_ports, top_vulns, top_tags = await fetch(_load)

    active = {"port": port, "vuln": vuln, "tag": tag}
    # The window rides in every link this page builds. Same trap as params["range"]
    # on /visitors: without it, clicking a facet silently widens the time window
    # back to the default.
    range_link = {
        "range": active_range if active_range in _RANGE_KEYS else "",
        "date_from": date_from if active_range == "custom" else "",
        "date_to": date_to if active_range == "custom" else "",
    }

    def _exposure_url(**overrides) -> str:
        merged = {**active, **range_link, **overrides}
        parts = [f"{k}={quote(str(v))}" for k, v in merged.items() if v]
        return "/exposure" + ("?" + "&".join(parts) if parts else "")

    _pill_colors = {
        "port": GROUP_COLOR_VARS["bots"],
        "tag": GROUP_COLOR_VARS["humans"],
        "vuln": GROUP_COLOR_VARS["threats"],
    }
    pills = [
        {"kind": label, "value": str(active[key]), "href": _exposure_url(**{key: None})}
        for key, label in (("port", "Port"), ("tag", "Tag"), ("vuln", "CVE"))
        if active[key]
    ]
    filter_chips = [
        {"label": f"{label} {active[key]}", "color": _pill_colors[key]}
        for key, label in (("port", "Port"), ("tag", "Tag"), ("vuln", "CVE"))
        if active[key]
    ]
    return _remember_range(
        templates.TemplateResponse(
            request,
            "exposure.html",
            {
                "hosts": hosts,
                "total": total,
                "total_all": total_all,
                "enriched_ips": enriched_ips,
                "page": page,
                "total_pages": total_pages(total, limit),
                "active_filter": active,
                "pills": pills,
                "filter_chips": filter_chips,
                "active_range": active_range,
                "date_from": date_from or "",
                "date_to": date_to or "",
                # Clearing the value filters keeps the window: the range tabs are
                # their own control, exactly as on /visitors.
                "clear_href": _exposure_url(port=None, vuln=None, tag=None),
                "range_params": "".join(f"&{k}={quote(str(v))}" for k, v in active.items() if v),
                # The window alone, for links built inside macros that cannot
                # see the route's params (the tag badges in the host table).
                "range_suffix": "".join(
                    f"&{k}={quote(str(v))}" for k, v in range_link.items() if v
                ),
                "pager_params": "".join(
                    f"&{k}={quote(str(v))}" for k, v in {**active, **range_link}.items() if v
                ),
                "facets": [
                    {
                        "title": "Open ports",
                        "note": "click to add a port filter",
                        "param": "port",
                        "entries": top_ports,
                        "active": str(port) if port else "",
                        "color": GROUP_COLOR_VARS["bots"],
                    },
                    {
                        "title": "Tags",
                        "note": "Shodan classification of the host itself",
                        "param": "tag",
                        "entries": top_tags,
                        "active": tag or "",
                        "color": GROUP_COLOR_VARS["humans"],
                    },
                    {
                        "title": "CVEs",
                        "note": "known-vulnerable services on visiting IPs",
                        "param": "vuln",
                        "entries": top_vulns,
                        "active": vuln or "",
                        "color": GROUP_COLOR_VARS["threats"],
                    },
                ],
                "facet_urls": {
                    p: {str(i["value"]): _exposure_url(**{p: i["value"]}) for i in items}
                    for p, items in (
                        ("port", top_ports),
                        ("tag", top_tags),
                        ("vuln", top_vulns),
                    )
                },
                "facet_clear_urls": {
                    p: _exposure_url(**{p: None}) for p in ("port", "tag", "vuln")
                },
            },
        ),
        active_range,
        date_from,
        date_to,
    )
