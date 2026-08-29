"""GET /visitors and its /visitors/rows fragment — every visitor surface."""

from __future__ import annotations

from functools import partial
from urllib.parse import quote

from fastapi import APIRouter, Query, Request

from .. import search
from ..config import settings
from ..queries import (
    count_visitors_grouped,
    get_activity_timeline,
    get_geo_data,
    get_hourly_heatmap,
    get_visitor_ip_counts,
    get_visitors_grouped,
)
from ..taxonomy import GROUP_COLOR_VARS, SIGNAL_COLOR_VARS, SIGNAL_LABELS, VISITOR_CATEGORIES
from ..validators import (
    valid_choice,
    valid_country,
    valid_date,
    valid_ip,
    valid_min_visits,
    valid_order,
    valid_port,
    valid_search,
)
from ._app import templates
from ._cache import fetch
from ._charts import ACTIVITY_SERIES, HOUR_SWITCH_DAYS, build_heatmap_grid, day_rows, pick_bucket
from ._filters import _DRILL_KINDS, _GROUP_SPECS, _build_filter_context, _normalize_filters
from ._helpers import total_pages
from ._range import _RANGE_KEYS, _remember_range, _remembered_range, _resolve_range
from ._urls import _form_fields, _visitors_url

router = APIRouter()


@router.get("/visitors")
async def visitors(
    request: Request,
    group: str = "ip",
    view: str = "table",
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=500),
    sort: str = "",
    order: str = "DESC",
    country: str | None = None,
    ip: str | None = None,
    active_classes: list[str] = Query(default=[], alias="class"),
    signal_filter: list[str] = Query(default=[], alias="signal"),
    min_visits: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    range_key: str | None = Query(default=None, alias="range"),
    port: str | None = None,
    asn: str | None = None,
    path: str | None = None,
    browser: str | None = None,
    q: str | None = None,
    status: str | None = None,
):
    """Visitors — the one visitor surface.

    ?group= picks the grouping (ip / asn / country / client / path), ?view= picks
    table, map or timeline. All dispatch onto the existing query pairs; `ip` uses
    the exact-match drill-down filters (asn/path/browser/country/port), the four
    aggregations use ?q= free-text search. Every drill-down renders as a
    removable pill in the filter rail, and the class/signal selection carries
    across all three views.
    """
    group = group if group in _GROUP_SPECS else "ip"
    view = view if view in ("table", "map", "timeline") else "table"
    spec = _GROUP_SPECS[group]

    sort = valid_choice(sort, spec["sorts"], spec["default_sort"])
    order = valid_order(order)
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    date_from, date_to, active_range = _resolve_range(
        range_key, date_from, date_to, _remembered_range(request)
    )
    # The window decides the activity chart's resolution. On a 24-hour range a
    # daily axis is a single point, and no amount of zooming recovers hours from
    # it — a drag inside one bucket has nothing to open.
    activity_bucket = pick_bucket(date_from, date_to)
    country = valid_country(country)
    ip = valid_ip(ip)
    min_visits_int = valid_min_visits(min_visits)
    port_int = valid_port(port)
    asn = valid_search(asn)
    path = valid_search(path)
    browser = valid_search(browser)
    q = valid_search(q)
    status = valid_choice(status, frozenset({"2xx", "3xx", "4xx", "5xx"}), "") or None
    # Only the Path grouping has a status band to filter on. Carrying ?status=
    # into any other grouping would render a pill for a filter that changes
    # nothing — the UI must not claim a narrowing it does not perform.
    if group != "path":
        status = None
    # Same rule for the map: get_geo_data narrows by class, signal, country,
    # min_visits and the date window. The row-level drill-downs reach no query
    # there, so they must not survive into it as pills either.
    if view == "map":
        ip = asn = path = browser = None
        port_int = 0
    active_classes, signal_filter = _normalize_filters(active_classes, signal_filter)

    # Everything that survives a tab click, a sort, or a page turn.
    params = {
        "group": group if group != "ip" else "",
        "view": view if view != "table" else "",
        "class": active_classes,
        "signal": signal_filter,
        "country": country or "",
        "ip": ip or "",
        "min_visits": min_visits_int or "",
        "port": port_int or "",
        "asn": asn or "",
        "path": path or "",
        "browser": browser or "",
        "q": q or "",
        "status": status or "",
        # active_range, not range_key: the window may come from the cookie
        # rather than the query string, and every link this dict builds — sort,
        # pager, drill-down — has to name the window it was built under.
        "range": active_range if active_range in _RANGE_KEYS else "",
        "date_from": date_from if active_range == "custom" else "",
        "date_to": date_to if active_range == "custom" else "",
    }

    def _load(conn):
        rows: list[dict] = []
        markers: list[dict] = []
        geo_stats: dict = {}
        activity: list[dict] = []
        heatmap: tuple[list[dict], dict[str, int]] = ([], {})
        total = 0
        if view == "map":
            markers, geo_stats = get_geo_data(
                conn,
                class_filter=active_classes or None,
                signal_filter=signal_filter or None,
                country=country,
                min_visits=min_visits_int,
                date_from=date_from,
                date_to=date_to,
                q=q,
            )
            total = len(markers)
        elif view == "timeline":
            activity = get_activity_timeline(
                conn,
                since=date_from,
                until=date_to,
                class_filter=active_classes or None,
                signal_filter=signal_filter or None,
                bucket=activity_bucket,
                q=q,
            )
            # The same selection, folded onto weekday × hour instead of a date
            # axis. Deliberately not cached the way the Overview cached it: the
            # key would have to carry every filter, and the point of this view is
            # that changing a filter changes what it shows.
            heatmap = build_heatmap_grid(
                get_hourly_heatmap(
                    conn,
                    since=date_from,
                    until=date_to,
                    class_filter=active_classes or None,
                    signal_filter=signal_filter or None,
                    q=q,
                )
            )
            total = sum(d["total"] for d in activity)
        elif group == "ip":
            rows = get_visitors_grouped(
                conn,
                page,
                limit,
                sort,
                order,
                country,
                ip,
                active_classes,
                signal_filter,
                min_visits_int,
                date_from,
                date_to,
                port_filter=port_int,
                asn_filter=asn,
                path_filter=path,
                browser_filter=browser,
                q=q,
            )
            total = count_visitors_grouped(
                conn,
                country,
                ip,
                active_classes,
                signal_filter,
                min_visits_int,
                date_from,
                date_to,
                port_filter=port_int,
                asn_filter=asn,
                path_filter=path,
                browser_filter=browser,
                q=q,
            )
        else:
            get_fn, count_fn = spec["get"], spec["count"]
            if group == "path":
                get_fn = partial(get_fn, status=status)
                count_fn = partial(count_fn, status=status)
            rows = get_fn(
                conn,
                page,
                limit,
                sort,
                order,
                active_classes,
                signal_filter,
                date_from,
                date_to,
                q=q,
            )
            total = count_fn(conn, active_classes, signal_filter, date_from, date_to, q=q)
        return (
            rows,
            markers,
            geo_stats,
            activity,
            heatmap,
            total,
            get_visitor_ip_counts(conn, date_from, date_to),
        )

    rows, markers, geo_stats, activity, heatmap, total, visitor_counts = await fetch(_load)
    heatmap_grid, heatmap_max = heatmap

    # Sort links and the pager carry the full filter state minus what they set.
    sort_suffix = _visitors_url(params, drop="page")[len("/visitors") :].replace("?", "&", 1)
    pager_params = f"&sort={sort}&order={order}{sort_suffix}"
    # A range preset replaces the date window but must keep everything else —
    # picking "7 days" is not a request to drop the class and signal selection.
    range_params = _visitors_url(params, page="", range="", date_from="", date_to="")[
        len("/visitors") :
    ].replace("?", "&", 1)
    # The slide-over inherits only the class/signal/date selection — never the
    # grouping or a drill-down, since the clicked row *is* the drill-down.
    # What the activity chart carries into its own requests: the selection, but
    # not the date window — the chart sets that from whatever the reader zoomed
    # into, and it is narrower than the page's range by definition.
    chart_params = "".join(
        f"&{k}={quote(str(v))}"
        for k, vals in (
            ("class", active_classes),
            ("signal", signal_filter),
            # Without this the chart's own hourly refetch would drop the search.
            ("q", [q] if q else []),
        )
        for v in vals
    )
    rows_params = "".join(
        f"&{k}={quote(str(v))}"
        for k, vals in (
            ("class", active_classes),
            ("signal", signal_filter),
            ("date_from", [date_from] if date_from else []),
            ("date_to", [date_to] if date_to else []),
            # The search is part of the selection the drawer inherits, like the
            # class/signal/date filters — the clicked row supplies the dimension.
            ("q", [q] if q else []),
        )
        for v in vals
    )

    # Everything that narrows the result gets a pill. A class or signal was only
    # ever visible as a highlighted chip — and a signal not even that, since its
    # chips live inside a closed menu — so a filtered page could not be told
    # from an empty one without hunting for what was still switched on.
    active_filter_chips = [
        {
            "label": c.split("/")[-1].replace("-", " ").title(),
            "color": GROUP_COLOR_VARS.get(c.split("/")[0], GROUP_COLOR_VARS["unknown"]),
            "kind": "Class",
            "value": c,
        }
        for c in active_classes
    ] + [
        {
            "label": SIGNAL_LABELS[sig],
            "color": SIGNAL_COLOR_VARS[sig],
            "kind": "Signal",
            "value": sig,
        }
        for sig in signal_filter
    ]
    search_terms, unknown_fields = search.parse(q)
    drill = (
        [
            {
                "kind": label,
                "value": params[key],
                "href": _visitors_url(params, drop=key),
            }
            for key, label in _DRILL_KINDS
            if params.get(key)
        ]
        + [
            {
                "kind": chip["kind"],
                "value": chip["label"],
                "color": chip["color"],
                "href": _visitors_url(
                    params,
                    drop_value=("class" if chip["kind"] == "Class" else "signal", chip["value"]),
                ),
            }
            for chip in active_filter_chips
        ]
        # One pill per search term rather than one for the whole box, so a
        # multi-term search can be unpicked a term at a time. The label comes
        # from the field registry, so `country:DE` reads "Country DE".
        + [
            {
                "kind": term.label,
                "value": term.value,
                "href": _visitors_url(params, **{"q": search.strip_term(q, term.raw)}),
            }
            for term in search_terms
        ]
    )

    return _remember_range(
        templates.TemplateResponse(
            request,
            "visitors.html",
            {
                "group": group,
                "group_spec": spec,
                "view": view,
                "rows": rows,
                "visitors": rows if group == "ip" else [],
                "markers": markers,
                "geo_stats": geo_stats,
                "activity_days": day_rows(activity),
                "activity_series": ACTIVITY_SERIES,
                "activity_bucket": activity_bucket,
                "hour_switch_days": HOUR_SWITCH_DAYS,
                "heatmap_grid": heatmap_grid,
                "heatmap_max": heatmap_max,
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": total_pages(total, limit),
                "sort": sort,
                "order": order,
                "sort_suffix": sort_suffix,
                "pager_params": pager_params,
                "range_params": range_params,
                "rows_params": rows_params,
                "chart_params": chart_params,
                "available_categories": VISITOR_CATEGORIES,
                "visitor_counts": visitor_counts,
                "active_classes": active_classes,
                "active_signals": signal_filter,
                "active_filter_chips": active_filter_chips,
                "active_range": active_range,
                "drill": drill,
                "search_q": q or "",
                "search_help": search.help_rows(),
                "broad_fields": search.broad_field_labels(),
                # The four aggregations search their own columns, not the broad set.
                "group_search_columns": spec.get("q_span", ""),
                # A mistyped field must say so — silently searching everything would
                # filter the page differently than the user believes.
                "search_unknown": unknown_fields,
                # Both GET forms carry the rest of the selection as hidden inputs,
                # built from the same params dict every link is built from.
                "search_fields": _form_fields(params, ("q",)),
                "range_fields": _form_fields(params, ("range", "date_from", "date_to")),
                "status_filter": status or "",
                "date_from": date_from or "",
                "date_to": date_to or "",
                "group_tabs": [
                    {
                        "label": _GROUP_SPECS[g]["label"],
                        "href": _visitors_url(params, group=g if g != "ip" else "", page=""),
                        "active": g == group,
                    }
                    for g in _GROUP_SPECS
                ],
                "view_tabs": [
                    {
                        "label": "Table",
                        "href": _visitors_url(params, view="", page=""),
                        "active": view == "table",
                    },
                    {
                        # The map has no grouping either — switching to it drops the
                        # parameter rather than carrying one it will not honour.
                        "label": "Map",
                        "href": _visitors_url(params, view="map", group="", page=""),
                        "active": view == "map",
                    },
                    {
                        # Like the map: no grouping applies, so none is carried over.
                        "label": "Timeline",
                        "href": _visitors_url(params, view="timeline", group="", page=""),
                        "active": view == "timeline",
                    },
                ],
                # Clearing filters keeps the grouping, the view and the time window:
                # the range tabs are their own control, always visible, and picking
                # "7 days" is not one of the filters the pills offer to remove.
                "clear_href": _visitors_url(
                    {
                        "group": params["group"],
                        "view": params["view"],
                        "range": params.get("range"),
                        "date_from": params.get("date_from"),
                        "date_to": params.get("date_to"),
                    }
                ),
                "server_location": (
                    {
                        "lat": settings.server_lat,
                        "lon": settings.server_lon,
                        "city": settings.server_city,
                        "country": settings.server_country,
                        "asn": settings.server_asn,
                        "ip": settings.server_ip,
                    }
                    if settings.server_lat is not None
                    else None
                ),
                **_build_filter_context(
                    country,
                    ip,
                    min_visits_int,
                    date_from,
                    date_to,
                    active_classes,
                    signal_filter,
                    port_int,
                    asn,
                    path,
                    browser,
                ),
            },
        ),
        active_range,
        date_from,
        date_to,
    )


@router.get("/visitors/rows")
async def visitor_rows(
    request: Request,
    country: str | None = None,
    asn: str | None = None,
    path: str | None = None,
    browser: str | None = None,
    active_classes: list[str] = Query(default=[], alias="class"),
    signal_filter: list[str] = Query(default=[], alias="signal"),
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
):
    """HTML fragment: the IPs behind one aggregation row, for the slide-over.

    Clicking a row opens this without a page change — the drill-down itself stays
    a pill on /visitors. Reuses get_visitors_grouped with the drill-down filter
    the clicked dimension maps to. Registered before /visitors/{ip}.
    """
    country = valid_country(country)
    asn, path, browser = valid_search(asn), valid_search(path), valid_search(browser)
    date_from, date_to = valid_date(date_from), valid_date(date_to)
    q = valid_search(q)
    active_classes, signal_filter = _normalize_filters(active_classes, signal_filter)

    def _load(conn):
        rows = get_visitors_grouped(
            conn,
            1,
            limit,
            "visit_count",
            "DESC",
            country,
            None,
            active_classes,
            signal_filter,
            0,
            date_from,
            date_to,
            asn_filter=asn,
            path_filter=path,
            browser_filter=browser,
            q=q,
        )
        total = count_visitors_grouped(
            conn,
            country,
            None,
            active_classes,
            signal_filter,
            0,
            date_from,
            date_to,
            asn_filter=asn,
            path_filter=path,
            browser_filter=browser,
            q=q,
        )
        return rows, total

    rows, total = await fetch(_load)
    kind, value = next(
        (
            (k, v)
            for k, v in (
                ("Network", asn),
                ("Country", country),
                ("Path", path),
                ("Client", browser),
            )
            if v
        ),
        ("Visitors", ""),
    )
    return templates.TemplateResponse(
        request,
        "_visitor_rows.html",
        {
            "rows": rows,
            "total": total,
            "limit": limit,
            "kind": kind,
            "value": value,
            "full_href": _visitors_url(
                {
                    "country": country or "",
                    "asn": asn or "",
                    "path": path or "",
                    "browser": browser or "",
                    "class": active_classes,
                    "signal": signal_filter,
                    "date_from": date_from or "",
                    "date_to": date_to or "",
                }
            ),
        },
    )
