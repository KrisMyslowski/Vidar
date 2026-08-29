"""Grouping specs, sort whitelists and filter normalisation for /visitors."""

from __future__ import annotations

from ..queries import (
    CLIENTS_SORT_MAP,
    COUNTRIES_SORT_MAP,
    NETWORKS_SORT_MAP,
    PATHS_SORT_MAP,
    VISITOR_SORT_MAP,
    count_clients,
    count_countries,
    count_networks,
    count_paths,
    get_clients,
    get_countries,
    get_networks,
    get_paths,
)
from ..taxonomy import VALID_CLASSES, VALID_GROUPS, VALID_SIGNALS

# ── Helpers ──────────────────────────────────────────────────────────────────

# The columns the IP table renders a sort header for. A subset of what the query
# layer can sort by (VISITOR_SORT_MAP also maps org, country_code, the signal
# flags, tags, devices and ports) — which columns get a header is a UI decision,
# so it is stated here rather than derived. Checked against the map at import: a
# key that no longer exists there would otherwise fall back to last_seen in
# silence, and the header would look like it worked.
_VALID_VISITOR_SORTS = frozenset(
    {
        "last_seen",
        "first_seen",
        "visit_count",
        "ip",
        "country",
        "city",
        "isp",
        "unique_pages",
        "browsers",
        "oses",
        "visitor_class",
    }
)
if not _VALID_VISITOR_SORTS <= set(VISITOR_SORT_MAP):
    # Raised, not asserted: `python -O` would silence the one check that makes
    # this fire at import rather than as a header sorting by something else.
    raise ValueError(
        "sort keys the query layer cannot map: "
        f"{sorted(_VALID_VISITOR_SORTS - set(VISITOR_SORT_MAP))}"
    )


def _build_filter_context(
    country: str | None,
    ip: str | None,
    min_visits: int,
    date_from: str | None,
    date_to: str | None,
    active_classes: list[str],
    signal_filter: list[str],
    port: int | None = None,
    asn: str | None = None,
    path: str | None = None,
    browser: str | None = None,
) -> dict:
    """Build the filter UI context keys shared by all visitor list routes."""
    return {
        "country_filter": country or "",
        "ip_filter": ip or "",
        "min_visits": min_visits or "",
        "date_from": date_from or "",
        "date_to": date_to or "",
        "active_classes": active_classes,
        "active_signals": signal_filter,
        "port_filter": port or "",
        "asn_filter": asn or "",
        "path_filter": path or "",
        "browser_filter": browser or "",
    }


def _normalize_filters(classes: list[str], signals: list[str]) -> tuple[list[str], list[str]]:
    # Accept full class strings (humans/browser-direct) and group prefixes (humans).
    return (
        [c for c in classes if c in VALID_CLASSES or c in VALID_GROUPS],
        [s for s in signals if s in VALID_SIGNALS],
    )


# Sort-key whitelists for the aggregation tables, derived from the maps the query
# layer sorts by. These were written out a second time here and the comment said
# they "must mirror" those maps — which is a rule a reader has to keep, not one
# the code keeps. Anything unmapped falls back to "visits".
_AGG_SORTS: dict[str, frozenset[str]] = {
    "networks": frozenset(NETWORKS_SORT_MAP),
    "countries": frozenset(COUNTRIES_SORT_MAP),
    "clients": frozenset(CLIENTS_SORT_MAP),
    "paths": frozenset(PATHS_SORT_MAP),
}


# ── Visitors: one page, five groupings, two views ────────────────────────────
#
# Networks/Countries/Clients/Paths stopped being routes — they are groupings of
# /visitors via ?group=, and the map is ?view=map on the same page. The five
# groupings differ only in which query pair they call and which sort keys they
# accept; everything around them (legend filter, search, range, pagination,
# breakdown columns) is shared. The query layer is untouched: `ip` keeps the
# drill-down parameter family, the four aggregations keep ?q=.

_GROUP_SPECS: dict[str, dict] = {
    "ip": {
        "label": "IP",
        "title": "Visitors",
        "noun": "visitor",
        "sorts": frozenset(_VALID_VISITOR_SORTS),
        "default_sort": "last_seen",
        "q_placeholder": (
            "Search IP, network, country, path or client… (e.g. 192.0.2., hetzner, /.env)"
        ),
    },
    "asn": {
        "label": "Network",
        "title": "Networks",
        "noun": "network",
        "unit": "ASNs",
        "get": get_networks,
        "count": count_networks,
        "sorts": _AGG_SORTS["networks"],
        "default_sort": "visits",
        "q_placeholder": "Search org, ISP or ASN… (e.g. amazon, AS13335)",
        "q_span": "org, ISP and ASN",
    },
    "country": {
        "label": "Country",
        "title": "Countries",
        "noun": "country",
        "unit": "countries",
        "get": get_countries,
        "count": count_countries,
        "sorts": _AGG_SORTS["countries"],
        "default_sort": "visits",
        "q_placeholder": "Search country name or code… (e.g. Germany, DE)",
        "q_span": "country name and code",
    },
    "client": {
        "label": "Client",
        "title": "Clients",
        "noun": "client",
        "unit": "clients",
        "get": get_clients,
        "count": count_clients,
        "sorts": _AGG_SORTS["clients"],
        "default_sort": "visits",
        "q_placeholder": "Search browser, OS or device… (e.g. Chrome, Android)",
        "q_span": "browser, OS and device",
    },
    "path": {
        "label": "Path",
        "title": "Paths",
        "noun": "path",
        "unit": "paths",
        "get": get_paths,
        "count": count_paths,
        "sorts": _AGG_SORTS["paths"],
        "default_sort": "visits",
        "q_placeholder": "Search path or user-agent… (e.g. /.env, curl)",
        "q_span": "path and user-agent",
    },
}

# Drill-down filters, in the order they render as pills. Each maps a /visitors
# query param to the aggregation row that sets it.
_DRILL_KINDS = (
    ("asn", "Network"),
    ("country", "Country"),
    ("path", "Path"),
    ("browser", "Client"),
    ("ip", "IP"),
    ("port", "Port"),
    ("status", "Status"),
    ("min_visits", "Min. visits"),
)
