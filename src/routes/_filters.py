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
        # The label under a count, so it names the thing and not its
        # identifier: the column holding AS15169 stays "ASN", what is
        # counted is networks.
        "unit": "networks",
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
# Sorting for the two pages whose rows are built in Python rather than ordered
# by SQL. A map of key → the value to sort on, not key → SQL column: on Exposure
# the figures that matter are produced by folding percent-encoded spellings
# together *after* the query, so the query's own ORDER BY is decorative and a
# SQL sort key would order by pre-fold values. On Incidents the score, the
# duration and "against normal" exist only in Python.
#
# Descending is the default for every count and every date — the interesting end
# of all of them is the top — and ascending for the two text columns, where
# alphabetical is what a reader means by sorted.
def _text(key):
    """Case-folded, so `Zeta` does not sort before `alpha`."""
    return lambda r: str(r.get(key) or "").lower()


EXPOSURE_SORTS: dict[str, tuple] = {
    "path": (_text("path"), "ASC"),
    "family": (_text("family_title"), "ASC"),
    "addresses": (lambda r: r["ips"], "DESC"),
    "requests": (lambda r: r["hits"], "DESC"),
    "size": (lambda r: r["bytes_sent"] or 0, "DESC"),
    "first": (lambda r: r["first_seen"] or "", "DESC"),
    "last": (lambda r: r["last_seen"] or "", "DESC"),
}
EXPOSURE_DEFAULT_SORT = "addresses"

# Served — the block under the findings, listing everything the server answers
# 2xx for. Its own map because it shows different columns: Kind and Benign are
# here and Family is not, and Addresses means the same thing under a different
# key on the row (`ips`).
#
# "kind" is the default and reproduces the order the block already had — Site
# before Finding, then the most benign, then the most requested. It stays one
# key rather than becoming three columns to click, because the split is the
# point of the block and Benign is what the split is made of.
SERVED_SORTS: dict[str, tuple] = {
    "path": (_text("path"), "ASC"),
    "kind": (lambda r: (r["is_finding"], -r["benign_ips"], -r["hits"]), "ASC"),
    "addresses": (lambda r: r["ips"], "DESC"),
    "benign": (lambda r: r["benign_ips"], "DESC"),
    "requests": (lambda r: r["hits"], "DESC"),
    "size": (lambda r: r["bytes_sent"] or 0, "DESC"),
    "last": (lambda r: r["last_seen"] or "", "DESC"),
}
SERVED_DEFAULT_SORT = "kind"

INCIDENT_SORTS: dict[str, tuple] = {
    "started": (lambda r: r["started"], "DESC"),
    "duration": (lambda r: r["duration"], "DESC"),
    "addresses": (lambda r: r["addresses"], "DESC"),
    "asns": (lambda r: r["asns"], "DESC"),
    "probes": (lambda r: r["probe_404"], "DESC"),
    "listed": (lambda r: r["blocklisted"], "DESC"),
    # None sorts last in both directions, the way an em dash reads on the page.
    "normal": (lambda r: (r["against_normal"] is None, r["against_normal"] or 0), "DESC"),
    "score": (lambda r: r["score"], "DESC"),
}
INCIDENT_DEFAULT_SORT = "score"

# ── The incident drawer's own two tables ─────────────────────────────────────
#
# Both default to the order the panel already had, so an untouched drawer is
# what it was: paths in the order they arrived, sessions in the order the
# addresses joined.
#
# The paths table is sortable where the page's Signature column is not, and the
# difference is the "#" column. It carries the arrival position as a value in
# the row, so sorting by Requests moves the rows without destroying the order
# that makes five paths a signature — the position travels with the path. The
# page's Signature cell has no such column: there the order is the only place
# the information lives, which is why the rule in apply_sort still holds there
# and in a visitor's session requests.
INCIDENT_PATH_SORTS: dict[str, tuple] = {
    "pos": (lambda r: r["pos"], "ASC"),
    "path": (lambda r: r["path"], "ASC"),
    "addresses": (lambda r: r["addresses"], "DESC"),
    "requests": (lambda r: r["requests"], "DESC"),
}
INCIDENT_PATH_DEFAULT_SORT = "pos"

INCIDENT_SESSION_SORTS: dict[str, tuple] = {
    "started": (lambda r: r["started"], "ASC"),
    "duration": (lambda r: r["duration"], "DESC"),
    # Lexical, like every other IP ordering here (VISITOR_SORT_MAP sorts on
    # v.ip). It puts 10.x before 9.x; matching the rest of the dashboard beats
    # being right in one panel and different everywhere else.
    "ip": (lambda r: r["ip"], "ASC"),
    # Enrichment has not reached every address. Blank sorts last in both
    # directions, the way the em dash it renders as reads in the cell.
    "org": (lambda r: (not (r["org"] or r["asn"]), (r["org"] or r["asn"] or "").lower()), "ASC"),
    "probes": (lambda r: r["probe_404"], "DESC"),
}
INCIDENT_SESSION_DEFAULT_SORT = "started"


def apply_sort(rows: list[dict], sorts: dict, sort: str, order: str, default: str) -> list[dict]:
    """Order rows by one of `sorts`, with the current order.

    Signature and From are deliberately absent from both maps. A signature is an
    *ordered* path list and that order is its identity — alphabetising by its
    first element destroys what the column is for, which is the same reason a
    session's requests are not sortable. From is a truncated eight of N, so
    sorting by its first address sorts by an accident of DISTINCT.

    The route validates `sort` against the same map before calling, and this
    falls back anyway — the executors in the query layer defend twice the same
    way, because a KeyError here is a 500 on a page that had one bad character
    in its URL.
    """
    key, _ = sorts.get(sort) or sorts[default]
    return sorted(rows, key=key, reverse=order == "DESC")


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
