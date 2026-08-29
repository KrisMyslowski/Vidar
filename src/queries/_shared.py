"""Query fragments every other module in this package builds on.

Four groups, and nothing that runs a query itself:
  Projections  the shared SELECT lists and sort-column whitelists
  Grouping     the taxonomy-group and status-band CASE fragments
  Window       the one definition of "inside the date range"
  Filters      class, signal, drill-down and search, as WHERE builders

Every SQL string here is assembled from hardcoded literals; user input travels as
a bound parameter, never as text. See the note above _term_sql.
"""

from __future__ import annotations

import re

from .. import search
from ..taxonomy import (
    CLEAN_SIGNAL_COLUMNS,
    GROUPS,
    GROUPS_WITH_UNKNOWN,
    SIGNALS,
    SIGNALS_BY_ALIAS,
    SIGNALS_BY_KEY,
    Signal,
)

# ── SQL building: the invariant ──────────────────────────────────────────────
# Twenty-odd places in this package assemble SQL with f-strings. One rule makes
# all of them safe, and it is worth stating once instead of per site:
#
#   1. A *value* is never interpolated. It is bound as a parameter, always,
#      including inside LIKE patterns and IN lists.
#   2. Only *identifiers* are interpolated — table names, column names, the
#      table-qualified IP reference a fragment correlates on — and only ones
#      this package owns as literals.
#   3. Where a function takes such an identifier as an argument, it checks it
#      before building: against a whitelist where the set is known, against
#      _assert_identifier() where it is a caller-supplied column reference.
#
# The check is what makes the rule enforceable rather than a convention: a
# caller that ever reaches one of these with request data fails at the call
# instead of quietly producing SQL out of it. db.py's _add_col_if_missing has
# asserted its migration table this way all along; this is the same shape.

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?")


def _assert_identifier(value: str, what: str) -> str:
    """Guard an identifier on its way into an f-string SQL fragment.

    Accepts `name` and `alias.name` and nothing else — no quotes, no spaces, no
    parentheses, so no expression can arrive dressed as a column reference.

    Raises rather than asserts: `python -O` strips assertions, and rule 3 above
    is only enforceable while this check exists. Same reasoning as db.py's
    _add_col_if_missing.
    """
    if not _IDENT_RE.fullmatch(value):
        raise ValueError(f"not a plain {what}: {value!r}")
    return value


# The five normalized Shodan child tables as (table, column, name), where the
# name is both the display alias the aggregate select emits and the key the
# enrichment payload carries. Sole definition: the aggregate select below, the
# host filter and facet reader in analysis.py, and the writer in intel.py all
# derive from this. Each of the four used to spell the same five rows out.
SHODAN_CHILDREN: tuple[tuple[str, str, str], ...] = (
    ("ip_intel_ports", "port", "open_ports"),
    ("ip_intel_tags", "tag", "tags"),
    ("ip_intel_vulns", "vuln", "vulns"),
    ("ip_intel_cpes", "cpe", "cpes"),
    ("ip_intel_hostnames", "hostname", "hostnames"),
)
SHODAN_CHILD_TABLES: frozenset[str] = frozenset(t for t, _, _ in SHODAN_CHILDREN)
SHODAN_CHILD_COLUMNS: dict[str, str] = {t: c for t, c, _ in SHODAN_CHILDREN}

_VISITOR_GROUPED_SELECT = """
    v.ip,
    MIN(v.timestamp) as first_seen,
    MAX(v.timestamp) as last_seen,
    COUNT(v.id) as visit_count,
    COUNT(DISTINCT v.path) as unique_pages,
    GROUP_CONCAT(DISTINCT NULLIF(v.browser, '')) as browsers,
    GROUP_CONCAT(DISTINCT NULLIF(v.os, '')) as oses,
    GROUP_CONCAT(DISTINCT NULLIF(v.device, '')) as devices,
    GROUP_CONCAT(DISTINCT NULLIF(v.server_port, 0)) as ports,
    i.country, i.country_code, i.city, i.isp, i.org,
    i.is_proxy, i.is_hosting, i.is_mobile,
    i.is_tor, i.dnsbl_listed, i.dnsbl_sources,
    (SELECT GROUP_CONCAT(tag) FROM ip_intel_tags WHERE ip = v.ip) AS tags,
    -- Whether enrichment ever ran for this IP. No signals and no intel row is
    -- "we don't know yet", which is not the same as clean.
    (i.ip IS NOT NULL) AS enriched,
    COALESCE(i.visitor_class, '') AS visitor_class
"""


# Sort-column whitelists (prevent SQL injection — only a mapped key reaches an
# ORDER BY). Public, because the routes validate against them: a route that kept
# its own copy of the key set was a second list to keep in step, and a typo there
# fell back to the default sort in silence.
VISIT_SORT_MAP: dict[str, str] = {
    "timestamp": "v.timestamp",
    "ip": "v.ip",
    "status": "v.status",
    "path": "v.path",
    "bytes_sent": "v.bytes_sent",
    "request_time": "v.request_time",
}


# Everything the grouped-visitor query can sort by. The IP table offers a sort
# header for a subset of these — that subset is a UI decision and lives in the
# route, checked against this map at import.
VISITOR_SORT_MAP: dict[str, str] = {
    "last_seen": "last_seen",
    "first_seen": "first_seen",
    "visit_count": "visit_count",
    "ip": "v.ip",
    "country": "i.country",
    "country_code": "i.country_code",
    "city": "i.city",
    "isp": "i.isp",
    "org": "i.org",
    "is_proxy": "i.is_proxy",
    "is_hosting": "i.is_hosting",
    "is_mobile": "i.is_mobile",
    "is_tor": "i.is_tor",
    "dnsbl_listed": "i.dnsbl_listed",
    "tags": "tags",
    "browsers": "browsers",
    "oses": "oses",
    "devices": "devices",
    "ports": "ports",
    "unique_pages": "unique_pages",
    "visitor_class": "i.visitor_class",
}


# Excluded values for browser/OS/language aggregations in stats queries
_EXCLUDED_BROWSERS = frozenset({"No User-Agent", "", "Unknown", "Bot"})


_EXCLUDED_OSES = frozenset({"No User-Agent", "", "Unknown"})


# Safe map from public sort names to DB columns for get_visitor_requests
VISITOR_REQUEST_SORT_MAP = {
    "timestamp": "timestamp",
    "method": "method",
    "path": "path",
    "server_port": "server_port",
    "status": "status",
    "bytes_sent": "bytes_sent",
    "request_time": "request_time",
    "browser": "browser",
    "os": "os",
    "device": "device",
    "referer": "referer",
    "request_length": "request_length",
    "ssl_cipher": "ssl_cipher",
    "limit_req_status": "limit_req_status",
}


# Every fragment below is derived from taxonomy.GROUPS, which is the one place the
# taxonomy's groups and their order are declared. Anything else (NULL / '' /
# 'unknown' / unmatched) folds into the implicit 'unknown' group.


def _group_match(group: str, col: str = "visitor_class") -> str:
    """Parenthesised SQL predicate: `col` holds a class of `group`.

    'unknown' is the implicit group — no class string carries the prefix, so it
    matches everything unlabelled instead. One definition, because the CASE, the
    pivot and the per-row breakdown all have to fold those rows the same way.
    """
    if group == "unknown":
        return f"({col} IS NULL OR {col} = '' OR {col} = 'unknown')"
    return f"({col} LIKE '{group}/%')"


# visitor_class -> group label, for CASE+GROUP BY breakdowns (get_stats, get_analysis_data).
_VISITOR_GROUP_CASE = (
    "CASE "
    + " ".join(f"WHEN {_group_match(g)} THEN '{g}'" for g in GROUPS)
    + " ELSE 'unknown' END"
)


# Canonical ordering of the groups (humans=1 … unknown=last), for ORDER BY on `grp`.
_VISITOR_GROUP_ORDER = (
    "CASE grp "
    + " ".join(f"WHEN '{g}' THEN {i}" for i, g in enumerate(GROUPS, 1))
    + f" ELSE {len(GROUPS) + 1} END"
)


# Per-group SUM columns (pivoted) for the activity timeline; uses the `i` table alias.
_VISITOR_GROUP_SUMS = ", ".join(
    f"SUM(CASE WHEN {_group_match(g, 'i.visitor_class')} THEN 1 ELSE 0 END) AS {g}"
    for g in GROUPS_WITH_UNKNOWN
)


# HTTP status-code bands — the single source for every 2xx/3xx/4xx/5xx split
# (paths status mix, ?status= filter, status doughnut, status-mix timeline).
_STATUS_BANDS: tuple[tuple[str, str], ...] = (
    ("s2xx", "BETWEEN 200 AND 299"),
    ("s3xx", "BETWEEN 300 AND 399"),
    ("s4xx", "BETWEEN 400 AND 499"),
    ("s5xx", ">= 500"),
)


def _status_band_sums(col: str = "status") -> str:
    """SUM(CASE …) AS s2xx … s5xx column list splitting `col` by status band."""
    return ",\n".join(
        f"SUM(CASE WHEN {col} {cond} THEN 1 ELSE 0 END) AS {alias}"
        for alias, cond in _STATUS_BANDS
    )


# The network/reputation signal columns, from the taxonomy registry — the
# 'clean' inverse means none of these are set.
_THREAT_FLAGS_SQL = " OR ".join(f"i.{c}=1" for c in CLEAN_SIGNAL_COLUMNS)


def _signal_condition(sig: Signal, prefix: str = "i.", ip_ref: str = "i.ip") -> str:
    """SQL predicate for one signal. `clean` is the only derived one and is built here;
    every other signal carries its own template in the registry."""
    if not sig.sql:
        return _no_signals_sql(prefix, ip_ref)
    return sig.condition(prefix, ip_ref)


def _no_signals_sql(prefix: str = "i.", ip_ref: str = "i.ip", intel_ref: str | None = None) -> str:
    """The one definition of "clean": an enriched IP with none of the signals.

    It used to be three: the Identity x Signals matrix also required
    is_mobile = 0, the map's selection counts ignored Shodan tags, and the
    tooltip on both promised "no Tor, Proxy/VPN, Hosting, DNSBL, or Shodan tags"
    — which neither of them checked. Clean is a filter chip now, so the number
    behind the chip and the number in the matrix have to be the same number.

    Mobile is not part of it: it says which network an IP sits on, not whether
    anything is known against it, and it is not offered as a signal.
    Not-yet-enriched IPs are not clean either — they are simply unknown, which
    is why the intel row itself has to exist.

    Two IP references, and they are not interchangeable. `intel_ref` is the
    ip_intel row's own IP and carries that last test; `ip_ref` correlates the
    tags subquery and may legitimately be the visits-side column. They were one
    parameter until now, and at two of the four call sites it arrived as `v.ip`
    — never NULL on a LEFT JOIN from visits, so the enrichment test was inert
    exactly where it was written. The counts stayed right anyway, but by
    accident: `NULL = 0` evaluates to NULL and drops the row, so NULL
    propagation was doing the work the clause claims to do. A
    `COALESCE(i.is_tor, 0)` or a `NOT NULL DEFAULT 0` on any of those columns —
    both plausible changes — would have started counting every never-enriched
    IP as clean, and the test that holds filter, matrix and map counts equal
    would not have noticed, because all three would have been equally wrong.
    """
    # Derived from the prefix that already qualifies the intel columns, so the
    # two cannot drift apart. Only where there is no prefix (a query reading
    # ip_intel directly) does the caller's own reference stand in.
    intel = intel_ref or (f"{prefix}ip" if prefix else ip_ref)
    # ip_ref must be table-qualified: an unqualified column inside the EXISTS
    # binds to the subquery's own table, making the condition t.ip = t.ip.
    flags = " AND ".join(f"{prefix}{c} = 0" for c in CLEAN_SIGNAL_COLUMNS)
    return (
        f"{intel} IS NOT NULL AND {flags}"
        f" AND NOT EXISTS (SELECT 1 FROM ip_intel_tags t WHERE t.ip = {ip_ref})"
    )


def _like_escape(term: str) -> str:
    r"""Escape LIKE wildcards so the term matches literally (use with ESCAPE '\')."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# One definition of "inside the window", in four shapes for the four ways a
# caller needs to splice it in. Both bounds take either a date ("2026-08-09") or
# a full timestamp ("2026-08-09T23:59:59"); the upper bound is normalised to
# "before the next day" either way, so a bare date always covers the day it names.
#
# There used to be three conventions, and two of them were wrong:
#   * `<= ?` on the upper bound — nginx writes $time_iso8601 with an offset, so
#     '2026-08-09T23:59:59+00:00' <= '2026-08-09T23:59:59' is false and every
#     windowed figure on the dashboard silently dropped its last second. Handed a
#     bare date it dropped the *entire* day, which the route comments worked
#     around by expanding to T23:59:59 at six call sites.
#   * an inline T00:00:00/T23:59:59 expansion inside get_visitor_ip_counts,
#     carrying the same off-by-one-second.


def _date_conditions(
    since: str | None, until: str | None, column: str = "timestamp"
) -> tuple[list[str], list]:
    """The window as a list of conditions on `column`, plus their parameters."""
    conditions, params = [], []
    if since:
        conditions.append(f"{column} >= ?")
        params.append(since)
    if until:
        conditions.append(f"{column} < date(substr(?, 1, 10), '+1 day')")
        params.append(until)
    return conditions, params


def _date_where(
    since: str | None, until: str | None, column: str = "timestamp"
) -> tuple[str, list]:
    """Standalone WHERE clause ("" when unbounded), for queries with no open AND chain."""
    conditions, params = _date_conditions(since, until, column)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where, params


def _apply_date_filter(
    query: str, params: list, date_from: str | None, date_to: str | None
) -> tuple[str, list]:
    """Append the window to an open WHERE chain on visit rows (`v.timestamp`)."""
    conditions, window_params = _date_conditions(date_from, date_to, "v.timestamp")
    query += "".join(f" AND {c}" for c in conditions)
    params.extend(window_params)
    return query, params


def _apply_visit_filters(
    query: str, params: list, ip_filter: str | None, country_filter: str | None
) -> tuple[str, list]:
    """Append exact IP and country_code filters to a visits WHERE clause."""
    if ip_filter:
        query += " AND v.ip = ?"
        params.append(ip_filter)
    if country_filter:
        query += " AND i.country_code = ?"
        params.append(country_filter)
    return query, params


def _apply_class_filter(
    query: str, params: list, class_filter: list[str] | None
) -> tuple[str, list]:
    """Append visitor_class WHERE clause for a list of class values.

    Each value is either a full class string (``humans/browser-direct``), a group prefix
    (``humans`` -> every ``humans/*`` class), or the literal ``unknown``.
    """
    if not class_filter:
        return query, params
    has_unknown = "unknown" in class_filter
    rest = [c for c in class_filter if c != "unknown"]
    full = [c for c in rest if "/" in c]
    groups = [c for c in rest if "/" not in c]
    conditions: list[str] = []
    if full:
        ph = ",".join("?" * len(full))
        conditions.append(f"i.visitor_class IN ({ph})")
        params.extend(full)
    for grp in groups:
        conditions.append("i.visitor_class LIKE ?")
        params.append(f"{grp}/%")
    if has_unknown:
        conditions.append(
            "(i.visitor_class = 'unknown' OR i.visitor_class = '' OR i.visitor_class IS NULL)"
        )
    query += f" AND ({' OR '.join(conditions)})"
    return query, params


# Columns the per-IP search spans. Split by cardinality, because they cannot be
# filtered the same way:
#   IP_COLS are constant within one IP, so they can go straight into the WHERE;
#   VISIT_COLS vary per request, so filtering on them there would also shrink the
#   row's own aggregates — a visitor searched by path would report only the visits
#   that matched. Those go through a subquery that picks IPs and leaves the rows
#   being aggregated alone.


def _like(col: str) -> str:
    r"""A `col LIKE ? ESCAPE '\'` fragment. The pattern is a bound parameter, so the
    caller has to append it — run it through _like_escape() first."""
    return rf"{col} LIKE ? ESCAPE '\'"


def _term_sql(term: "search.Term", ip_ref: str) -> tuple[str, list, str, list]:
    """SQL for one parsed term, split by where it can be evaluated.

    Returns (intel_cond, intel_params, visit_cond, visit_params). `visit_cond`
    names `visits` columns **without** a table prefix, so the caller can either
    inline it (prefixing `v.`) or drop it into a subquery over visits — the two
    surfaces need different treatment and this keeps that decision at the caller.
    Either half may be empty.
    """
    _assert_identifier(ip_ref, "IP reference")
    field, value = term.field, term.value
    esc = f"%{_like_escape(value)}%"

    if term.match == search.BROAD:
        fields = search.fields_for(search.BROAD_FIELDS)
        intel_cols = [c for f in fields if f.source == "intel" for c in f.columns]
        visit_cols = [c.split(".", 1)[1] for f in fields if f.source == "visit" for c in f.columns]
        intel = " OR ".join(_like(c) for c in intel_cols)
        visit = " OR ".join(_like(c) for c in visit_cols)
        return f"({intel})", [esc] * len(intel_cols), f"({visit})", [esc] * len(visit_cols)

    if term.match == search.COUNTRY:
        # Two letters is a whole country code, so match it exactly — that is what
        # makes "DE" mean Germany instead of every path containing the letters.
        if len(value) == 2:
            return "(i.country_code = ? COLLATE NOCASE)", [value], "", []
        return f"({_like('i.country')})", [esc], "", []

    if term.match == search.SIGNAL:
        # Every name the registry knows resolves: the key (`has_tags`), the alias
        # (`tags`), and the alias with the column prefix a reader copies off a
        # chip (`is_tor`). Only the middle one used to work, via
        # removeprefix("is_") — so `signal:has_tags` and `signal:dnsbl_listed`
        # resolved to nothing and were dropped, while the Signals help panel
        # printed exactly those two as the value to type and the page still drew
        # a pill claiming the filter.
        key = value.lower()
        sig = SIGNALS_BY_KEY.get(key) or SIGNALS_BY_ALIAS.get(key.removeprefix("is_"))
        if sig is None:
            return "", [], "", []
        return f"({_signal_condition(sig, 'i.', ip_ref)})", [], "", []

    if term.match == search.CLASS:
        if "/" in value:
            return "(i.visitor_class = ?)", [value], "", []
        if value == "unknown":
            return (
                "(i.visitor_class = 'unknown' OR i.visitor_class = '' OR i.visitor_class IS NULL)",
                [],
                "",
                [],
            )
        return f"({_like('i.visitor_class')})", [f"{_like_escape(value)}/%"], "", []

    if term.match == search.STATUS:
        band = _STATUS_CLASS_SQL.get(value.lower())
        if band:  # stored as " AND v.status BETWEEN …" — reuse it without the AND
            return "", [], f"({band.replace(' AND v.', '', 1)})", []
        return ("", [], "(status = ?)", [int(value)]) if value.isdigit() else ("", [], "", [])

    if field.source == "child":
        table, column = field.columns[0].split(".")
        if term.match == search.NUMBER:
            if not value.isdigit():
                return "", [], "", []
            cond = f"(EXISTS (SELECT 1 FROM {table} c WHERE c.ip = {ip_ref} AND c.{column} = ?))"
            return cond, [int(value)], "", []
        if term.match == search.EXACT:
            cond = (
                f"(EXISTS (SELECT 1 FROM {table} c WHERE c.ip = {ip_ref}"
                f" AND c.{column} = ? COLLATE NOCASE))"
            )
            return cond, [value], "", []
        cond = (
            f"(EXISTS (SELECT 1 FROM {table} c WHERE c.ip = {ip_ref} AND {_like(f'c.{column}')}))"
        )
        return cond, [esc], "", []

    # A plain column. Visit-side columns are emitted unprefixed so the caller can
    # put them in a subquery over `visits`; intel columns keep their `i.` alias.
    col = field.columns[0]
    ref = col.split(".", 1)[1] if field.source == "visit" else col

    if term.match == search.NUMBER:
        if not value.isdigit():
            return "", [], "", []
        pattern, param = f"({ref} = ?)", int(value)
    elif term.match == search.EXACT:
        pattern, param = f"({ref} = ? COLLATE NOCASE)", value
    elif term.match == search.PREFIX:
        pattern, param = f"({_like(ref)})", f"{_like_escape(value)}%"
    else:
        pattern, param = f"({_like(ref)})", esc

    if field.source == "visit":
        return "", [], pattern, [param]
    return pattern, [param], "", []


def _apply_visitor_search(query: str, params: list, q: str | None) -> tuple[str, list]:
    """Append the search to the per-IP visitor list, the map and the timeline.

    Terms are AND-ed. Per-IP facts (intel columns, child tables, the address)
    go straight into the WHERE. Per-visit facts go through
    `v.ip IN (SELECT ip FROM visits WHERE …)` instead: they select *visitors*,
    and filtering them inline would also shrink the rows the query aggregates
    over, so an IP found via /.env would report only its .env requests rather
    than its real visit count.
    """
    terms, _ = search.parse(q)
    for term in terms:
        intel, intel_params, visit, visit_params = _term_sql(term, "v.ip")
        parts, term_params = [], []
        if intel:
            parts.append(intel)
            term_params.extend(intel_params)
        if visit:
            parts.append(f"v.ip IN (SELECT ip FROM visits WHERE {visit})")
            term_params.extend(visit_params)
        if not parts:
            continue
        query += " AND (" + " OR ".join(parts) + ")"
        params.extend(term_params)
    return query, params


def _apply_drilldown_filters(
    query: str,
    params: list,
    asn_filter: str | None,
    path_filter: str | None,
    browser_filter: str | None,
) -> tuple[str, list]:
    """Append exact-match drill-down filters used when arriving from an aggregation
    table (Networks → asn, Paths → path, Clients → browser)."""
    if asn_filter:
        query += " AND i.asn = ?"
        params.append(asn_filter)
    if path_filter:
        query += " AND v.path = ?"
        params.append(path_filter)
    if browser_filter:
        query += " AND v.browser = ?"
        params.append(browser_filter)
    return query, params


def _apply_signal_filter(
    query: str, params: list, signal_filter: list[str] | None
) -> tuple[str, list]:
    """Append signal WHERE clause for enrichment flags (is_tor, is_proxy, etc.).

    Selected signals are OR-ed: ?signal=is_tor&signal=clean means either. The
    order follows the registry, not the query string, so the same selection always
    produces the same SQL.
    """
    if not signal_filter:
        return query, params
    conditions = [f"({_signal_condition(s)})" for s in SIGNALS if s.key in signal_filter]
    if conditions:
        query += f" AND ({' OR '.join(conditions)})"
    return query, params


def _shodan_agg_select(ip_ref: str) -> str:
    """Correlated subqueries that re-aggregate the normalized Shodan child tables back
    into comma-separated columns (open_ports/tags/vulns/cpes/hostnames) for display.

    `ip_ref` is the outer IP column to correlate on (a hardcoded literal like 'i.ip').
    """
    _assert_identifier(ip_ref, "IP reference")
    return "\n" + ",\n".join(
        f"        (SELECT GROUP_CONCAT({col}) FROM {table} WHERE ip = {ip_ref}) AS {name}"
        for table, col, name in SHODAN_CHILDREN
    )


# Whitelisted status-class conditions for the Paths table's ?status= filter
_STATUS_CLASS_SQL = {alias[1:]: f" AND v.status {cond}" for alias, cond in _STATUS_BANDS}


_VISIT_COLUMN_NAMES = tuple(
    c.split(".", 1)[1] for f in search.FIELDS if f.source == "visit" for c in f.columns
)


def _prefix_visit_cols(cond: str) -> str:
    """Put the `v.` alias back on visit columns emitted for a subquery."""
    for name in sorted(_VISIT_COLUMN_NAMES, key=len, reverse=True):
        cond = re.sub(rf"(?<![\w.]){re.escape(name)}(?=\s)", f"v.{name}", cond)
    return cond


def visit_window(
    since: str | None,
    until: str | None,
    col: str = "timestamp",
) -> tuple[str, list]:
    """The date window as an ` AND …` fragment plus its parameters, for `visits`.

    Returns ("", []) when neither bound is set, so an unwindowed call produces
    exactly the SQL it always did. Every aggregate on the dashboard is scoped
    through this — the fragment is always ANDed onto an existing WHERE, never
    started with one, so callers keep their own conditions.
    """
    conditions, params = _date_conditions(since, until, col)
    return "".join(f" AND {c}" for c in conditions), params


def seen_in_window(ip_ref: str, since: str | None, until: str | None) -> tuple[str, list]:
    """ "This IP was here during the window" as an EXISTS clause over `visits`.

    The counterpart to visit_window() for everything counted off `ip_intel`:
    the matrix, the Exposure facets, the country total. Those count IPs, not
    requests, so they carry no timestamp of their own — a window can only mean
    "IPs with at least one visit in it".

    Empty when no bound is set, and that is load-bearing: an unconditional
    EXISTS would silently drop every enriched IP whose visits have been
    archived away, or that was enriched before its first request landed.
    """
    if not (since or until):
        return "", []
    frag, params = visit_window(since, until, "v.timestamp")
    return f"EXISTS (SELECT 1 FROM visits v WHERE v.ip = {ip_ref}{frag})", params
