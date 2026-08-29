"""Search-term parsing for the visitor search box — the registry and the parser.

Deliberately free of SQL: this module decides *what* a term means, `queries.py`
decides how to ask SQLite for it. That keeps the "all SQL in the query layer"
rule intact and leaves the interesting logic (which is all in the parsing) unit
testable without a database.

Why fields at all: the search used to throw every term as a substring against
eleven columns at once. Measured against a live log, `de` matched 3,617 of 11,564
IPs — 1,627 of them through `path` alone, because "in*de*x.html" contains the
letters. The 961 IPs actually in Germany drowned in that. A term now says which
dimension it means, either explicitly (`country:DE`) or by an unambiguous shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

# ── Match kinds ──────────────────────────────────────────────────────────────
# What the query layer must build for a term. Kept as plain strings so this
# module stays free of SQL vocabulary.

EXACT = "exact"  # column = value
PREFIX = "prefix"  # column LIKE 'value%'
SUBSTRING = "substring"  # column LIKE '%value%'
NUMBER = "number"  # column = int(value)
STATUS = "status"  # 404, or a 2xx–5xx band
CLASS = "class"  # a taxonomy class or a group prefix
SIGNAL = "signal"  # one of the boolean intel flags
COUNTRY = "country"  # code exact, or name substring
BROAD = "broad"  # no field given and no shape recognised


@dataclass(frozen=True)
class Field:
    """One searchable dimension.

    `source` decides how the query layer may filter on it:
      "intel"  — a column on ip_intel, constant per IP;
      "visit"  — a column on visits, varies per request;
      "child"  — a row in an ip_intel_* child table.
    The distinction matters: filtering a per-visit column in the WHERE of the
    per-IP list would also shrink that row's own aggregates, so those go through
    a subquery instead. See _apply_visitor_search in queries.py.
    """

    name: str
    label: str
    source: str
    match: str
    columns: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    example: str = ""
    note: str = ""


def _signal_aliases() -> str:
    """The short forms a `signal:` term accepts, from the registry."""
    from .taxonomy import SIGNALS

    names = [s.alias for s in SIGNALS]
    return ", ".join(names[:-1]) + " or " + names[-1]


FIELDS: tuple[Field, ...] = (
    # ── Identity ─────────────────────────────────────────────────────────────
    Field("ip", "IP", "visit", PREFIX, ("v.ip",), (), "ip:192.0.2.", "matches a prefix"),
    Field(
        "country",
        "Country",
        "intel",
        COUNTRY,
        ("i.country_code", "i.country"),
        ("cc",),
        "country:DE",
        "two-letter code exactly, or part of the name",
    ),
    Field("city", "City", "intel", SUBSTRING, ("i.city",), (), "city:Berlin"),
    Field("asn", "Network", "intel", SUBSTRING, ("i.asn",), (), "asn:AS13335"),
    Field("org", "Org", "intel", SUBSTRING, ("i.org",), (), "org:hetzner"),
    Field("isp", "ISP", "intel", SUBSTRING, ("i.isp",), (), "isp:datacamp"),
    Field(
        "rdns", "Reverse DNS", "intel", SUBSTRING, ("i.reverse_dns",), ("host",), "rdns:googlebot"
    ),
    # ── Behaviour ────────────────────────────────────────────────────────────
    Field("path", "Path", "visit", SUBSTRING, ("v.path",), ("url",), "path:/.env"),
    Field("ua", "User-Agent", "visit", SUBSTRING, ("v.user_agent",), ("agent",), "ua:wget"),
    # `client:` because the grouping this filters is called Clients — the tab,
    # the heading and the table all say so, and only the search said browser.
    # The column keeps its name (ua_parser produces `browser`), and so does the
    # field, so every saved URL and bookmark still works.
    Field("browser", "Browser", "visit", SUBSTRING, ("v.browser",), ("client",), "browser:Chrome"),
    Field("os", "OS", "visit", SUBSTRING, ("v.os",), (), "os:Android"),
    Field(
        "device",
        "Device",
        "visit",
        EXACT,
        ("v.device",),
        (),
        "device:Bot",
        "Desktop, Mobile, Tablet, Bot, Other or Unknown",
    ),
    Field("referer", "Referrer", "visit", SUBSTRING, ("v.referer",), ("ref",), "referer:google"),
    # ── Verdict ──────────────────────────────────────────────────────────────
    Field(
        "class",
        "Class",
        "intel",
        CLASS,
        ("i.visitor_class",),
        (),
        "class:threats",
        "a group, or a full class like humans/browser-direct",
    ),
    Field(
        "signal",
        "Signal",
        "intel",
        SIGNAL,
        (),
        (),
        "signal:tor",
        # Generated: the hand-written list had lost `mobile` when that signal
        # became filterable. Both the key and the alias resolve.
        _signal_aliases(),
    ),
    Field("tag", "Shodan tag", "child", EXACT, ("ip_intel_tags.tag",), (), "tag:scanner"),
    Field("vuln", "CVE", "child", SUBSTRING, ("ip_intel_vulns.vuln",), ("cve",), "vuln:CVE-2021"),
    Field(
        "port",
        "Open port",
        "child",
        NUMBER,
        ("ip_intel_ports.port",),
        (),
        "port:22",
        "a port Shodan sees open on the host",
    ),
    # ── Request technicals ───────────────────────────────────────────────────
    Field(
        "serverport",
        "Server port",
        "visit",
        NUMBER,
        ("v.server_port",),
        (),
        "serverport:80",
        "the port on *our* server — only ever 80 or 443",
    ),
    Field(
        "status", "Status", "visit", STATUS, ("v.status",), (), "status:404", "a code, or 2xx–5xx"
    ),
    Field("method", "Method", "visit", EXACT, ("v.method",), (), "method:POST"),
    Field(
        "http", "HTTP version", "visit", SUBSTRING, ("v.http_version",), ("httpversion",), "http:2"
    ),
)

_BY_NAME: dict[str, Field] = {}
for _f in FIELDS:
    _BY_NAME[_f.name] = _f
    for _a in _f.aliases:
        _BY_NAME[_a] = _f

# Columns a term with no field and no recognised shape falls back to. Deliberately
# the human-readable dimensions only: searching a status code or a port by
# accident produces noise, and those have unambiguous shapes or field names.
BROAD_FIELDS: tuple[str, ...] = (
    "ip",
    "country",
    "city",
    "asn",
    "org",
    "isp",
    "rdns",
    "path",
    "ua",
    "browser",
    "os",
)

# More terms than this in one query buys nothing and only grows the SQL.
MAX_TERMS = 8

# One token is either `field:"a quoted value"`, a bare `"quoted phrase"`, or a
# run of non-space. The field-plus-quotes case needs its own branch: splitting on
# whitespace first would tear `ua:"Mozilla 5.0"` in half.
_TOKEN_RE = re.compile(r'([A-Za-z_]{1,16}):"([^"]*)"|"([^"]*)"|(\S+)')
_ASN_RE = re.compile(r"^AS\d+$", re.I)
_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
_STATUS_RE = re.compile(r"^[1-5]\d{2}$")
_IPISH_RE = re.compile(r"^[0-9a-fA-F.:]+$")


@dataclass(frozen=True)
class Term:
    """One parsed search term.

    `field` is None only for BROAD. `raw` is what the user typed, so a pill can
    show it back and a remove-link can strip exactly that term from ?q=.
    """

    raw: str
    value: str
    field: Field | None = None
    match: str = BROAD

    @property
    def label(self) -> str:
        return self.field.label if self.field else "Search"


def _classify_bare(token: str) -> tuple[Field | None, str]:
    """Map an unqualified token to a field by shape, or leave it broad.

    Only shapes that cannot plausibly mean anything else are claimed, and every
    one of them can be overridden by naming a field (`path:de` searches paths for
    "de" again). This is the only inference in the module.
    """
    if _COUNTRY_RE.match(token):
        return _BY_NAME["country"], COUNTRY
    if _ASN_RE.match(token):
        return _BY_NAME["asn"], SUBSTRING
    if token.startswith("/"):
        return _BY_NAME["path"], SUBSTRING
    if _STATUS_RE.match(token):
        return _BY_NAME["status"], STATUS
    # An IP or the start of one: hex/dot/colon only, and enough structure that it
    # cannot be an ordinary word ("22" or "abc" must not become an IP search).
    if _IPISH_RE.match(token) and (token.count(".") >= 2 or ":" in token):
        return _BY_NAME["ip"], PREFIX
    return None, BROAD


def parse(q: str | None) -> tuple[list[Term], list[str]]:
    """Split a search box entry into terms.

    Returns (terms, unknown_fields). Terms are AND-ed by the caller. A quoted run
    stays one term, so paths and user-agents with spaces remain searchable.
    Unknown field names are reported rather than quietly demoted to a broad
    search — otherwise the page would filter differently than the user believes.
    The same holds one level down: `signal:` and `class:` take an enumeration,
    and a value outside it is reported too. It used to build a term that
    produced no SQL, so the page showed everything under a pill claiming a
    filter.
    """
    if not q:
        return [], []

    terms: list[Term] = []
    unknown: list[str] = []
    for fname, fquoted, quoted, bare in _TOKEN_RE.findall(q):
        # field:"quoted value" — the value keeps its spaces.
        if fname:
            field = _BY_NAME.get(fname.lower())
            if field is None:
                unknown.append(fname)
                continue
            if not _value_is_known(field, fquoted):
                unknown.append(f'{fname}:"{fquoted}"')
                continue
            terms.append(
                Term(raw=f'{fname}:"{fquoted}"', value=fquoted, field=field, match=field.match)
            )
            continue

        # A bare "quoted phrase" opts out of the shape inference entirely.
        if quoted:
            terms.append(Term(raw=f'"{quoted}"', value=quoted, field=None, match=BROAD))
            continue

        if not bare:
            continue

        name, sep, value = bare.partition(":")
        if sep and value:
            field = _BY_NAME.get(name.lower())
            if field is not None:
                if not _value_is_known(field, value):
                    unknown.append(bare)
                    continue
                terms.append(Term(raw=bare, value=value, field=field, match=field.match))
                continue
            if _looks_like_field_attempt(name, value):
                unknown.append(name)
                continue

        field, match = _classify_bare(bare)
        terms.append(Term(raw=bare, value=bare, field=field, match=match))

    return terms[:MAX_TERMS], unknown


def _value_is_known(field: "Field", value: str) -> bool:
    """Whether an enumerated field's value resolves to something real.

    signal: and class: take a fixed set. A value outside it used to build a Term
    that produced no SQL, so the page rendered an unfiltered list under a pill
    claiming the filter — the same failure the unknown-field check exists to
    prevent, one level down. Free-text fields have no enumeration and pass.
    """
    from .taxonomy import SIGNALS_BY_ALIAS, SIGNALS_BY_KEY, VALID_CLASSES, VALID_GROUPS

    v = value.lower()
    if field.match == SIGNAL:
        return bool(SIGNALS_BY_KEY.get(v) or SIGNALS_BY_ALIAS.get(v.removeprefix("is_")))
    if field.match == CLASS:
        return value in VALID_CLASSES or value in VALID_GROUPS or value == "unknown"
    return True


def _looks_like_field_attempt(name: str, value: str) -> bool:
    """True for a mistyped `foo:bar`, false for a URL that merely has a colon.

    Without this `https://example.com` would report "https" as an unknown field
    and refuse to search. A scheme is followed by `//`; a field name is a bare
    word followed by a value.
    """
    if value.startswith("//"):
        return False
    return bool(name) and name.replace("_", "").isalpha() and len(name) <= 16


def strip_term(q: str | None, raw: str) -> str:
    """Return `q` without the given term — for a pill's remove link.

    Matches on the token as typed (Term.raw), so removing one pill leaves every
    other term exactly as the user wrote it.
    """
    kept = []
    for fname, fquoted, quoted, bare in _TOKEN_RE.findall(q or ""):
        if fname:
            token = f'{fname}:"{fquoted}"'
        elif quoted:
            token = f'"{quoted}"'
        else:
            token = bare
        if not token or token == raw:
            continue
        kept.append(token)
    return " ".join(kept)


def broad_field_labels() -> list[str]:
    """The fields a bare term is matched against, by their display labels.

    The help panel used to name five categories in prose, one of which ("geo")
    is not a field at all, while BROAD_FIELDS has eleven entries. Reading the
    tuple means the sentence cannot drift from the search again.
    """
    by_name = {f.name: f for f in FIELDS}
    return [by_name[n].label for n in BROAD_FIELDS if n in by_name]


def help_rows() -> list[dict]:
    """The syntax help, generated from the registry so it cannot go stale."""
    return [
        {
            "name": f.name,
            "aliases": ", ".join(f.aliases),
            "label": f.label,
            "example": f.example,
            "note": f.note,
        }
        for f in FIELDS
    ]


def fields_for(names: Iterable[str]) -> list[Field]:
    """Registry entries for a list of field names, in registry order."""
    wanted = set(names)
    return [f for f in FIELDS if f.name in wanted]
