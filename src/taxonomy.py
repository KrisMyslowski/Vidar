"""Visitor taxonomy — canonical category definitions shared by routes and queries."""

from __future__ import annotations

from dataclasses import dataclass

# ── Category groups ───────────────────────────────────────────────────────────

VISITOR_CATEGORIES: list[tuple[str, list[str]]] = [
    (
        "humans",
        ["humans/browser-direct", "humans/browser-referred", "humans/browser-internal-nav"],
    ),
    (
        "bots",
        [
            "bots/vulnerability-probers",
            "bots/security-researchers",
            "bots/scanning-tools",
            "bots/search-crawlers",
            "bots/ai-crawlers",
            "bots/seo-tools",
            "bots/impersonators",
            "bots/generic-bots",
        ],
    ),
    (
        "automated",
        [
            "automated/headless-browser",
            "automated/http-clients",
            "automated/protocol-mismatch",
            "automated/datacenter",
        ],
    ),
    (
        "threats",
        ["threats/protocol-abusers", "threats/exploit-probers"],
    ),
    ("unknown", ["unknown"]),
]
# Identity classes only. Network/reputation (Tor, proxy/VPN, hosting, DNSBL) are
# orthogonal *signals* — see VALID_SIGNALS — not classes: an IP keeps its identity
# (e.g. humans/browser-direct) while carrying any number of signals on top.
#
# The one exception is deliberate and documented: automated/headless-browser reads
# is_hosting to separate "a browser, in a datacenter" from a person. See the human
# gate in _apply_priority_chain() — reputation still never downgrades a human on a
# consumer VPN (is_proxy), only cloud compute (is_hosting without is_proxy).

VALID_CLASSES: frozenset[str] = frozenset(c for _, cats in VISITOR_CATEGORIES for c in cats)

# The identity groups in canonical display order — the one list every surface
# iterates. Only groups that actually prefix a class string: the "unknown" group
# holds the bare literal "unknown", which is the implicit group everything
# unmatched falls into, so it is not a prefix and is appended separately below.
GROUPS: tuple[str, ...] = tuple(g for g, cats in VISITOR_CATEGORIES if any("/" in c for c in cats))
# Same order plus the implicit group, for everything that displays or counts all
# five: the SQL CASE breakdowns, the activity chart's series, the heatmap toggle,
# the Overview's class mix and the map legend (via TAXONOMY_DATA). This used to
# be a literal in seven places; adding a group meant finding all of them.
GROUPS_WITH_UNKNOWN: tuple[str, ...] = GROUPS + ("unknown",)

# Group prefixes usable in ?class= (e.g. class=humans -> all humans/* classes);
# the unknown group is handled via the literal "unknown", which is both its
# group name and its only class.
VALID_GROUPS: frozenset[str] = frozenset(GROUPS)

# ── Signal registry ───────────────────────────────────────────────────────────
# The network/reputation signals, declared once. They used to live in four
# parallel structures under two different key vocabularies — VALID_SIGNALS and
# SIGNAL_LABELS keyed by `is_tor`, the search's column map keyed by `tor`, and a
# hand-written if-chain in _apply_signal_filter repeating the SQL a third time.
# Everything below this block is derived; adding a signal is one entry.


@dataclass(frozen=True)
class Signal:
    """One network/reputation signal — orthogonal to identity, never a class.

    key         `?signal=` value, and the ip_intel column where there is one.
    alias       short form: the `signal:` search term, and the stem of the
                generated SQL column aliases (`<alias>_ips`, `<alias>_count`).
    sql         predicate template. `{p}` is the ip_intel column prefix
                ("i." / "ip_intel." / ""), `{ip}` the IP column to correlate on.
                Empty means derived — queries.py builds it (only `clean` is).
    column      the ip_intel column, empty for signals that are not one.
    in_clean    counts against "clean". Mobile deliberately does not: it says
                which network an IP sits on, not what is known against it.
                Being selectable and being held against an IP are separate
                questions, and only this one is about the second.
    tip         (what, how) for the tooltip; empty means no tooltip content.

    Every signal in here is filterable. There was a `filterable` flag for the
    one that was not, and the surfaces it produced — a matrix column with no
    link, a badge with no chip — read as breakage rather than as intent.
    """

    key: str
    alias: str
    label: str
    sql: str
    column: str = ""
    label_short: str = ""
    tip: tuple[str, str] = ()
    color_var: str = ""
    badge: str = ""
    in_clean: bool = True

    def condition(self, prefix: str = "i.", ip_ref: str = "i.ip") -> str:
        """The SQL predicate for this signal against the given table prefix / IP column."""
        return self.sql.format(p=prefix, ip=ip_ref)

    @property
    def short(self) -> str:
        """Column-header form — the full label unless a narrower one is declared."""
        return self.label_short or self.label


SIGNALS: tuple[Signal, ...] = (
    Signal(
        key="is_tor",
        alias="tor",
        label="Tor",
        sql="{p}is_tor = 1",
        column="is_tor",
        tip=(
            "Traffic leaves the Tor network here.",
            "IP is on the Tor exit node list, refreshed daily.",
        ),
        color_var="var(--sig-tor)",
        badge="badge-purple",
    ),
    Signal(
        key="is_proxy",
        alias="proxy",
        label="Proxy / VPN",
        sql="{p}is_proxy = 1",
        column="is_proxy",
        tip=("IP is a proxy or a VPN exit.", "ip-api.com proxy=true."),
        color_var="var(--sig-proxy)",
        badge="badge-red",
    ),
    Signal(
        key="is_hosting",
        alias="hosting",
        label="Hosting / Cloud",
        label_short="Hosting",
        sql="{p}is_hosting = 1",
        column="is_hosting",
        tip=(
            "IP belongs to a datacenter or cloud provider.",
            "ip-api.com hosting=true, or an ISP name matching a known cloud "
            "operator — the API does not flag them all.",
        ),
        color_var="var(--sig-hosting)",
        badge="badge-yellow",
    ),
    Signal(
        key="dnsbl_listed",
        alias="dnsbl",
        label="DNSBL Listed",
        label_short="DNSBL",
        sql="{p}dnsbl_listed = 1",
        column="dnsbl_listed",
        tip=(
            "IP is on a DNS blocklist.",
            "A Spamhaus answer in the real listing range 127.0.0.2–127.0.0.11; "
            "error codes (127.255.255.x) count as not listed.",
        ),
        color_var="var(--sig-dnsbl)",
        badge="badge-orange",
    ),
    Signal(
        key="has_tags",
        alias="tags",
        label="Shodan Tags",
        label_short="Shodan",
        sql="EXISTS (SELECT 1 FROM ip_intel_tags t WHERE t.ip = {ip})",
        tip=(
            "Shodan has tagged this host.",
            "One or more tags from the Shodan InternetDB API, e.g. scanner, vpn. "
            "A host Shodan knows but has not tagged does not count.",
        ),
        color_var="var(--sig-tags)",
        badge="badge-muted",
    ),
    Signal(
        key="clean",
        alias="clean",
        label="Clean",
        # Derived from the five above — see _no_signals_sql() in queries.py, the
        # one definition of "clean" that the filter, the matrix and the map share.
        sql="",
        tip=(
            "Enriched, and nothing is known against it.",
            "No Tor, Proxy/VPN, Hosting, DNSBL or Shodan tag. Mobile does not "
            "count — it says which network, not what is known.",
        ),
        color_var="var(--sig-clean)",
        badge="badge-green",
        in_clean=False,
    ),
    Signal(
        key="is_mobile",
        alias="mobile",
        label="Mobile",
        sql="{p}is_mobile = 1",
        column="is_mobile",
        tip=("IP belongs to a mobile carrier network.", "ip-api.com mobile=true."),
        color_var="var(--sig-mobile)",
        badge="badge-blue",
        # Filterable like the rest: the matrix column showed a number nobody
        # could open, which reads as a broken link rather than as a deliberate
        # omission. in_clean stays False — see below.
        in_clean=False,
    ),
)

SIGNALS_BY_KEY: dict[str, Signal] = {s.key: s for s in SIGNALS}
SIGNALS_BY_ALIAS: dict[str, Signal] = {s.alias: s for s in SIGNALS}
# There used to be a second tuple here, EXTRA_SIGNALS, for signals that were
# displayed but not selectable — Mobile was its only member, and its matrix
# column drew a count that could not be opened. Now that every signal filters,
# the split described nothing: one tuple was the whole registry and the other
# was empty, while three template loops and a `filterable` flag were still
# maintained for it. SIGNALS is the one list again.
# The ip_intel columns "clean" is the absence of. has_tags has no column and is
# checked separately; mobile is excluded on purpose (see Signal.in_clean).
CLEAN_SIGNAL_COLUMNS: tuple[str, ...] = tuple(s.column for s in SIGNALS if s.in_clean and s.column)

VALID_SIGNALS: frozenset[str] = frozenset(s.key for s in SIGNALS)

# ── Tooltip content for filter chips (what, how) ──────────────────────────────

CLASS_TIPS: dict[str, tuple[str, str]] = {
    "humans/browser-direct": (
        "Real browser, arriving without a referrer.",
        "Browser navigation signals — Sec-Fetch navigate/document, or a fetch of a "
        "JS-only fragment — and no referrer of either kind.",
    ),
    "humans/browser-referred": (
        "Real browser, arriving from another site.",
        "Browser navigation signals and Sec-Fetch-Site: cross-site.",
    ),
    "humans/browser-internal-nav": (
        "Real browser, moving between pages of this site.",
        "Browser navigation signals and a same-origin referrer pointing at a "
        "different path than the one requested.",
    ),
    "bots/vulnerability-probers": (
        "Scanner hunting for exploitable software.",
        "Known probe paths (/.env, /wp-admin, /boaform/, /HNAP1/ …), or a high 404 "
        "rate across several distinct missing paths.",
    ),
    "bots/security-researchers": (
        "Scanning organization that publishes its identity.",
        "Attributable UA or reverse DNS: Censys, Shodan, Shadowserver, "
        "internet-census, LeakIX, Palo Alto, Modat.",
    ),
    "bots/scanning-tools": (
        "Internet-scanning tool, operator unknown.",
        "The UA names the tool rather than an actor: zgrab, masscan, libredtail.",
    ),
    "bots/search-crawlers": (
        "Search engine crawler.",
        "Known crawler UA (Googlebot, Bingbot, SeznamBot …) confirmed by reverse "
        "DNS or by the network owner, or not contradicted by hosting.",
    ),
    "bots/ai-crawlers": (
        "AI training or retrieval crawler.",
        "Known AI crawler UA (GPTBot, ClaudeBot, PerplexityBot …) confirmed by "
        "reverse DNS or by the network owner, or not contradicted by hosting.",
    ),
    "bots/seo-tools": (
        "SEO analysis crawler.",
        "UA strings from Ahrefs, Semrush, Majestic, Moz or Screaming Frog.",
    ),
    "bots/impersonators": (
        "Claims to be a well-known crawler, with nothing to back it.",
        "A crawler UA on a hosting IP that neither reverse DNS nor the network "
        "owner connects to the operator it names.",
    ),
    "bots/generic-bots": (
        "Self-declared bot, operator unknown.",
        "The UA contains bot, crawler or spider but matches none of the operator "
        "or tool patterns above.",
    ),
    "automated/headless-browser": (
        "A browser engine driven by software, in a datacenter.",
        "Passes the browser test on a hosting IP with no proxy signal. Behind a "
        "consumer VPN the same traffic stays human.",
    ),
    "automated/http-clients": (
        "A script or HTTP library, not a browser.",
        "The UA is a client library: curl, wget, Go-http-client, python-requests, "
        "java, OkHttp.",
    ),
    "automated/protocol-mismatch": (
        "Spoke the wrong protocol to this port.",
        "A TLS handshake on the plain-HTTP port, or an empty request line.",
    ),
    "automated/datacenter": (
        "Datacenter traffic with nothing else to go on.",
        "A hosting IP — ip-api.com hosting=true, or a known cloud ISP — carrying no "
        "human and no bot evidence.",
    ),
    "threats/protocol-abusers": (
        "Malicious payload sent outside normal HTTP.",
        "Non-HTTP request bodies carrying shell commands, botnet droppers (Mozi, "
        "Mirai) or service exploits (GPON, WebLogic T3, JSON-RPC).",
    ),
    "threats/exploit-probers": (
        "Targeted attempt at a known vulnerability.",
        "Path traversal, /etc/passwd, SQL injection, XSS, encoded null bytes, or "
        "botnet dropper paths (.arm, .mips, .x86 …).",
    ),
    "unknown": (
        "Not enough evidence to identify.",
        "No probe paths, no bot signature, no browser signals and not a hosting IP "
        "— often a client that never got past the HTTP→HTTPS redirect.",
    ),
}

# Tooltip content per signal. Keyed by every signal that declares any.
SIGNAL_TIPS: dict[str, tuple[str, str]] = {s.key: s.tip for s in SIGNALS if s.tip}

# Badge text for filter chips, pills and stat-card labels. Filterable signals
# only: a key here is a chip in the filter rail.
SIGNAL_LABELS: dict[str, str] = {s.key: s.label for s in SIGNALS}

# Column-header forms: a narrow numeric column cannot carry "Hosting / Cloud"
# without colliding with its neighbour. Falls back to the full label where no
# narrower one is declared.
SIGNAL_LABELS_SHORT: dict[str, str] = {s.key: s.short for s in SIGNALS}

# Group-level tooltip content for map legend and chart tooltips (what, how).
# One entry per taxonomy group; more specific per-class text lives in CLASS_TIPS.
GROUP_TIPS: dict[str, tuple[str, str]] = {
    "humans": (
        "A person, in a real browser.",
        "Browser navigation signals on more than one page, with no probe paths and "
        "a low error rate. Network origin is a signal, not the identity.",
    ),
    "bots": (
        "Declared automation — it says what it is.",
        "A UA naming a crawler, scanner or tool, or a known crawler confirmed by " "reverse DNS.",
    ),
    "automated": (
        "Software that names no operator.",
        "Machine evidence without a bot UA: a client library, a malformed request, "
        "or a browser running on a hosting IP.",
    ),
    "threats": (
        "Active exploitation attempt.",
        "Exploit paths, injection payloads or malicious non-HTTP bodies — what the "
        "client did, not where it came from.",
    ),
    # One filter, one explanation. The group chip and the class are the same
    # ?class=unknown value, and they used to carry different text on the same
    # page: "Not yet classified / No matching pattern" against "Not enough
    # evidence / no probe behaviour, no bot signature …".
    # One key, because there is one group. VISITOR_CATEGORIES used to call it
    # "other" while every display called it "unknown", so three maps here
    # carried both spellings and the templates translated between them on every
    # render. A lookup by the taxonomy's own name once fell through to an empty
    # pair and rendered a tooltip with nothing in it.
    "unknown": CLASS_TIPS["unknown"],
}

# ── Group / signal colors (single source of truth) ───────────────────────────
# Canonical identity colors for the taxonomy groups and enrichment signals.
# CSS mirrors these as --grp-*/--sig-* tokens in tokens.css; JS reads the tokens
# via cssVar('grp-<group>'). Every badge/chip/chart/map surface derives from
# these maps — no local color dicts in templates. unknown = muted gray
# ("no statement"); teal is exclusive to humans; each signal has its own hue
# (proxy red vs. dnsbl orange stay distinguishable side by side).

GROUP_BADGES: dict[str, str] = {
    "humans": "badge-teal",
    "bots": "badge-blue",
    "automated": "badge-yellow",
    "threats": "badge-red",
    "unknown": "badge-muted",
}

GROUP_COLOR_VARS: dict[str, str] = {
    "humans": "var(--grp-humans)",
    "bots": "var(--grp-bots)",
    "automated": "var(--grp-automated)",
    "threats": "var(--grp-threats)",
    "unknown": "var(--grp-unknown)",
}

SIGNAL_BADGES: dict[str, str] = {s.key: s.badge for s in SIGNALS}

# Signal counterpart to GROUP_COLOR_VARS — needed wherever a signal color goes
# into an inline style rather than a badge class (mix_bar segments).
SIGNAL_COLOR_VARS: dict[str, str] = {s.key: s.color_var for s in SIGNALS}
