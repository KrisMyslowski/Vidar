"""The decision: one ordered chain of rules over one evidence row.

Pure — no database, no I/O. Give it the dict evidence_sql.py produced and it
returns a verdict. patterns.py holds every literal the rules compare against.
"""

from __future__ import annotations

from .patterns import (
    _AI_RDNS,
    _AI_UAS,
    _CRAWLER_ORIGINS,
    _DISTINCT_404_PATHS_FOR_PROBER,
    _HTTP_CLIENT_UAS,
    _MALFORMED_REQUEST_RATE,
    _MIN_CONTENT_FOR_RATIO,
    _MIN_PAGES_FOR_DATACENTER_HUMAN,
    _MIN_PAGES_FOR_WEAK_BROWSER,
    _PROBE_404_RATE,
    _RESEARCHER_RDNS,
    _RESEARCHER_UAS,
    _SCANNING_TOOL_UAS,
    _SEARCH_RDNS,
    _SEARCH_UAS,
    _SEO_UAS,
    _hit,
    _is_cloud_isp,
)

# ── The rule chain ───────────────────────────────────────────────────────────
# One ordered list. Each rule reads the evidence and either claims the IP — with
# the sentence that justifies the claim — or passes to the next.
#
# Precedence is behaviour-first: a malicious or bot-like *action* outranks a
# browser-looking request. Network/reputation (Tor, proxy, DNSBL, Shodan tags) are
# NOT identities — they are orthogonal signals on ip_intel, surfaced through the
# ?signal= filter. One reputation field is read here, deliberately: is_hosting. It
# never downgrades a person behind a consumer VPN (is_proxy); it only separates "a
# browser" from "a browser running in a datacenter", which is a different object,
# and it corroborates a crawler's self-declared identity.
#
# This was two functions: one returning the class, one returning the same decision
# with a sentence attached — a hand-maintained copy of the same fourteen conditions
# in the same order, every threshold written twice. A test held them together,
# which prevents divergence without removing the second copy. The condition and the
# sentence it justifies now sit in one place, and the two entry points below are
# two views of the same walk.

_Verdict = tuple[str, str, str]  # (class, why, source)


class _Evidence:
    """One IP's signal row, plus the four values the rules derive from it."""

    __slots__ = ("row", "content", "uas", "rdns", "owner", "hosting", "err_rate")

    def __init__(self, row: dict) -> None:
        self.row = row
        # At least 1: it is a divisor, and an IP whose every request was the
        # port-80 redirect has no content requests at all.
        self.content = max(self.n("content_requests"), 1)
        self.uas = (row.get("all_uas_lower") or "").lower()
        self.rdns = (row.get("reverse_dns") or "").lower()
        self.owner = (row.get("network_owner") or "").lower()
        self.hosting = bool(row.get("is_hosting")) or _is_cloud_isp((row.get("isp") or "").lower())
        self.err_rate = self.n("probe_404") / self.content

    def n(self, key: str) -> int:
        """A counter off the row — 0 when the column is absent or NULL."""
        return self.row.get(key) or 0


def _browser_disqualified(e: _Evidence) -> bool:
    """Direct counter-evidence to "a person is browsing this site".

    Each of these is something a real browsing session does not produce, and each was
    measured letting non-humans through the gate:
      - probe paths, and a UA the parser already identified as a bot (21 IPs);
      - non-HTTP traffic: TLS handshakes on the plain port, empty request lines (28);
      - a high share of 404s or 400s — malformed requests are tooling, not browsing (37).
    """
    return (
        e.n("scanner_paths") > 0
        or e.n("bot_device") > 0
        or e.n("protocol_mismatch") > 0
        or e.err_rate >= _PROBE_404_RATE
        or e.n("bad_requests") / e.content >= _MALFORMED_REQUEST_RATE
    )


def _rule_payload_abuse(e: _Evidence) -> _Verdict | None:
    """A non-HTTP body carrying a shell command or a dropper URL."""
    n = e.n("payload_abuse")
    if not n:
        return None
    return (
        "threats/protocol-abusers",
        f"{n} non-HTTP request(s) carrying a shell command or dropper payload",
        "behaviour",
    )


def _rule_exploit_probes(e: _Evidence) -> _Verdict | None:
    """A request path carrying a known exploit pattern."""
    n = e.n("exploit_probes")
    if not n:
        return None
    return (
        "threats/exploit-probers",
        f"{n} request(s) carrying an exploit pattern "
        "(traversal, SQL, script, null byte, dropper)",
        "behaviour",
    )


def _rule_scanner_paths(e: _Evidence) -> _Verdict | None:
    """A request for one of the known probe paths."""
    n = e.n("scanner_paths")
    if not n:
        return None
    return (
        "bots/vulnerability-probers",
        f"Requested {n} known probe path(s) (/.env, /.git/, /wp-admin …)",
        "behaviour",
    )


def _rule_probe_404_rate(e: _Evidence) -> _Verdict | None:
    """A high share of requests to paths that do not exist."""
    if not (e.content >= _MIN_CONTENT_FOR_RATIO and e.err_rate > _PROBE_404_RATE):
        return None
    return (
        "bots/vulnerability-probers",
        f"{round(e.err_rate * 100)}% of {e.content} content requests hit a path that "
        "does not exist — probing for what does",
        "behaviour",
    )


def _rule_distinct_404_paths(e: _Evidence) -> _Verdict | None:
    """A spread of distinct missing paths — a scanner too slow for the ratio."""
    n = e.n("distinct_404_paths")
    if n < _DISTINCT_404_PATHS_FOR_PROBER:
        return None
    return (
        "bots/vulnerability-probers",
        f"Asked for {n} distinct paths that do not exist",
        "behaviour",
    )


def _rule_researcher_rdns(e: _Evidence) -> _Verdict | None:
    """Reverse DNS naming an organisation that publishes its scanning."""
    hit = _hit(e.rdns, _RESEARCHER_RDNS)
    if not hit:
        return None
    return (
        "bots/security-researchers",
        f"Reverse DNS belongs to a named scanning organisation ({hit})",
        "reverse_dns",
    )


def _rule_researcher_ua(e: _Evidence) -> _Verdict | None:
    """A user-agent naming such an organisation."""
    hit = _hit(e.uas, _RESEARCHER_UAS)
    if not hit:
        return None
    return (
        "bots/security-researchers",
        f"User-Agent of a named scanning organisation ({hit})",
        "user-agent",
    )


def _rule_scanning_tool(e: _Evidence) -> _Verdict | None:
    """A user-agent naming the software rather than an actor."""
    hit = _hit(e.uas, _SCANNING_TOOL_UAS)
    if not hit:
        return None
    return (
        "bots/scanning-tools",
        f"User-Agent names a generic scanning tool ({hit}) — operator unknown",
        "user-agent",
    )


def _crawler_rule(rdns_needles: tuple, ua_needles: tuple, label: str, kind: str):
    """Build the rule for one declared-crawler family.

    A user-agent is a claim, so it has to survive a check. Two things can confirm
    it: reverse DNS naming the operator, or the network owner being one the
    operator crawls from (_CRAWLER_ORIGINS). Both families are checked rDNS-then-UA
    before the next family is considered, which is the order the chain has always
    walked.

    Reverse DNS was the only check until v6, and it covers 42% of the addresses
    here — against the large operators it is worse than that, because the ones
    that publish no PTR record are exactly OpenAI, Anthropic and DuckDuckGo. That
    made "unverified" indistinguishable from "disproven" and filed 88 real
    crawlers out of 91 impersonators. The network owner decides those; only a
    claim that nothing corroborates *and* that comes from a hosting IP is an
    impersonator now, and the verdict names which of the two checks failed.
    """

    def rule(e: _Evidence) -> _Verdict | None:
        hit = _hit(e.rdns, rdns_needles)
        if hit:
            return (label, f"Reverse DNS confirms the {kind} crawler ({hit})", "reverse_dns")
        hit = _hit(e.uas, ua_needles)
        if not hit:
            return None
        owner = _hit(e.owner, _CRAWLER_ORIGINS.get(hit, ()))
        if owner:
            return (
                label,
                f"Identified as {hit}, on a network belonging to {owner}",
                "ip-api",
            )
        if e.hosting:
            why = (
                f"Claims to be {hit}, but its reverse DNS points somewhere else"
                if e.rdns
                else f"Claims to be {hit} from a hosting/cloud IP that belongs to "
                "neither the operator nor a network it crawls from"
            )
            return ("bots/impersonators", why, "reverse_dns" if e.rdns else "ip-api")
        return (label, f"Identified as {hit} by its user-agent", "user-agent")

    rule.__name__ = f"_rule_{label.split('/')[1].replace('-', '_')}"
    return rule


def _rule_seo_ua(e: _Evidence) -> _Verdict | None:
    """A user-agent from a known SEO crawler."""
    hit = _hit(e.uas, _SEO_UAS)
    if not hit:
        return None
    return ("bots/seo-tools", f"Identified as {hit} by its user-agent", "user-agent")


def _rule_screaming_frog(e: _Evidence) -> _Verdict | None:
    """Screaming Frog, whose UA carries the two words apart."""
    if not ("screaming" in e.uas and "frog" in e.uas):
        return None
    return ("bots/seo-tools", "Identified as Screaming Frog by its user-agent", "user-agent")


def _reads_like_a_person(e: _Evidence) -> bool:
    """Whether a datacenter address behaved like somebody reading the site.

    Commercial VPN exits are datacenters — Datacamp, M247 and Private Relay's
    Akamai ranges all carry the hosting flag — so the flag alone files every
    person behind a VPN as a driven browser, which is the opposite of what the
    taxonomy promises about identity and reputation being separate axes.

    Three conditions together, each measured against production. Internal
    navigation is the discriminator: it holds for all 20 addresses that pass and
    for 9% of the 268 that do not. Requiring no probe-404 removes the eight that
    navigate internally *and* ask for missing paths — every one of them a scanner
    on Google Cloud, averaging 226 pages and 46 missing ones. The page floor
    drops single-page infrastructure that would otherwise slip through.

    It cannot be certain. A patient crawler that follows links, requests nothing
    absent and stays under the floor looks the same from here. The hosting and
    proxy signals stay attached either way, so the reader sees what the address
    is as well as what it did.
    """
    return (
        e.n("internal_nav") > 0
        and e.n("probe_404") == 0
        and e.n("unique_paths") >= _MIN_PAGES_FOR_DATACENTER_HUMAN
    )


def _rule_browser(e: _Evidence) -> _Verdict | None:
    """The browser gate, and what a passing browser turns out to be.

    Sec-Fetch navigation headers are sent by real browsers and practically never by
    bots or CLI tools, so a single hit is enough. Fetching a path only our own
    JavaScript requests is equally strong — the one browser signal an HTTP/1.1
    client without Sec-Fetch can still give us — but a datacenter IP or a bot UA
    makes it a headless crawler running our JS, so it does not count there.

    A browser engine on cloud compute is automation *unless it reads like a
    person*. From the server side a rented box and a VPN exit are the same thing,
    and the proxy flag cannot tell them apart: among datacenter addresses with
    browser evidence the proxy-flagged ones probe more, not less — 23.5 missing
    paths each against 7.4. Behaviour separates them where reputation does not.
    See _reads_like_a_person().
    """
    js_browser = e.n("js_fetch") > 0 and not e.hosting and e.n("bot_device") == 0
    strong = e.n("browser_navigate") > 0 or js_browser
    weak = e.n("has_zstd") > 0 or e.n("http2_visits") > 0
    passes = strong or (weak and e.n("unique_paths") >= _MIN_PAGES_FOR_WEAK_BROWSER)
    if _browser_disqualified(e) or not passes:
        return None

    if e.n("browser_navigate") > 0:
        why = f"Sec-Fetch navigation headers on {e.n('browser_navigate')} request(s)"
    elif js_browser:
        why = f"Fetched {e.n('js_fetch')} page fragment(s) only our JavaScript requests"
    else:
        why = f"Browser-only transport signals across {e.n('unique_paths')} distinct pages"

    if e.hosting and not _reads_like_a_person(e):
        return (
            "automated/headless-browser",
            f"{why} — but from a datacenter/cloud IP, so a driven browser",
            "ip-api",
        )
    if e.n("cross_site_nav") > 0:
        return ("humans/browser-referred", f"{why}, arriving from an external site", "headers")
    if e.n("internal_nav") > 0:
        return ("humans/browser-internal-nav", f"{why}, navigating within the site", "headers")
    return ("humans/browser-direct", f"{why}, no internal or external referrer", "headers")


def _rule_http_client(e: _Evidence) -> _Verdict | None:
    """A user-agent naming an HTTP library — how the request was made, not who made it."""
    hit = _hit(e.uas, _HTTP_CLIENT_UAS)
    if not hit:
        return None
    return (
        "automated/http-clients",
        f"User-Agent is an HTTP client library ({hit.rstrip('/')})",
        "user-agent",
    )


def _rule_generic_bot(e: _Evidence) -> _Verdict | None:
    """A self-declared bot the parser recognised but no rule above claimed."""
    if not e.n("bot_device"):
        return None
    return ("bots/generic-bots", "User-Agent declares itself a bot or crawler", "user-agent")


def _rule_protocol_mismatch(e: _Evidence) -> _Verdict | None:
    """Spoke something other than HTTP to an HTTP port, and carried no payload.

    Ranked below every behavioural rule, so a prober that also mis-speaks the
    protocol is still labelled a prober.
    """
    n = e.n("protocol_mismatch")
    if not n:
        return None
    return (
        "automated/protocol-mismatch",
        f"{n} request(s) that were not HTTP — a TLS handshake on the plain-HTTP "
        "port, or an empty request line",
        "behaviour",
    )


def _rule_datacenter(e: _Evidence) -> _Verdict | None:
    """Network-only fallback: cloud compute with no human or bot evidence.

    Tor or proxy without hosting could equally carry a human, so those fall through
    to 'unknown' and are described by their signals instead.
    """
    if not e.hosting:
        return None
    return ("automated/datacenter", "Datacenter/cloud IP with no human or bot evidence", "ip-api")


_RULES = (
    _rule_payload_abuse,
    _rule_exploit_probes,
    _rule_scanner_paths,
    _rule_probe_404_rate,
    _rule_distinct_404_paths,
    _rule_researcher_rdns,
    _rule_researcher_ua,
    _rule_scanning_tool,
    _crawler_rule(_SEARCH_RDNS, _SEARCH_UAS, "bots/search-crawlers", "search engine"),
    _crawler_rule(_AI_RDNS, _AI_UAS, "bots/ai-crawlers", "AI"),
    _rule_seo_ua,
    _rule_screaming_frog,
    _rule_browser,
    _rule_http_client,
    _rule_generic_bot,
    _rule_protocol_mismatch,
    _rule_datacenter,
)

_UNMATCHED: _Verdict = ("unknown", "No rule matched — too little evidence to classify", "—")


def _decide(d: dict) -> _Verdict:
    """Walk the chain; the first rule that claims the IP wins."""
    e = _Evidence(d)
    for rule in _RULES:
        verdict = rule(e)
        if verdict is not None:
            return verdict
    return _UNMATCHED


def _apply_priority_chain(d: dict) -> str:
    """The identity class for one IP's signal row — the chain's verdict, label only."""
    return _decide(d)[0]


def _decisive_rule(d: dict) -> tuple[str, str, str]:
    """The same verdict with its justification: (label, what it saw, where it came from).

    What explain_classification() puts at the top of the detail page. It cannot
    disagree with _apply_priority_chain any more: both are _decide().
    """
    return _decide(d)
