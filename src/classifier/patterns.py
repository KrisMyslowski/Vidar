"""What the classifier matches on, and the thresholds it matches against.

Three kinds of thing live here, and nothing else:
  Version    — CLASSIFIER_VERSION, and the pack fingerprint folded into it
  Derivations — the SQL LIKE chains built from the needle lists (a derivation
               belongs next to the list it reads)
  Thresholds — the calibrated numbers, in one block with their measurements

**The needles themselves are no longer here.** They are in `patterns.toml`,
loaded by pack.py, because they go stale for a different reason than the rules
do: a newly announced AI crawler is not a logic change, and making it one meant
a code edit, a version bump and a release for a string. The names below are
unchanged, so nothing that imports them had to move.

The thresholds stayed. Each is calibration — a number measured against a real
log, meaningless apart from the rule that reads it — and putting one in a data
file would invite tuning it away from its measurement.

No SQL is executed here and no decision is made here; see rules.py for the chain
and evidence_sql.py for the query that fills it.
"""

from __future__ import annotations

from ..config import settings
from .pack import load

# Bump whenever _apply_priority_chain logic changes — startup reclassifies all IPs
# once when the stored value differs (see main.py _backfill_task).
# v2 (2026-06): split identity from network/reputation signals; dropped
# infrastructure/* and threats/dnsbl-listed classes; added automated/datacenter.
# v3 (2026-08): audit against production. Fixed the '%00' pattern (it matched any
# path containing "00"); split protocol *mismatch* out of protocol *abuse*; split
# generic scanning tools out of named security researchers and dropped the Shodan-tag
# branch (reputation, not identity); require crawler UA claims to be corroborated;
# separated headless browsers and HTTP client libraries from humans and generic bots;
# excluded port-80 redirects from the ratio denominators; added JS-fetch browser
# evidence. See docs/data-reference.md §4.2.
# v4 (2026-08): the human gate, reviewed against the v3 result. A bot UA, non-HTTP
# traffic or a high rate of malformed requests now *disqualify* the gate instead of
# only being checked after it; protocol-error pseudo-paths no longer count toward
# "pages explored"; the is_proxy exemption is gone (every hosting IP in humans/* also
# carried the proxy flag, so it exempted all of them); and a curated cloud-operator
# list supplements ip-api's incomplete hosting flag. 202 -> 103 humans.
# v5 (2026-08): JS-fetch prefixes are bound and LIKE-escaped rather than
# interpolated, so a prefix containing % or _ stops behaving as a pattern; and
# the content-request denominator excludes 308 alongside 301, since which
# permanent redirect an nginx answers on port 80 is the operator's choice and
# was changing every error ratio.
# v6 (2026-08): two classes were built on checks their evidence could not carry.
# A datacenter address that navigates inside the site, reads three or more pages
# and probes nothing is now a person on a VPN rather than a driven browser —
# commercial VPN exits are datacenters, so the old rule filed every VPN user as
# automation. And a crawler claim is verified against the network owner as well
# as reverse DNS (_CRAWLER_ORIGINS), because the operators that publish no PTR
# record are the large ones: 88 of 91 impersonators were the real crawler.
# v7 (2026-09): unique_paths counts pages, not spellings — the path up to its query
# string. Three ?utm_source= variants of the homepage were three pages, enough to
# clear _MIN_PAGES_FOR_DATACENTER_HUMAN, whose measurement was taken in pages.
_RULES_VERSION = "7"

# The needle lists, from the shipped pack plus whatever PATTERNS_PATH adds.
# A broken pack raises PackError here, at import, which stops the service with
# the file and the reason named rather than starting it with no patterns and a
# dashboard where nothing is ever wrong.
_PACK, PACK_DIGEST = load(settings.patterns_path)

_SCANNER_PATH_PATTERNS: tuple[str, ...] = tuple(_PACK["scanner_paths"]["entries"])
_PAYLOAD_ABUSE_PATTERNS: tuple[str, ...] = tuple(_PACK["payload_abuse"]["entries"])
_DROPPER_SUFFIXES: tuple[str, ...] = tuple(_PACK["dropper_suffixes"]["entries"])
_CONVENTION_404_PATTERNS: tuple[str, ...] = tuple(_PACK["convention_404"]["entries"])
_CLOUD_ISP_PATTERNS: tuple[str, ...] = tuple(_PACK["cloud_isps"]["entries"])
_RESEARCHER_RDNS: tuple[str, ...] = tuple(_PACK["researcher_rdns"]["entries"])
_RESEARCHER_UAS: tuple[str, ...] = tuple(_PACK["researcher_uas"]["entries"])
_SCANNING_TOOL_UAS: tuple[str, ...] = tuple(_PACK["scanning_tool_uas"]["entries"])
_SEARCH_RDNS: tuple[str, ...] = tuple(_PACK["search_rdns"]["entries"])
_SEARCH_UAS: tuple[str, ...] = tuple(_PACK["search_uas"]["entries"])
_AI_RDNS: tuple[str, ...] = tuple(_PACK["ai_rdns"]["entries"])
_AI_UAS: tuple[str, ...] = tuple(_PACK["ai_uas"]["entries"])
_SEO_UAS: tuple[str, ...] = tuple(_PACK["seo_uas"]["entries"])
_HTTP_CLIENT_UAS: tuple[str, ...] = tuple(_PACK["http_client_uas"]["entries"])
_CRAWLER_ORIGINS: dict[str, tuple[str, ...]] = {
    k: tuple(v) for k, v in _PACK["crawler_origins"].items()
}

# Rules and data both make a verdict, so both have to invalidate stored ones.
# The rules half is bumped by hand when the chain changes; the data half is a
# fingerprint of the effective pack, so editing a needle — or pointing
# PATTERNS_PATH at an operator file — reclassifies every address on the next
# start. Without it, an operator pack would apply to addresses seen after the
# restart and to nothing else, and the dashboard would hold two vintages of
# judgement with no way to tell them apart. Measured at 5.8 s per million
# visits; see docs/architecture.md.
CLASSIFIER_VERSION = f"{_RULES_VERSION}+{PACK_DIGEST}"


def _scanner_path_match(column: str = "v.path") -> str:
    return " OR ".join(f"{column} LIKE '{p}'" for p in _SCANNER_PATH_PATTERNS)


_SCANNER_PATH_MATCH = _scanner_path_match()
_PAYLOAD_ABUSE_MATCH = " OR ".join(f"LOWER(v.path) LIKE '{p}'" for p in _PAYLOAD_ABUSE_PATTERNS)
_DROPPER_MATCH = " OR ".join(f"LOWER(v.path) LIKE '%.{s}'" for s in _DROPPER_SUFFIXES)

# Request lines nginx could not parse as HTTP at all.
_NON_HTTP_METHODS = "v.method IN ('NON-HTTP', 'TLS', 'UNKNOWN')"

_CONVENTION_404_MATCH = " OR ".join(f"v.path LIKE '{p}'" for p in _CONVENTION_404_PATTERNS)


def _is_cloud_isp(isp: str) -> bool:
    """True when the ISP name names a cloud/VPS operator with no consumer customers."""
    return any(name in isp for name in _CLOUD_ISP_PATTERNS)


def _hit(haystack: str, needles: tuple[str, ...]) -> str | None:
    """First needle present in haystack, or None."""
    return next((n for n in needles if n in haystack), None)


# ── Thresholds ───────────────────────────────────────────────────────────────
# Calibrated against production (v4: 202 -> 103 humans). The reasoning behind each
# number is in docs/data-reference.md §4.2 — do not tune them here.

# Share of content requests hitting a missing path. Read twice, with different
# operators, and that is deliberate: the prober rule needs to *exceed* it, the
# browser gate is disqualified on reaching it. An IP sitting exactly on 20% is
# therefore neither — it has no browser claim left, but nothing calls it a prober.
_PROBE_404_RATE = 0.20
# Share of malformed (400) requests. Tooling, not browsing.
_MALFORMED_REQUEST_RATE = 0.20
# Below this many content requests a ratio says nothing, so the rate rule abstains.
_MIN_CONTENT_FOR_RATIO = 3
# A spread of distinct missing paths catches low-volume scanners the ratio misses.
_DISTINCT_404_PATHS_FOR_PROBER = 3
# Transport hints (http2/zstd) are weak — bots send them too — so they only count
# for an IP that also looked at more than one page.
_MIN_PAGES_FOR_WEAK_BROWSER = 2

# How many distinct pages a datacenter address has to have read before browser
# evidence there is taken as a person rather than a driven browser. Measured
# against production: with internal navigation and no probe-404s, 3+ pages
# isolates 20 addresses, all of them commercial-VPN or Private Relay exits with
# 6.3 pages each on average. Dropping to 2 admits 17 more, of which fifteen are
# single-page infrastructure — CenturyLink five times, Microsoft and DigitalOcean
# twice each — and two look like people. Three is where the noise starts.
_MIN_PAGES_FOR_DATACENTER_HUMAN = 3
