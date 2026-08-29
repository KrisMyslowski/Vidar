"""Everything the classifier matches on, and the thresholds it matches against.

Four kinds of literal live here, and nothing else:
  Version   — CLASSIFIER_VERSION, bumped when the rules change
  Paths     — probe/exploit/dropper/convention patterns, plus the SQL LIKE chains
              derived from them (the derivation belongs next to the list it reads)
  Needles   — user-agent and reverse-DNS substrings per operator family
  Thresholds — the calibrated numbers, in one block with their measurements

No SQL is executed here and no decision is made here; see rules.py for the chain
and evidence_sql.py for the query that fills it.
"""

from __future__ import annotations

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
CLASSIFIER_VERSION = "6"

# The probe paths that mark a request as scanning. Defined once: the classifier
# counts them per IP, the Overview's "Needs attention" ranks them by distinct IPs.
#
# Site-specific by design: this site is fully static and has no login, so '%.php%',
# '%/login%' and '%/admin%' cannot match anything legitimate here. On a deployment
# that actually serves PHP or an admin area, drop those three.
_SCANNER_PATH_PATTERNS = (
    "%/.env%",
    "%/.git/%",
    "%actuator%",
    "%wp-admin%",
    "%wp-config%",
    "%wp-login%",
    "%/wp-json/%",
    "%rest_route%",
    "%xmlrpc%",
    "%/cgi-bin/%",
    "%phpinfo%",
    "%phpmyadmin%",
    "%/.aws/%",
    "%.sql%",
    "%docker-compose%",
    "%kubernetes%",
    "%terraform%",
    "%credentials%",
    "%database.yml%",
    "%/boaform/%",  # router botnet login probe
    "%hnap1%",  # D-Link HNAP RCE
    "%/geoserver%",
    "%/solr/%",
    "%/jenkins%",
    "%/telnet%",
    "%.php%",  # site serves no PHP
    "%/login%",  # site has no login
    "%/admin%",  # site has no admin area
    "%/mcp%",  # AI agent endpoint probe
    "%/sse%",
)

# Non-HTTP request bodies that carry an actual payload rather than a protocol error.
# nginx cannot parse these into method/URI, so log_processor stores the raw line as
# the path — that is where the shell command or dropper URL ends up.
_PAYLOAD_ABUSE_PATTERNS = (
    "%wget%",
    "%curl %",
    "%chmod%",
    "%busybox%",
    "%/bin/sh%",
    "%rm+-rf%",
    "%rm -rf%",
    "%mozi%",
    "%gpon%",
    "%jsonrpc%",
    "%/shell%",
    "%t3 1%",  # Oracle WebLogic T3 handshake
)

# Multi-architecture dropper filenames — a request for one is a botnet trying to
# fetch its payload from a host it believes is already compromised.
_DROPPER_SUFFIXES = (
    "arm",
    "arm5",
    "arm6",
    "arm7",
    "mips",
    "mpsl",
    "x86",
    "x86_64",
    "m68k",
    "sh4",
    "spc",
    "arc",
    "ppc",
)


def _scanner_path_match(column: str = "v.path") -> str:
    return " OR ".join(f"{column} LIKE '{p}'" for p in _SCANNER_PATH_PATTERNS)


_SCANNER_PATH_MATCH = _scanner_path_match()
_PAYLOAD_ABUSE_MATCH = " OR ".join(f"LOWER(v.path) LIKE '{p}'" for p in _PAYLOAD_ABUSE_PATTERNS)
_DROPPER_MATCH = " OR ".join(f"LOWER(v.path) LIKE '%.{s}'" for s in _DROPPER_SUFFIXES)

# Request lines nginx could not parse as HTTP at all.
_NON_HTTP_METHODS = "v.method IN ('NON-HTTP', 'TLS', 'UNKNOWN')"

# Well-known convention files. Asking for one and getting a 404 is protocol, not
# probing: security.txt is RFC 9116, ads.txt is an IAB standard, llms.txt an AI-crawler
# convention, and /.well-known/ is the reserved namespace (RFC 8615). Counting these
# toward the error rate labelled 42 production IPs as vulnerability-probers whose only
# "offence" was asking politely where to report a vulnerability.
_CONVENTION_404_PATTERNS = (
    "%security.txt",
    "%ads.txt",
    "%llms.txt",
    "%humans.txt",
    "%robots.txt",
    "%sitemap%.xml",
    "/.well-known/%",
    "/favicon.ico",
    "/apple-touch-icon%",
)
_CONVENTION_404_MATCH = " OR ".join(f"v.path LIKE '{p}'" for p in _CONVENTION_404_PATTERNS)


# ip-api's `hosting` flag misses whole operators: against a live log it did not
# flag Akamai (which now carries Linode's VPS ranges), Server Mania, PureVoltage or
# Cherry Servers, so 29 rented boxes sat in humans/*. These names supplement the flag.
#
# Cloudflare is deliberately ABSENT. Its ranges carry WARP, a consumer VPN: all 32
# Cloudflare IPs in the human cohort were proxy-flagged, 23 fetched the JS-only page
# fragments and 22 sent Sec-Fetch — that is a person, not a rented box. Matching a bare
# "cloud" substring would have swept every one of them up.
_CLOUD_ISP_PATTERNS = (
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
    "linode",
    "akamai",
    "oracle",
    "alibaba",
    "tencent",
    "huawei cloud",
    "datacamp",
    "m247",
    "vultr",
    "contabo",
    "leaseweb",
    "choopa",
    "scaleway",
    "upcloud",
    "cherry servers",
    "server mania",
    "purevoltage",
    "hostinger",
    "ionos",
)


def _is_cloud_isp(isp: str) -> bool:
    """True when the ISP name names a cloud/VPS operator with no consumer customers."""
    return any(name in isp for name in _CLOUD_ISP_PATTERNS)


# Named organisations that publish their scanning identity — attribution, not tooling.
_RESEARCHER_RDNS = ("shodan", "censys", "shadowserver", "internet-census", "leakix")
_RESEARCHER_UAS = (
    "censysinspect",
    "shodan",
    "l9explore",
    "leakix",
    "palo alto",
    "expanse",
    "modatscanner",
    "internet-measurement",
    "bitsight",
    "netsystemsresearch",
)
# Tools anyone can run. They name the software, so that is all we claim.
_SCANNING_TOOL_UAS = ("zgrab", "masscan", "libredtail", "nmap", "zmap", "nuclei")

_SEARCH_RDNS = ("googlebot", "bingbot", "yandex", "duckduck", "baidu", "seznam", "msn.com")
_SEARCH_UAS = (
    "googlebot",
    "bingbot",
    "yandexbot",
    "baiduspider",
    "duckduckbot",
    "seznambot",
    "sogou",
    "petalbot",
)
# Matched against reverse DNS on its own, before any UA claim, so a needle here
# has to be unambiguous as a hostname: applebot.apple.com and not "apple",
# because the match is a substring one and the full host is what Apple publishes
# (17-x-x-x.applebot.apple.com). Corroborating a UA claim is a separate, wider
# question — see _CRAWLER_ORIGINS.
_AI_RDNS = ("openai", "anthropic", "bytedance", "perplexity", "applebot.apple.com")
_AI_UAS = ("gptbot", "claudebot", "bytespider", "perplexitybot", "ccbot", "applebot", "oai-search")
_SEO_UAS = ("ahrefsbot", "semrushbot", "mj12bot", "dotbot", "rogerbot", "blexbot", "seokicks")

# Where each declared crawler legitimately runs, matched against the network owner
# (ip-api's org and ASN) when reverse DNS cannot decide.
#
# Reverse DNS alone was the whole verification until v6, and it disqualified the
# operators who publish no PTR record — which turned out to be most of the large
# ones. Of 91 addresses filed as impersonators, 88 were the real crawler: 41
# OpenAI (GPTBot and OAI-SearchBot, crawling from Azure), 22 Applebot, 10
# ClaudeBot on AWS under Anthropic's own org, 4 SeznamBot, 1 DuckDuckBot on Azure.
# The org field named the operator in every one of those cases.
#
# Two kinds of needle, and the difference matters when reading a verdict:
# operator-owned networks (google, yandex, seznam, apple, anthropic) prove the
# claim, while the provider-level ones — microsoft for the crawlers that run on
# Azure, amazon for CommonCrawl — only place the address on the right platform.
# A forged GPTBot UA from any Azure box passes on that second kind. Narrowing it
# needs the operators' published IP ranges, i.e. a network dependency this
# service does not take.
_CRAWLER_ORIGINS: dict[str, tuple[str, ...]] = {
    "googlebot": ("googlebot.com", "google"),
    "bingbot": ("search.msn.com", "microsoft", "bing"),
    "yandexbot": ("yandex",),
    "baiduspider": ("baidu",),
    "duckduckbot": ("duckduckgo", "microsoft"),
    "seznambot": ("seznam",),
    "sogou": ("sogou",),
    "petalbot": ("petalsearch", "huawei"),
    "gptbot": ("openai", "microsoft"),
    "oai-search": ("openai", "microsoft"),
    "claudebot": ("anthropic",),
    "bytespider": ("bytedance",),
    "perplexitybot": ("perplexity",),
    "ccbot": ("commoncrawl", "amazon"),
    "applebot": ("apple",),
}

# UAs that name an HTTP client library. "How the request was made", not "who made it".
_HTTP_CLIENT_UAS = (
    "curl/",
    "wget/",
    "go-http-client",
    "python-requests",
    "python-urllib",
    "java/",
    "okhttp",
    "libwww-perl",
    "guzzlehttp",
    "axios/",
    "node-fetch",
)


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
