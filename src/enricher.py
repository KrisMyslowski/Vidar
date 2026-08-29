"""Background IP enrichment — builds the intelligence pool from raw IPs.

Five data sources, called in sequence per batch:
  1. ip-api.com   — geo, ASN, proxy/hosting/mobile flags (batch, free tier)
  2. Shodan       — open ports, hostnames, CVEs (per IP, no API key)
  3. Reverse DNS  — forward-confirmed PTR; the classifier checks crawler claims against it
  4. Tor Project  — exit node list (downloaded once, cached 24 h)
  5. DNSBL        — blocklist lookups; the returned A record is the answer, see _dnsbl_lookup
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .config import settings
from .db import get_conn, run_db
from .queries import (
    classify_ip,
    get_ip_intel_bulk,
    get_ips_without_rdns,
    get_stale_ips,
    get_unenriched_ips,
    mark_enrichment_failed,
    set_reverse_dns,
    set_visitor_class,
    upsert_ip_intel,
)

logger = logging.getLogger("vidar.enricher")

BATCH_URL = "http://ip-api.com/batch"  # free tier = HTTP only
SHODAN_URL = "https://internetdb.shodan.io"  # free, no API key
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
BATCH_FIELDS = (
    "status,message,query,country,countryCode,city," "lat,lon,isp,org,as,proxy,hosting,mobile"
)

# Timing (implementation-specific; not operator-tunable)
_RATE_LIMIT_DEFAULT_TTL_S = 60  # fallback if ip-api X-Ttl header is missing
_RATE_LIMIT_MAX_TTL_S = 900  # ceiling on what we will believe from that header
_BATCH_INTERVAL_S = 4.5  # ~13 req/min, under 15 req/min free-tier limit
_WORKER_ERROR_SLEEP_S = 10
_WORKER_ERROR_SLEEP_MAX_S = 300

# In-memory Tor exit node cache (populated by _load_tor_exits)
_tor_exits: set[str] = set()
_tor_exits_loaded_at: float = 0
_tor_exits_failed_at: float = 0
_TOR_RETRY_AFTER_FAILURE_S = 300
# Attempts within one call, before the 300 s cooldown above starts. A single
# ConnectError used to cost five minutes of no Tor data even when the next
# packet would have got through, which is what a blip on the way to
# torproject.org looks like. Three tries a second apart cost four seconds in the
# bad case and nothing in the good one.
_TOR_DOWNLOAD_ATTEMPTS = 3
_TOR_RETRY_BACKOFF_S = 1.0

# Semaphores and lock — must be initialized inside the asyncio event loop.
# Call _init_async_globals() once from main.py lifespan before tasks start.
_SHODAN_SEM: asyncio.Semaphore | None = None
_DNSBL_SEM: asyncio.Semaphore | None = None
_tor_exits_lock: asyncio.Lock | None = None


def _init_async_globals() -> None:
    """Initialize asyncio primitives. Must be called once inside the event loop (lifespan)."""
    global _SHODAN_SEM, _DNSBL_SEM, _tor_exits_lock
    _SHODAN_SEM = asyncio.Semaphore(settings.shodan_concurrency)
    _DNSBL_SEM = asyncio.Semaphore(settings.dnsbl_concurrency)
    _tor_exits_lock = asyncio.Lock()
    _shodan_gate.reset()


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _stale_before(ttl_days: int) -> str:
    """The fetched_at below which cached enrichment counts as stale."""
    return (datetime.now(timezone.utc) - timedelta(days=ttl_days)).isoformat()


def _rate_limit_pause(header: str | None) -> int:
    """How long to wait when ip-api says it has had enough, from its X-Ttl.

    The header is whatever the other end sent. Taken at face value a negative
    value made the wait a no-op and kept the worker hammering, and a large one
    parked it for as long as the number said — a typo at the far end, or a bad
    proxy, could stop enrichment for a day. One second is added because waiting
    exactly as long as the window is a race against it.
    """
    ttl = _safe_int(header, _RATE_LIMIT_DEFAULT_TTL_S)
    return min(max(ttl, 0) + 1, _RATE_LIMIT_MAX_TTL_S)


def _error_backoff_s(consecutive_errors: int) -> float:
    """Exponential backoff for repeated worker errors: 10s, 20s, 40s, ... capped at 300s."""
    return min(
        _WORKER_ERROR_SLEEP_S * 2 ** max(0, consecutive_errors - 1), _WORKER_ERROR_SLEEP_MAX_S
    )


# ── ip-api.com ───────────────────────────────────────────────────────────────


def _parse_api_result(item: dict) -> dict | None:
    """Convert a single ip-api.com response item to a partial ip_intel row.

    Note: fetched_at is NOT set here — it is stamped after all enrichment steps
    (Shodan, Tor, DNSBL) complete in enrich_batch().
    """
    if item.get("status") != "success":
        logger.debug("Enrichment failed for %s: %s", item.get("query"), item.get("message"))
        return None
    return {
        "ip": item["query"],
        "country": item.get("country", ""),
        "country_code": item.get("countryCode", ""),
        "city": item.get("city", ""),
        "lat": item.get("lat", 0.0),
        "lon": item.get("lon", 0.0),
        "isp": item.get("isp", ""),
        "org": item.get("org", ""),
        "asn": item.get("as", ""),
        "is_proxy": item.get("proxy", False),
        "is_hosting": item.get("hosting", False),
        "is_mobile": item.get("mobile", False),
    }


# ── Shodan ───────────────────────────────────────────────────────────────────


# What Shodan returns for a host it has no record of. The keys are present and
# empty, which is an answer: whatever we knew about this host's ports is no
# longer true. Not the same thing as a lookup that never completed.
_SHODAN_NOTHING_KNOWN = {
    "open_ports": "",
    "tags": "",
    "hostnames": "",
    "cpes": "",
    "vulns": "",
}

# Set by _fetch_shodan when Shodan rate-limits us, read and cleared once per
# batch. Per-IP it would be up to 100 identical warnings in one round.
_shodan_rate_limited = False


class _RateGate:
    """Paces outbound requests, and stops entirely when the server pushes back.

    _SHODAN_SEM bounds how many lookups run at once and says nothing about how
    many run per minute. Draining a backlog meant 100 requests every 4.5 s —
    about 1,300 a minute at a free service that publishes no limit — and a 429
    came back as "no data", so nothing ever slowed down.
    """

    def __init__(self, per_minute: int) -> None:
        self._interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self._next_at = 0.0
        self._resume_at = 0.0
        self._lock: asyncio.Lock | None = None

    def reset(self) -> None:
        """Drop the pacing and any cooldown, and let the next loop own the lock.

        Not constructed here: reset() is also called from test teardown, which
        is not inside an event loop. wait() only ever runs in one.
        """
        self._lock = None
        self._next_at = 0.0
        self._resume_at = 0.0

    def in_cooldown(self) -> bool:
        return time.monotonic() < self._resume_at

    def back_off(self, seconds: float) -> None:
        self._resume_at = max(self._resume_at, time.monotonic() + seconds)

    async def wait(self) -> None:
        """Block until this caller's turn. Serialised so the spacing holds."""
        if not self._interval:
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + self._interval
        if delay:
            await asyncio.sleep(delay)


_shodan_gate = _RateGate(settings.shodan_requests_per_minute)


def snapshot() -> dict:
    """What the enrichment worker is currently doing, for /settings/status.

    The state lives in module globals because that is where a worker's state
    belongs; this is the one place that hands it out, so a route never reaches
    past the underscore and there is a single thing to change when the worker
    grows a new mood.
    """
    # time.time(), not monotonic: _load_tor_exits stamps the wall clock, and
    # subtracting one from the other reported the list as 496,394 hours old.
    age = time.time() - _tor_exits_loaded_at if _tor_exits_loaded_at else None
    return {
        "tor_exits": len(_tor_exits),
        "tor_age_seconds": age,
        "shodan_rate_limited": _shodan_rate_limited,
        "shodan_cooling_down": _shodan_gate.in_cooldown(),
    }


def _report_shodan_silence(silent: int, total: int) -> None:
    """Say when Shodan stopped answering, once per batch.

    Per-IP this is a DEBUG line, and has to be: a hundred lookups produce a
    hundred messages, and an occasional timeout is not worth an operator's
    attention. The batch total is what distinguishes "one slow lookup" from
    "Shodan has been unreachable for a day" — and since a silent lookup now
    preserves the stored data instead of erasing it, nothing else would show it.
    """
    if not silent:
        return
    reason = " (we are being rate-limited)" if _shodan_rate_limited else ""
    log = logger.warning if silent == total else logger.info
    log("Shodan did not answer %d of %d lookups%s", silent, total, reason)


async def _fetch_shodan(ip: str, client: httpx.AsyncClient) -> dict | None:
    """Fetch open ports, hostnames, CPEs and CVEs from Shodan InternetDB.

    Returns a dict when Shodan answered — empty values included, see
    _SHODAN_NOTHING_KNOWN — and None when it did not answer at all: timeout,
    connection error, 429, 5xx, unparseable body. The caller writes an answer
    straight through to the child tables, which delete before they insert, so
    the two must not look alike. They did, and a single Shodan hiccup during
    re-enrichment wiped the ports, CVEs, CPEs and tags of every IP in the batch.
    """
    global _shodan_rate_limited
    if _shodan_gate.in_cooldown():
        # Told to stop. Not asking again is the whole point of being told.
        return None
    try:
        await _shodan_gate.wait()
        resp = await client.get(f"{SHODAN_URL}/{ip}", timeout=5.0)
        if resp.status_code == 404:
            return dict(_SHODAN_NOTHING_KNOWN)
        if resp.status_code == 429:
            # Worth telling apart from a timeout: it is the one Shodan failure
            # we are causing ourselves, and the batch summary names it.
            _shodan_rate_limited = True
            _shodan_gate.back_off(settings.shodan_cooldown_seconds)
        resp.raise_for_status()
        data = resp.json()
        hostnames = ",".join(data.get("hostnames", []))
        result = {
            "open_ports": ",".join(str(p) for p in data.get("ports", [])),
            "tags": ",".join(data.get("tags", [])),
            "hostnames": hostnames,
            "cpes": ",".join(data.get("cpes", [])),
            "vulns": ",".join(data.get("vulns", [])),
        }
        if hostnames:
            # Only ever a name we actually got. reverse_dns holds forward-confirmed
            # PTR data from the step below, and an empty Shodan answer is not a
            # reason to drop it — set_reverse_dns() makes the same call.
            result["reverse_dns"] = hostnames
        return result
    except Exception as e:
        logger.debug("Shodan lookup failed for %s: %s", ip, e)
        return None


# ── Tor exits ────────────────────────────────────────────────────────────────


async def _load_tor_exits(client: httpx.AsyncClient) -> set[str] | None:
    """Download and cache Tor exit node list (refreshed every 24h).

    Returns None when no list is available at all, so the caller leaves is_tor
    as it stands. An empty set here reads as "no IP is an exit node", and
    writing that over a batch turns one failed download into a batch of IPs
    recorded as not-Tor. A stale list is still returned in preference to None:
    an exit list from yesterday is evidence, an empty one is not.
    """
    global _tor_exits, _tor_exits_loaded_at, _tor_exits_failed_at

    def _fresh() -> bool:
        return bool(_tor_exits) and (time.time() - _tor_exits_loaded_at) < (
            settings.tor_cache_ttl_seconds
        )

    if _fresh():
        return _tor_exits
    if time.time() - _tor_exits_failed_at < _TOR_RETRY_AFTER_FAILURE_S:
        # A failed download used to leave _tor_exits_loaded_at unstamped, so the
        # next batch tried again — about thirteen attempts a minute at
        # torproject.org, for as long as the outage lasted.
        return _tor_exits or None

    async with _tor_exits_lock:
        # Re-read the clock rather than reuse it: waiting on the lock can itself
        # outlast a 15 s download, and the pre-lock value would call a list that
        # another waiter just fetched stale.
        if _fresh():
            return _tor_exits
        now = time.time()
        last: Exception | None = None
        for attempt in range(1, _TOR_DOWNLOAD_ATTEMPTS + 1):
            try:
                resp = await client.get(TOR_EXIT_URL, timeout=15.0)
                resp.raise_for_status()
                _tor_exits = {
                    line.strip()
                    for line in resp.text.splitlines()
                    if line.strip() and not line.startswith("#")
                }
                _tor_exits_loaded_at = now
                _tor_exits_failed_at = 0
                logger.info("Loaded %d Tor exit nodes", len(_tor_exits))
                return _tor_exits
            except Exception as e:
                last = e
                if attempt < _TOR_DOWNLOAD_ATTEMPTS:
                    await asyncio.sleep(_TOR_RETRY_BACKOFF_S)

        _tor_exits_failed_at = time.time()
        # The class name carries the reason on its own when str(e) is empty,
        # which is what httpx.ConnectTimeout gives — the likeliest failure
        # here, and the one that used to log a bare trailing colon.
        reason = f"{type(last).__name__}: {last}" if str(last) else type(last).__name__
        # Say what the signal does in the meantime. A failure that only reports
        # itself leaves the reader to work out whether Tor detection is off or
        # merely old, and those are different problems.
        if _tor_exits:
            age_h = (time.time() - _tor_exits_loaded_at) / 3600
            fallback = f"keeping the {len(_tor_exits)} exits from {age_h:.1f} h ago"
        else:
            fallback = "no list has ever loaded, so the Tor signal stays empty"
        logger.warning(
            "Tor exit list failed %d times, not retrying for %ds — %s: %s",
            _TOR_DOWNLOAD_ATTEMPTS,
            _TOR_RETRY_AFTER_FAILURE_S,
            fallback,
            reason,
        )
    return _tor_exits or None


# ── DNSBL ────────────────────────────────────────────────────────────────────


# A DNSBL answers in 127.0.0.0/8, and the *value* is the answer — presence of any
# A record is not a listing. Spamhaus reserves 127.255.255.0/24 for query errors:
#
#   127.0.0.2 / .3      SBL / CSS          → listed
#   127.0.0.4 – .7      XBL                → listed
#   127.0.0.10 / .11    PBL                → listed
#   127.255.255.252     wrong zone name    → error
#   127.255.255.254     open/public resolver used   → error
#   127.255.255.255     query quota exceeded        → error
#
# Treating "it resolved" as "it is listed" marks essentially every IP as listed,
# because the container resolves through Docker's embedded DNS to a public upstream
# and Spamhaus answers 127.255.255.254 to all of it.
#
# TODO: parsing alone only makes the answer honest, not useful — the legacy zone
# still refuses us, so nothing gets recorded at all. Set DNSBL_DQS_KEY (free
# Spamhaus Data Query Service) to get real data; see _dnsbl_host(). Alternatives
# weighed in docs/data-reference.md §4.2.8: AbuseIPDB (free API, 1k
# checks/day, richer than a boolean but below our IP volume) and the Spamhaus rsync
# feed (needs a local mirroring DNS server).
_DNSBL_ERROR_PREFIX = "127.255.255."


def _dnsbl_lookup(reversed_ip: str, provider: str) -> bool | None:
    """Query one DNSBL. True = listed, False = not listed, None = provider error.

    None is distinct from False on purpose: it means the blocklist declined to answer
    (open resolver, quota, bad zone), so the caller can report the misconfiguration
    instead of silently recording every IP as clean.
    """
    try:
        answers = socket.getaddrinfo(f"{reversed_ip}.{provider}", None, socket.AF_INET)
    except socket.gaierror:
        return False  # NXDOMAIN — the documented "not listed" response
    except Exception:
        return None

    listed = False
    for info in answers:
        addr = info[4][0]
        if addr.startswith(_DNSBL_ERROR_PREFIX):
            return None
        if addr.startswith("127."):
            listed = True
    return listed


def _dnsbl_host(provider: str) -> str:
    """Query zone for a provider, routed through Spamhaus DQS when a key is set.

    The legacy public zones are exactly what refuses queries from public resolvers,
    so a key is what makes Spamhaus usable at all from a container.
    """
    key = settings.dnsbl_dqs_key.strip()
    if key and provider.endswith("spamhaus.org"):
        zone = provider.split(".", 1)[0]  # zen.spamhaus.org -> zen
        return f"{key}.{zone}.dq.spamhaus.net"
    return provider


# Providers already reported as misconfigured — one warning each, not one per IP.
_DNSBL_WARNED: set[str] = set()


def _warn_dnsbl_error(provider: str) -> None:
    if provider not in _DNSBL_WARNED:
        _DNSBL_WARNED.add(provider)
        logger.warning(
            "DNSBL %s refused the query (127.255.255.x). It contributes nothing "
            "until this is fixed — set DNSBL_DQS_KEY for Spamhaus, or point the "
            "container at a non-public DNS resolver.",
            provider,
        )


async def _with_dns_timeout(coro, on_timeout):
    """Bound the *wait* on a DNS lookup, which is all that can be bounded.

    socket.getaddrinfo takes its timeout from the resolver configuration and
    nothing here can shorten it, and a thread started by to_thread cannot be
    cancelled. What this stops is the enrichment worker waiting on it: a
    black-holed resolver otherwise parks a batch of 100 IPs for minutes, and the
    threads outlive a shutdown either way.
    """
    try:
        return await asyncio.wait_for(coro, timeout=settings.dns_timeout_seconds)
    except asyncio.TimeoutError:
        return on_timeout


async def _bounded_dnsbl_lookup(reversed_ip: str, provider: str) -> bool | None:
    """DNSBL lookup with semaphore to bound thread pool growth."""
    async with _DNSBL_SEM:
        return await _with_dns_timeout(
            asyncio.to_thread(_dnsbl_lookup, reversed_ip, _dnsbl_host(provider)), None
        )


def _reverse_ipv6(ip: str) -> str | None:
    """Nibble-reverse an IPv6 address for DNSBL queries (RFC 5782).

    e.g. 2001:db8::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
    Returns None if `ip` is not a valid IPv6 address.
    """
    try:
        addr = ipaddress.IPv6Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return None
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles))


async def _check_dnsbl(ip: str) -> tuple[bool, str] | None:
    """Check an IP against configured DNS blocklists.

    IPv4 uses dotted-quad reversal; IPv6 uses nibble reversal (RFC 5782). Providers
    that don't support IPv6 simply return NXDOMAIN, which reads as "not listed".

    Returns None when no provider produced a usable answer — every one errored,
    or the address cannot be queried at all. _dnsbl_lookup already keeps "the
    blocklist declined" apart from "not listed"; that distinction was then
    thrown away here, and a refusing zone or a dead resolver was stored as a
    clean record. One provider answering is enough to record what it said.
    """
    if "." in ip and ":" not in ip:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        reversed_ip = ".".join(reversed(parts))
    elif ":" in ip:
        reversed_ip = _reverse_ipv6(ip)
        if reversed_ip is None:
            logger.debug("Skipping DNSBL check for invalid IPv6 address: %s", ip)
            return None
    else:
        return None

    tasks = [_bounded_dnsbl_lookup(reversed_ip, p) for p in settings.dnsbl_providers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    answered = False
    sources = []
    for provider, result in zip(settings.dnsbl_providers, results, strict=True):
        if result is True:
            answered = True
            sources.append(provider)
        elif result is False:
            answered = True
        else:
            # None, or an exception object from gather(return_exceptions=True).
            _warn_dnsbl_error(provider)

    if not answered:
        return None
    return bool(sources), ",".join(sources)


# ── Reverse DNS ──────────────────────────────────────────────────────────────


def _reverse_dns_lookup(ip: str) -> str:
    """Forward-confirmed reverse DNS (FCrDNS) for one IP. Empty string if unverified.

    A PTR record is published by whoever controls the IP block, so on its own it can
    claim any name — "crawl-66-249.googlebot.com" costs an attacker nothing. Only a
    forward lookup of that name resolving back to the same IP proves the claim, which
    is exactly what the classifier needs to tell Googlebot from something wearing its
    User-Agent. An unverifiable name is discarded rather than stored.
    """
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        return ""  # no PTR, resolver failure, or a malformed address
    try:
        forward = socket.getaddrinfo(host, None)
    except Exception:
        return ""
    if any(info[4][0] == ip for info in forward):
        return host
    logger.debug("Reverse DNS for %s claims %s but does not forward-confirm", ip, host)
    return ""


async def _bounded_reverse_dns(ip: str) -> str:
    async with _DNSBL_SEM:
        return await _with_dns_timeout(asyncio.to_thread(_reverse_dns_lookup, ip), "")


def _load_rdns_candidates() -> list[str]:
    """One round's IPs. Blocking; runs in a thread."""
    with get_conn() as conn:
        return get_ips_without_rdns(conn)


def _store_rdns_results(pairs: list[tuple[str, str]]) -> int:
    """Record one round's PTR results; returns how many resolved. Blocking.

    Every IP is stamped whether or not it had a record — set_reverse_dns writes
    rdns_checked_at either way, which is what ends the loop above.
    """
    with get_conn() as conn:
        for ip, hostname in pairs:
            set_reverse_dns(conn, ip, hostname)
    return sum(1 for _, hostname in pairs if hostname)


async def reverse_dns_backfill() -> int:
    """One-off PTR pass over IPs enriched before reverse DNS was resolved locally.

    The crawler rules ask whether an IP's reverse DNS backs its User-Agent claim, so
    without this every pre-existing crawler on a cloud IP reads as an impersonator until
    its 30-day enrichment TTL expires.

    Runtime is DNS-bound, not API-bound: no rate limit, but IPs in unresponsive zones
    cost a full resolver timeout each, so a large backlog can take tens of minutes. It
    runs in the background and the dashboard serves normally throughout. Note it shares
    _DNSBL_SEM with the blocklist lookups, so live enrichment is throttled a little while
    the backlog drains — deliberate, to bound total DNS concurrency.

    Returns how many IPs were resolved.

    Both halves go through run_db() for the reason _select_batch and
    _persist_batch do: synchronous sqlite3 in a coroutine stalls the loop the
    tailer runs on. This read its IPs and wrote up to 500 UPDATEs per round
    inline, at startup, where the backlog is largest.
    """
    resolved = 0
    while True:
        ips = await run_db(_load_rdns_candidates)
        if not ips:
            return resolved
        results = await asyncio.gather(*[_bounded_reverse_dns(ip) for ip in ips])
        resolved += await run_db(_store_rdns_results, list(zip(ips, results, strict=True)))
        await asyncio.sleep(0)  # yield between batches


# ── Orchestration ────────────────────────────────────────────────────────────


async def enrich_batch(
    ips: list[str], client: httpx.AsyncClient
) -> tuple[list[dict], list[str]] | None:
    """Enrich one batch of IPs through all four providers.

    Order: ip-api.com (geo/ASN) → Shodan (ports) → Tor → DNSBL.
    Returns (enriched, failed_ips): partial ip_intel rows ready for upsert (fetched_at
    stamped at end), plus the IPs ip-api answered with status=fail (invalid/reserved —
    a permanent condition the worker records via mark_enrichment_failed).

    Returns None when the batch itself failed — a network error, a timeout, an
    unparseable body. That used to be ([], []) too, indistinguishable from "no
    work to do", so the worker counted a sustained outage as success and reset
    its backoff: the same hundred IPs, every 4.5 s, forever, one traceback per
    attempt. A 429 is not a failure in that sense — we were told to wait and we
    waited — so it still returns ([], []).
    """
    if not ips:
        return [], []

    batch = ips[: settings.enrichment_batch_size]
    try:
        resp = await client.post(
            BATCH_URL,
            params={"fields": BATCH_FIELDS},
            json=batch,
            timeout=10.0,
        )

        rl_ttl = _rate_limit_pause(resp.headers.get("X-Ttl"))

        if resp.status_code == 429:
            logger.warning("HTTP 429 — rate limited, waiting %d seconds", rl_ttl)
            await asyncio.sleep(rl_ttl)
            return [], []

        # Respect X-Rl (remaining) and X-Ttl (seconds until reset) headers
        rl_remaining = _safe_int(resp.headers.get("X-Rl"), 1)
        if rl_remaining <= 0:
            logger.warning("Rate limited, sleeping %d seconds", rl_ttl)
            await asyncio.sleep(rl_ttl)

        resp.raise_for_status()
        results = resp.json()

        enriched: list[dict] = []
        failed_ips: list[str] = []
        for item in results:
            parsed = _parse_api_result(item)
            if parsed:
                enriched.append(parsed)
            elif item.get("query"):
                failed_ips.append(item["query"])

        async def _fetch_shodan_bounded(ip: str) -> dict | None:
            async with _SHODAN_SEM:
                return await _fetch_shodan(ip, client)

        # Each source below contributes keys only when it answered. A key that
        # never lands leaves the stored column alone (see upsert_ip_intel), which
        # is the whole reason these three checks are not `if result:` — an empty
        # answer is still an answer, and None is the absence of one.
        global _shodan_rate_limited
        _shodan_rate_limited = False
        shodan_results = await asyncio.gather(*[_fetch_shodan_bounded(e["ip"]) for e in enriched])
        for entry, shodan in zip(enriched, shodan_results, strict=True):
            if shodan is not None:
                entry.update(shodan)
        _report_shodan_silence(sum(s is None for s in shodan_results), len(enriched))

        # A real PTR lookup, preferred over Shodan's hostnames: Shodan only knows
        # hosts it has scanned, which left reverse_dns empty for ~85% of IPs — and
        # the crawler-verification rules in the classifier are built on it.
        rdns_results = await asyncio.gather(*[_bounded_reverse_dns(e["ip"]) for e in enriched])
        for entry, rdns in zip(enriched, rdns_results, strict=True):
            if rdns:
                entry["reverse_dns"] = rdns

        tor_exits = await _load_tor_exits(client)
        if tor_exits is not None:
            for entry in enriched:
                entry["is_tor"] = entry["ip"] in tor_exits

        if settings.dnsbl_enabled:
            dnsbl_results = await asyncio.gather(*[_check_dnsbl(e["ip"]) for e in enriched])
            for entry, verdict in zip(enriched, dnsbl_results, strict=True):
                if verdict is not None:
                    entry["dnsbl_listed"], entry["dnsbl_sources"] = verdict

        now_iso = datetime.now(timezone.utc).isoformat()
        for entry in enriched:
            entry["fetched_at"] = now_iso

        return enriched, failed_ips

    except Exception as e:
        logger.exception("Batch enrichment failed: %s", e)
        return None


def _select_batch(pending: list[str]) -> list[str]:
    """Choose the IPs for one enrichment round. Blocking; runs in a thread.

    `pending` is what the queue handed over. It is topped up from the database
    with IPs that were never enriched and then with ones whose cache has
    expired, and anything already fresh is dropped — including from the queue,
    which used to bypass the check entirely.
    """
    with get_conn() as conn:
        if len(pending) < settings.enrichment_batch_size:
            unenriched = get_unenriched_ips(conn, settings.enrichment_batch_size - len(pending))
            pending.extend(ip for ip in unenriched if ip not in pending)

        if len(pending) < settings.enrichment_batch_size:
            stale = get_stale_ips(
                conn,
                settings.enrichment_cache_ttl_days,
                settings.enrichment_batch_size - len(pending),
            )
            pending.extend(ip for ip in stale if ip not in pending)

        existing_intel = get_ip_intel_bulk(conn, pending)

    # An IP arrives from the queue on its first sighting in this process, and
    # `seen_ips` in the tailer is per-process: every restart re-queues every
    # active IP. Without this check that meant re-enriching up to 50,000 IPs
    # against ip-api and Shodan minutes after the last time, past a 30-day cache
    # that already held the answers.
    cutoff = _stale_before(settings.enrichment_cache_ttl_days)
    fresh: list[str] = []
    expired: list[str] = []
    for ip in pending:
        intel = existing_intel[ip]
        if intel is None:
            fresh.append(ip)
        elif (intel.get("fetched_at") or "") < cutoff:
            expired.append(ip)
    return fresh + expired


def _persist_batch(results: list[dict], failed_ips: list[str]) -> None:
    """Write one round's results. Blocking; runs in a thread.

    classify_ip runs once per IP and is a correlated aggregate over that IP's
    whole history — a hundred of them per batch, which is why this is not
    allowed anywhere near the event loop.
    """
    with get_conn() as conn:
        for intel in results:
            upsert_ip_intel(conn, intel)
            set_visitor_class(conn, intel["ip"], classify_ip(conn, intel["ip"]))
        # Stub rows for permanent ip-api failures — keeps them out of
        # get_unenriched_ips() until the staleness TTL expires.
        now_iso = datetime.now(timezone.utc).isoformat()
        for ip in failed_ips:
            mark_enrichment_failed(conn, ip, now_iso)
            set_visitor_class(conn, ip, classify_ip(conn, ip))


async def enrichment_worker(new_ips_queue: asyncio.Queue) -> None:
    """Background worker: collect IPs from queue + DB, enrich in batches, persist results."""
    pending: list[str] = []
    consecutive_errors = 0

    async with httpx.AsyncClient() as client:
        while True:
            try:
                # Drain queue into pending list (non-blocking)
                while len(pending) < settings.enrichment_batch_size:
                    try:
                        ip = new_ips_queue.get_nowait()
                        pending.append(ip)
                    except asyncio.QueueEmpty:
                        break

                # Off the loop, like every other database access outside the
                # request path: selection is three queries, and persisting runs
                # classify_ip once per IP — up to a hundred correlated aggregate
                # queries per batch, every 4.5 s, on the thread that also runs
                # the log tailer and serves the dashboard.
                to_enrich = await run_db(_select_batch, list(pending))
                pending.clear()

                if not to_enrich:
                    consecutive_errors = 0
                    await asyncio.sleep(5)
                    continue

                outcome = await enrich_batch(to_enrich, client)
                if outcome is None:
                    # The batch failed, not "there was nothing to do". Counting
                    # it as success is what kept the backoff below from ever
                    # engaging on a network fault.
                    consecutive_errors += 1
                    await asyncio.sleep(_error_backoff_s(consecutive_errors))
                    continue
                results, failed_ips = outcome

                if results or failed_ips:
                    await run_db(_persist_batch, results, failed_ips)
                    logger.info(
                        "Enriched %d, failed %d / %d IPs",
                        len(results),
                        len(failed_ips),
                        len(to_enrich),
                    )

                consecutive_errors = 0
                await asyncio.sleep(_BATCH_INTERVAL_S)

            except Exception:
                consecutive_errors += 1
                logger.exception(
                    "Error in enrichment worker (consecutive: %d)", consecutive_errors
                )
                await asyncio.sleep(_error_backoff_s(consecutive_errors))
