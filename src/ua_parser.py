"""User-Agent string parser — extracts browser, OS, and device type.

Wraps the `user_agents` library. When the library returns empty or "Other"
for a field, passive regex/substring fallbacks are applied to catch common
CLI tools and scanners (curl, wget, zgrab, CensysInspect, …) that the
library misclassifies.

Results are LRU-cached to avoid redundant parsing of repeated UA strings.
"""

from __future__ import annotations

import functools
import re
import types

from user_agents import parse

_UA_CACHE_SIZE = 512

_BROWSER_PATTERNS = [
    (re.compile(r"\bcurl/(\S+)", re.I), "curl"),
    (re.compile(r"\bwget/(\S+)", re.I), "wget"),
    (re.compile(r"\bpython-requests/(\S+)", re.I), "python-requests"),
    (re.compile(r"\bgo-http-client/(\S+)", re.I), "go-http-client"),
    (re.compile(r"\bzgrab(?:/(\S+)|\b)", re.I), "zgrab"),
    (re.compile(r"\bcensysinspect(?:/(\S+)|\b)", re.I), "CensysInspect"),
    (re.compile(r"\bl9explore(?:/(\S+)|\b)", re.I), "l9explore"),
    (re.compile(r"\blibredtail-http(?:/(\S+)|\b)", re.I), "libredtail-http"),
]


# ── Fallbacks ────────────────────────────────────────────────────────────────


def _fallback_browser(ua_string: str) -> str:
    lower = ua_string.lower()
    for pattern, name in _BROWSER_PATTERNS:
        m = pattern.search(ua_string)
        if not m:
            continue
        version = m.group(1) if m.lastindex and m.group(1) else ""
        return f"{name} {version}".strip()
    if "mozilla/5.0" in lower:
        return "Mozilla-compatible"
    return "Unknown"


def _fallback_os(ua_string: str) -> str:
    lower = ua_string.lower()
    if "windows" in lower:
        return "Windows"
    if "android" in lower:
        return "Android"
    if "iphone" in lower or "ipad" in lower or "ios" in lower:
        return "iOS"
    if "mac os" in lower or "macintosh" in lower:
        return "macOS"
    if "linux" in lower:
        return "Linux"
    if "freebsd" in lower:
        return "FreeBSD"
    return "Unknown"


def _fallback_device(ua_string: str) -> str:
    lower = ua_string.lower()
    if any(
        t in lower
        for t in (
            "bot",
            "crawler",
            "spider",
            "zgrab",
            "censys",
            "scan",
            "go-http-client",
            "curl/",
            "wget/",
            "python-requests",
        )
    ):
        return "Bot"
    if "mobile" in lower or "android" in lower or "iphone" in lower:
        return "Mobile"
    if "ipad" in lower or "tablet" in lower:
        return "Tablet"
    if "mozilla/5.0" in lower:
        return "Desktop"
    return "Unknown"


# ── Parser ───────────────────────────────────────────────────────────────────


@functools.lru_cache(maxsize=_UA_CACHE_SIZE)
def parse_user_agent(ua_string: str) -> types.MappingProxyType[str, str]:
    """Parse a UA string into browser (name+version), OS (name+version), and device type.

    Results are cached (LRU, max 512 entries) to avoid redundant parsing of repeated UA strings.
    """
    if not ua_string or ua_string.strip() in {"", "-"}:
        return types.MappingProxyType(
            {"browser": "No User-Agent", "os": "No User-Agent", "device": "Unknown"}
        )

    ua = parse(ua_string)

    browser = ua.browser.family or ""
    if ua.browser.version_string:
        browser += " " + ua.browser.version_string

    os_name = ua.os.family or ""
    if ua.os.version_string:
        os_name += " " + ua.os.version_string

    # is_bot is tested first on purpose: the library sets is_pc alongside is_bot for
    # any crawler whose UA carries a desktop platform token (most of them do, e.g.
    # "Mozilla/5.0 (Windows NT 10.0; compatible; SomeBot/1.0)"). Checking is_pc first
    # meant those never came out as "Bot".
    if ua.is_bot:
        device = "Bot"
    elif ua.is_mobile:
        device = "Mobile"
    elif ua.is_tablet:
        device = "Tablet"
    elif ua.is_pc:
        device = "Desktop"
    else:
        device = "Other"

    # Improve low-information classifications using passive local UA heuristics.
    if browser.strip().lower() in {"", "other"}:
        browser = _fallback_browser(ua_string)
    if os_name.strip().lower() in {"", "other"}:
        os_name = _fallback_os(ua_string)
    if device.strip().lower() in {"", "other"}:
        device = _fallback_device(ua_string)

    return types.MappingProxyType({"browser": browser, "os": os_name, "device": device})
