"""Shared input-validation helpers for route handlers."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

# fullmatch(), not match() with a trailing $: in Python `$` also matches just
# before a final newline, so "2026-04\n" satisfied the month pattern and was
# handed back with the newline still on it — into a filename, from a validator
# whose whole job is to be the gate in front of one.
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# Strict: the month reaches the filesystem as <archive_dir>/<month>.zip, so a
# lenient pattern is a path traversal. Anchored, fixed width, 01-12 only.
_MONTH_RE = re.compile(r"\d{4}-(0[1-9]|1[0-2])")


def valid_ip(ip: str | None) -> str | None:
    """Return ip unchanged if it is a valid IPv4/IPv6 address, else None."""
    if not ip:
        return None
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def valid_country(code: str | None) -> str | None:
    """Return uppercased 2-letter country code if valid, else None."""
    if code and len(code) == 2 and code.isalpha():
        return code.upper()
    return None


def valid_date(s: str | None) -> str | None:
    """Return YYYY-MM-DD string if it names a real day, else None.

    Both checks are needed. The pattern fixes the shape — strptime alone takes
    "2026-4-6", which then compares as text against zero-padded timestamps and
    matches nothing. strptime fixes the calendar — the pattern alone takes
    "2026-99-99", which SQLite resolves to NULL, so the page answers "no visits"
    for what was a typo.
    """
    if not (s and _DATE_RE.fullmatch(s)):
        return None
    try:
        datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None
    return s


def valid_month(s: str | None) -> str | None:
    """Return YYYY-MM if valid, else None.

    The only gate between a URL segment and an archive filename. `2026-6`,
    `2026-13` and anything carrying a separator are rejected outright — callers
    still resolve the final path and check it stays inside the archive dir,
    because one validator should never be the only thing between a request and
    the filesystem.
    """
    if s and _MONTH_RE.fullmatch(s):
        return s
    return None


def valid_min_visits(n: str | int | None) -> int:
    """Return min_visits as a positive int; 0 means no filter."""
    if n is None or n == "":
        return 0
    try:
        return max(0, int(n))
    except (TypeError, ValueError):
        return 0


def valid_search(s: str | None, maxlen: int = 100) -> str | None:
    """Return a trimmed search term capped at maxlen chars, else None.

    LIKE wildcard escaping is handled by the query layer, not here.
    """
    if not s:
        return None
    s = s.strip()
    return s[:maxlen] if s else None


def valid_port(n: str | int | None) -> int | None:
    """Return a TCP port (1–65535) as int, else None (no filter)."""
    if n is None or n == "":
        return None
    try:
        p = int(n)
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def valid_order(order: str) -> str:
    """Return 'ASC' or 'DESC' — safe for SQL ORDER BY."""
    return "ASC" if str(order).upper() == "ASC" else "DESC"


def valid_choice(value: str, choices: frozenset[str], default: str) -> str:
    """Return value if it is in choices, else default."""
    return value if value in choices else default
