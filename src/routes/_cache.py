"""Off-loop database access and the short-lived aggregate cache.

fetch() is the only sanctioned way a handler touches SQLite: synchronous
sqlite3 in a coroutine stalls the log tailer and the enrichment worker with
it. Route modules import from here rather than from each other."""

from __future__ import annotations

import asyncio
import time

from ..db import get_conn
from ..queries import get_attention_items
from ._app import templates

_earliest_date_cache: str | None = None
_earliest_date_cached_at: float = 0.0
_EARLIEST_DATE_TTL_S = 3600  # refresh hourly so retention purges are reflected


def _load_earliest_date() -> str:
    """Query and cache the first day with data. Blocking — never call on the loop."""
    global _earliest_date_cache, _earliest_date_cached_at
    with get_conn() as conn:
        row = conn.execute("SELECT substr(MIN(timestamp),1,10) FROM visits").fetchone()
    # Only cache a real date; while the DB is empty keep re-querying so the
    # first arriving data is reflected immediately (not after the TTL).
    if row and row[0]:
        _earliest_date_cache = row[0]
        _earliest_date_cached_at = time.time()
    return _earliest_date_cache or ""


def _earliest_date() -> str:
    now = time.time()
    if _earliest_date_cache is None or now - _earliest_date_cached_at > _EARLIEST_DATE_TTL_S:
        _refresh_soon("earliest_date", _load_earliest_date)
    return _earliest_date_cache or ""


templates.env.globals["earliest_date"] = _earliest_date

# Refreshes in flight, so a burst of renders schedules one query and not one
# per page.
_refreshing: set[str] = set()
_refresh_tasks: set[asyncio.Task] = set()


def _refresh_soon(key: str, produce) -> None:
    """Reload `key` on a worker thread, without making this caller wait.

    The two Jinja globals below are called during template rendering, which is
    synchronous — there is no await to put a query behind. Blocking there breaks
    the rule at the top of this module in the place it matters most: a stalled
    loop is a stalled log tailer. So a render serves the value it has and the
    next render gets the fresh one, which on a cache measured in minutes is
    invisible. warm_caches() fills them before the first request, so "the value
    it has" is never nothing.
    """
    if key in _refreshing:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        produce()  # no loop at all — a test or a script; just do the work
        return

    _refreshing.add(key)

    async def run():
        try:
            await asyncio.to_thread(produce)
        finally:
            _refreshing.discard(key)

    # Held in a set: a bare create_task() may be collected before it runs.
    task = loop.create_task(run())
    _refresh_tasks.add(task)
    task.add_done_callback(_refresh_tasks.discard)


async def warm_caches() -> None:
    """Fill what the Jinja globals read, before anything renders."""
    await asyncio.to_thread(_load_earliest_date)
    await asyncio.to_thread(_attention_items)


# ── Aggregate cache ──────────────────────────────────────────────────────────
# The Overview's aggregates cost hundreds of milliseconds over a full retention
# window and every one of them is a *summary* — a minute of staleness is
# invisible on a log dashboard, but the blocked event loop is not: SQLite here
# is synchronous, so a slow page stalls the log tailer and the enrichment worker
# with it. One entry per aggregate and window, shared by whoever asks for it.
_AGG_TTL_S = 60
# Keys carry the date window, and a custom window is user input — so the key
# space is unbounded and nothing here would ever have been evicted. Expired
# entries are swept once the dict grows past this; it is a ceiling on garbage,
# not an LRU, because live keys are only ever a handful.
_AGG_MAX_ENTRIES = 64

_agg_cache: dict[str, tuple[float, object]] = {}


async def fetch(work):
    """Run `work(conn)` on a worker thread, with its own connection.

    SQLite here is synchronous, so querying straight from an async handler
    blocks the whole event loop — including the log tailer and the enrichment
    worker — for as long as the query runs. Every route that touches the
    database goes through this.
    """

    def run():
        with get_conn() as conn:
            return work(conn)

    return await asyncio.to_thread(run)


def _cached(key: str, produce, ttl_s: float = _AGG_TTL_S):
    """Return `produce()`, reusing the last value for ttl_s seconds."""
    now = time.time()
    hit = _agg_cache.get(key)
    if hit is not None and now - hit[0] < ttl_s:
        return hit[1]
    value = produce()
    if len(_agg_cache) >= _AGG_MAX_ENTRIES:
        # Every custom date range mints its own keys and would otherwise sit
        # here forever, holding a full stats dict each.
        for stale in [k for k, (at, _) in _agg_cache.items() if now - at >= ttl_s]:
            del _agg_cache[stale]
    _agg_cache[key] = (now, value)
    return value


def _attention_items() -> list[dict]:
    """The Overview findings — one cached entry for both the page and the badge."""

    def load():
        try:
            with get_conn() as conn:
                return get_attention_items(conn)
        except Exception:  # a finding list must never take the page down
            return []

    return _cached("attention", load)


def _attention_count() -> int:
    """Open findings, for the nav badge. This is the only place the nav reacts
    to data; it shares the Overview's cache entry rather than recomputing.

    Reads the cache and schedules a refresh when it is stale, rather than
    producing it here — base.html renders this on every page, and producing it
    meant a findings query on the event loop once a minute.
    """
    hit = _agg_cache.get("attention")
    if hit is None or time.time() - hit[0] >= _AGG_TTL_S:
        _refresh_soon("attention", _attention_items)
    return len(hit[1]) if hit else 0


templates.env.globals["attention_count"] = _attention_count
