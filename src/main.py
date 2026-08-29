"""FastAPI application entry point.

Lifespan:  init DB → start tail_log + enrichment_worker as asyncio tasks → cancel on shutdown
Middleware: per-IP rate limit on /api/export (configurable via settings)
Routing:   dashboard routes (/) + API routes (/api) + static files (/static)
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .backup import LAST_RUN_KEY as BACKUP_LAST_RUN_KEY
from .backup import run_backup
from .config import settings, unset_site_settings
from .db import get_conn, init_db
from .enricher import _init_async_globals, enrichment_worker, reverse_dns_backfill
from .log_processor import tail_log
from .queries import (
    CLASSIFIER_VERSION,
    backfill_visitor_classes,
    count_export_hits,
    force_reclassify_all,
    get_state,
    purge_old_rate_limits,
    reclassify_stale_ips,
    record_export_hit,
    set_state,
)
from .retention import LAST_RUN_KEY, run_retention
from .routes._cache import fetch, warm_caches
from .routes.api import router as api_router
from .routes.dashboard import router as dashboard_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vidar.main")


# ── Lifespan ─────────────────────────────────────────────────────────────────


async def _backfill_task() -> None:
    """Keep visitor_class current in the background so startup is not blocked.

    On a classifier logic change (CLASSIFIER_VERSION bumped) every IP is reclassified
    once; otherwise only IPs that have no class yet are filled in.
    """
    try:
        await _backfill()
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Classifier backfill failed")


async def _backfill() -> None:
    with get_conn() as conn:
        if get_state(conn, "classifier_version") != CLASSIFIER_VERSION:
            n = force_reclassify_all(conn)
            set_state(conn, "classifier_version", CLASSIFIER_VERSION)
            logger.info("Reclassified %d IPs for classifier v%s", n, CLASSIFIER_VERSION)
        else:
            n = backfill_visitor_classes(conn)
            if n:
                logger.info("Backfilled visitor_class for %d IPs", n)


def _seed_demo() -> None:
    """Fill an empty database with synthetic traffic.

    Only into a database with no visits: DEMO_MODE pointed at a real one must
    never write over it, which is the same refusal scripts/seed_demo.py makes.
    Seeding leaves visitor_class unset, so the backfill task below classifies it
    the way it classifies anything else — the demo shows the classifier's real
    output rather than a staged picture of it.
    """
    import random

    from .demo import SEED, seed

    with get_conn() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    if existing:
        logger.info("DEMO_MODE: %d visits already here, seeding nothing", existing)
        return
    visits, addrs = seed(random.Random(SEED))
    logger.info("DEMO_MODE: seeded %d synthetic visits across %d addresses", visits, addrs)


async def _rdns_backfill_task() -> None:
    """Resolve PTR for IPs enriched before reverse DNS was looked up locally.

    Runs once at startup and exits. The classifier's crawler rules depend on it, so
    doing it lazily via the 30-day enrichment TTL would leave real crawlers labelled
    as impersonators for weeks.
    """
    try:
        n = await reverse_dns_backfill()
        if n:
            logger.info("Backfilled reverse DNS for %d IPs", n)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Reverse DNS backfill failed")


async def _reclassify_task() -> None:
    """Periodically re-judge IPs that stayed active after they were classified.

    A class is derived from an IP's entire history, so it decays: an IP first seen
    fetching a page and only later probing keeps the harmless label until something
    looks again. Runs forever; one failed pass must not kill the loop.
    """
    interval = max(settings.reclassify_interval_minutes, 1) * 60
    while True:
        await asyncio.sleep(interval)
        try:
            with get_conn() as conn:
                n = reclassify_stale_ips(conn)
            if n:
                logger.info("Reclassified %d IPs whose behaviour changed", n)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Reclassification pass failed")


async def _retention_task() -> None:
    """Run the retention/archive pass once a day, from inside the app.

    This used to be cron in the container and never ran once: the crontab was
    installed in the wrong format, and the job's `> /proc/1/fd/1` redirect could
    not be opened by the non-root user it ran as, so the shell died before
    Python started — silently, because cron's error output goes nowhere in a
    container. Data reached 123 days under a 90-day policy.

    Hence the hour-long tick instead of a fixed 03:00 slot: the pass runs when
    the last one is a day old, so a container that was down at 03:00 catches up
    on its next start rather than skipping the day the way cron would.
    """
    while True:
        try:
            with get_conn() as conn:
                last = get_state(conn, LAST_RUN_KEY)
            due = True
            if last:
                elapsed = datetime.now(timezone.utc) - datetime.fromisoformat(last)
                due = elapsed >= timedelta(days=1)
            if due:
                await asyncio.to_thread(run_retention)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Retention pass failed")
        await asyncio.sleep(3600)


async def _backup_task() -> None:
    """Snapshot the database once a day, on the same tick shape as retention.

    Separate task rather than a step inside the retention pass: retention only
    does work in `rolling` mode, and a backup must not stop because someone
    switched to `lifetime`.
    """
    while True:
        try:
            with get_conn() as conn:
                last = get_state(conn, BACKUP_LAST_RUN_KEY)
            due = True
            if last:
                due = datetime.now(timezone.utc) - datetime.fromisoformat(last) >= timedelta(
                    days=1
                )
            if due:
                await asyncio.to_thread(run_backup)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Backup pass failed")
        await asyncio.sleep(3600)


def _report_task_exits(names: Iterable[str], results: Iterable[object]) -> None:
    """Name any background task that ended on an exception.

    gather(return_exceptions=True) is what stops one task's failure from hiding
    the others — but it also *retrieves* the exception, and this is the last
    moment anything can report it. Discarded here, a task that died hours ago
    leaves no trace anywhere at all. CancelledError derives from BaseException,
    so an ordinary shutdown says nothing.
    """
    for name, result in zip(names, results, strict=True):
        if isinstance(result, Exception):
            logger.error("Background task %s ended with an error: %r", name, result)


def _warn_about_unset_site_settings() -> None:
    """Say once, at startup, which site-specific settings are missing.

    Three settings describe the *watched site* rather than the service, so they
    ship empty — there is no value that is right for a second deployment. Unset,
    nothing fails: the classifier just loses evidence and quietly returns worse
    verdicts, which is the kind of degradation nobody goes looking for. Hence a
    line in the log naming exactly what was given up.

    The deploy script refuses to ship without these, so in production this should
    never fire; it is here for local runs and for anyone starting from a bare .env.
    """
    unset = unset_site_settings()
    if unset:
        logger.warning(
            "Site-specific settings are unset, so classification is weaker than "
            "it could be: %s. See .env.example.",
            "; ".join(unset),
        )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """App lifespan: init DB, start background tasks, cancel on shutdown.

    The app argument is Starlette's lifespan protocol, not something this hook
    uses — named with the underscore so that stays visible.
    """
    logger.info("Starting Vidar")
    _warn_about_unset_site_settings()
    init_db()
    if settings.demo_mode:
        # Before warm_caches() below, or the first page served is the empty one.
        _seed_demo()
    _init_async_globals()
    # The two Jinja globals read a cache and never produce one, because template
    # rendering is synchronous and has no await to hide a query behind. Filling
    # it here means the first page served already has real values.
    await warm_caches()

    # Backfill visitor_class for any IPs that predate the classifier — runs in
    # the background so startup is not blocked by a large unenriched dataset.
    backfill_bg = asyncio.create_task(_backfill_task())

    # Queue bridges log_processor -> enricher: new IPs that need geo lookup
    new_ips_queue: asyncio.Queue = asyncio.Queue(maxsize=settings.enrichment_queue_maxsize)

    tasks = {"classifier backfill": backfill_bg}
    if settings.demo_mode:
        # Everything skipped here either reads a log that is not there or calls a
        # provider about an address that does not exist. The classifier backfill
        # above is the one that has work to do.
        logger.warning(
            "DEMO_MODE is on: synthetic traffic, no log is read, no provider is "
            "called. Not a setting for a real deployment."
        )
    else:
        # On app.state so /settings/status can report how far behind the worker
        # is. Not set in demo mode, where nothing drains it: the page reads it
        # with a default and says "not running", which is the truth there.
        app.state.new_ips_queue = new_ips_queue
        tasks["log tailer"] = asyncio.create_task(tail_log(new_ips_queue))
        tasks["enrichment worker"] = asyncio.create_task(enrichment_worker(new_ips_queue))
        tasks["reverse DNS backfill"] = asyncio.create_task(_rdns_backfill_task())
        tasks["reclassifier"] = asyncio.create_task(_reclassify_task())
        tasks["retention"] = asyncio.create_task(_retention_task())
        tasks["backup"] = asyncio.create_task(_backup_task())

    yield

    for task in tasks.values():
        task.cancel()

    # Await task cancellation to ensure clean shutdown.
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    _report_task_exits(tasks, results)

    logger.info("Shutting down Vidar")


# docs_url/redoc_url are off, and /docs belongs to the documentation pages in
# routes/docs.py instead. Swagger and ReDoc were never usable here anyway: both
# pull their stylesheet and bundle from cdn.jsdelivr.net, which security_headers
# does not allow — the page loaded and then failed against its own CSP. The API
# is described in docs/api.md and on /settings/api. openapi.json stays, since it
# is data rather than a page and costs nothing.
app = FastAPI(title="Vidar", lifespan=lifespan, docs_url=None, redoc_url=None)

# ── Rate limiting ────────────────────────────────────────────────────────────
# State lives in the rate_limits SQLite table so the limit survives container
# restarts.
#
# The three queries go through fetch() like every other database access. They are
# small and indexed (idx_rate_limits_ip_time), but synchronous sqlite3 inside a
# coroutine stalls the log tailer and the enrichment worker for as long as it
# runs, and this middleware was the one place that did not follow the rule it
# documents elsewhere.
#
# The count→insert pair is still not atomic, and it used to be safe for a reason
# that no longer applies: the queries ran on the event loop, so one request was
# handled at a time. On a worker thread two exports can interleave and both pass
# the count. The lock restores exactly the serialisation the loop used to give
# for free — at export granularity, so it costs nothing anywhere else.
#
# The budget keys on the client IP, which behind the SSH tunnel is always
# 127.0.0.1, so in practice it is one global budget. That is the right shape for
# a single-user dashboard and worth knowing before anyone reads per-IP into it.
_export_rate_lock = asyncio.Lock()


@app.middleware("http")
async def rate_limit_export(request: Request, call_next: Callable):
    if request.url.path == "/api/export":
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = settings.export_rate_limit_window_s

        def claim_slot(conn) -> bool:
            """Purge, count and record on one connection. False when over budget."""
            purge_old_rate_limits(conn, window, now)  # opportunistic cleanup
            if count_export_hits(conn, client_ip, window, now) >= settings.export_rate_limit:
                return False
            record_export_hit(conn, client_ip, now)
            return True

        async with _export_rate_lock:
            allowed = await fetch(claim_slot)
        if not allowed:
            return Response(
                f"Rate limit exceeded ({settings.export_rate_limit} exports/hour)",
                status_code=429,
            )
    return await call_next(request)


# The origins the dashboard actually loads from, and nothing else. Leaflet and
# MarkerCluster come from unpkg pinned by SRI (script *and* stylesheet — the CSS
# is loaded from there too, which is why unpkg appears twice below), and the map
# tiles from Carto, which cannot carry SRI and therefore only needs img-src.
#
# style-src keeps 'unsafe-inline' because the taxonomy colours ride in on style
# attributes (`--clr:`, `--hm:`) in the macros. Those are style *attributes*, not
# scripts, and CSP has no nonce mechanism for them.
#
# script-src does not, and that is the point of the header: the templates render
# attacker-controlled text — raw request lines out of the log — and while
# autoescape is on and holds, this is the second line. A nonce covers the one
# inline script that must run before first paint; the three inline on* handlers
# that used to exist became data attributes plus static/js/actions.js, because a
# nonce cannot cover an attribute handler.
_CSP_TEMPLATE = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}' https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://unpkg.com; "
    "img-src 'self' data: https://*.basemaps.cartocdn.com; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next: Callable):
    """Add defensive response headers (clickjacking, MIME-sniffing, referrer leakage).

    The nonce is generated before the request is handled and stored on
    request.state, which lives in the ASGI scope and so reaches the template
    that renders the inline script. A ContextVar would not: BaseHTTPMiddleware
    runs the endpoint in its own task, and a value set here would not be visible
    there.
    """
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = _CSP_TEMPLATE.format(nonce=nonce)
    return response


# ── Cross-origin writes ──────────────────────────────────────────────────────
# There is no login: the service binds 127.0.0.1 and is reached over an SSH
# tunnel. That covers the network, not the browser at the tunnel's end — a form
# post is a simple request, so any page the operator has open can send one:
#
#   <form action="http://localhost:8080/settings/storage/delete-month/2026-08"
#         method="POST">
#
# CORS does not stop it being sent, and `form-action 'self'` above constrains
# where this page's forms submit, not who may submit here.
#
# Sec-Fetch-Site is the check — set by the browser, unforgeable by script.
# 'same-site' is not enough: a port is not part of a site, so anything else on
# localhost would pass. Origin is the fallback for clients too old to send
# Sec-Fetch; neither header means it is not a browser form post (curl, the
# smoke test, the tests) and is left alone.
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_same_origin(request: Request) -> bool:
    """Whether an unsafe request originated from the dashboard itself."""
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site == "same-origin"
    origin = request.headers.get("origin")
    if origin is None:
        return True
    host = request.headers.get("host", "")
    return bool(host) and origin in (f"http://{host}", f"https://{host}")


@app.middleware("http")
async def block_cross_origin_writes(request: Request, call_next: Callable):
    """Refuse state-changing requests a foreign page initiated.

    Registered last, so it runs first: a refused request must not spend a slot
    of the export budget on its way to a 403.
    """
    if request.method in _UNSAFE_METHODS and not _is_same_origin(request):
        return Response("Cross-origin request refused", status_code=403)
    return await call_next(request)


# ── Routing ──────────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check():
    """Lightweight health check endpoint (no DB query)."""
    return {"status": "ok"}


static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Serve the icon at the path a browser asks for on its own.

    base.html names the SVG directly, so the dashboard pages never come here.
    The four JSON endpoints that settings_api.html opens in new tabs do: those
    responses are not HTML and carry no <link>, so the browser falls back to
    /favicon.ico and got a 404. The extension is a lie the browser does not
    read — it follows the content type.
    """
    return FileResponse(static_dir / "img" / "favicon.svg", media_type="image/svg+xml")


app.include_router(dashboard_router)
app.include_router(api_router, prefix="/api")
