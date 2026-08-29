"""GET/POST /settings/* — storage and API settings."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from functools import partial

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from starlette.background import BackgroundTask

from .. import __version__, archive, backup, enricher
from ..archive import LAST_RUN_KEY
from ..config import Settings, settings, unset_site_settings
from ..db import run_db
from ..queries import count_stale_ips, count_unenriched_ips, get_state, get_visit_months
from ..validators import valid_month
from ._app import templates
from ._cache import fetch

router = APIRouter()


# ── Settings ─────────────────────────────────────────────────────────────────

# The sub-nav lives here, not in the template: a page and its nav entry are the
# same fact, and splitting them is how one of them goes missing.
_SETTINGS_PAGES = (
    ("status", "Status", "/settings/status"),
    ("storage", "Storage & Retention", "/settings/storage"),
    ("api", "API", "/settings/api"),
)

# Rendered as "set" / "not set" and never as a value or a run of asterisks: the
# length of a key is information too, and this page has no reason to give it up.
_SECRET_SETTINGS = frozenset({"dnsbl_dqs_key", "carto_api_key"})

# The order .env.example uses, so the page and the template read alike. Anything
# not named here lands under "Other", which is how a new setting shows up without
# this list having to know about it first.
_CONFIG_GROUPS = (
    ("Paths", ("log_path", "db_path", "archive_dir", "archive_restore_days")),
    ("Watched site", ("site_base_url", "static_asset_prefixes", "js_only_path_prefixes")),
    (
        "Log ingestion",
        (
            "demo_mode",
            "poll_interval_seconds",
            "ingest_existing_backlog",
            "filter_static_assets",
            "filter_internal_ips",
            "static_extensions",
        ),
    ),
    (
        "Enrichment",
        (
            "enrichment_cache_ttl_days",
            "enrichment_batch_size",
            "enrichment_queue_maxsize",
            "shodan_requests_per_minute",
            "shodan_cooldown_seconds",
            "shodan_concurrency",
            "dns_timeout_seconds",
            "tor_cache_ttl_seconds",
            "reclassify_interval_minutes",
        ),
    ),
    ("DNSBL", ("dnsbl_enabled", "dnsbl_providers", "dnsbl_dqs_key", "dnsbl_concurrency")),
    ("Backups", ("backup_enabled", "backup_dir", "backup_keep")),
    ("Map", ("carto_api_key",)),
    (
        "Server marker",
        ("server_lat", "server_lon", "server_city", "server_country", "server_asn", "server_ip"),
    ),
    (
        "Limits",
        (
            "db_connection_timeout",
            "export_rate_limit",
            "export_rate_limit_window_s",
            "retention_days",
        ),
    ),
)


def _config_rows() -> list[tuple[str, list[dict]]]:
    """The effective configuration, grouped, with secrets reduced to a yes/no.

    Reads the model rather than the .env file: the .env is not in the image, and
    what matters is what the service actually loaded, which is not the same thing
    once an environment variable overrides a file.
    """
    seen: set[str] = set()
    groups: list[tuple[str, list[dict]]] = []
    for title, names in _CONFIG_GROUPS:
        rows = []
        for name in names:
            if name not in Settings.model_fields:
                continue
            seen.add(name)
            rows.append(_config_row(name))
        if rows:
            groups.append((title, rows))
    rest = [_config_row(n) for n in Settings.model_fields if n not in seen]
    if rest:
        groups.append(("Other", rest))
    return groups


def _config_row(name: str) -> dict:
    value = getattr(settings, name)
    if name in _SECRET_SETTINGS:
        return {
            "name": name,
            "env": name.upper(),
            "value": "set" if value else "not set",
            "secret": True,
            "empty": not value,
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        shown = ", ".join(str(v) for v in sorted(value)) if value else ""
    else:
        shown = "" if value is None else str(value)
    return {
        "name": name,
        "env": name.upper(),
        "value": shown,
        "secret": False,
        "empty": shown == "",
    }


def _log_readability() -> dict:
    """Whether the service can read the log right now, and how far behind it is.

    The tailer reports an unopenable log to the container log after 30 seconds
    (_OPEN_FAILURE_QUIET_S), and a startup line scrolls away while the condition
    stays — the same reason unset_site_settings() is read twice. Stat'd here
    rather than persisted by the tailer: this route runs in the same container,
    as the same user, against the same mount, so the answer is the file itself.
    """
    try:
        size = settings.log_path.stat().st_size
    except OSError as exc:
        return {"ok": False, "reason": exc.strerror or str(exc)}
    try:
        with open(settings.log_path, "rb"):
            pass
    except OSError as exc:
        # Present but unreadable is the interesting case: nginx creates
        # access.log 0640 root:adm, which the container's UID cannot open.
        return {"ok": False, "reason": exc.strerror or str(exc), "size": size}
    return {"ok": True, "size": size}


def _expiring_now(archives: list[dict], keep: int, today: datetime) -> int:
    """How many archives the current keep window already covers.

    Shown before the form is submitted, not discovered in the log afterwards:
    switching expiry on with a short window can delete years in one nightly pass,
    and the operator should see that number while they still have a choice.
    """
    if keep == archive.ARCHIVE_KEEP_FOREVER:
        return 0
    cutoff = archive.window_start_month(today, keep)
    return sum(1 for a in archives if a["month"] < cutoff)


def _disk_usage() -> dict | None:
    """Free space on the volume the database and the archives sit on.

    Retention is the one setting on this page whose consequence is disk, and the
    page had every number except that one — months, IPs, archive sizes, and no
    way to tell whether any of it was close to a problem.

    Measured on the archive directory rather than the database file: both live
    under the deploy root, the directory exists before the first archive does,
    and a path that has gone missing is worth reporting as "unknown" rather than
    as zero bytes free. None means exactly that, and the template omits the bar.
    """
    try:
        total, used, free = shutil.disk_usage(settings.archive_dir)
    except OSError:
        return None
    return {"total": total, "used": used, "free": free, "pct_used": round(used / total * 100, 1)}


def _settings_nav(active: str) -> list[dict]:
    """Sub-nav entries for subnav_base.html, with `active` marked."""
    return [
        {"label": label, "href": href, "active": key == active}
        for key, label, href in _SETTINGS_PAGES
    ]


@router.get("/settings")
async def settings_index():
    """Settings has no page of its own — the first entry is the landing page."""
    return RedirectResponse(url="/settings/status", status_code=301)


@router.get("/settings/status")
async def settings_status(request: Request):
    """What the service is doing, and what it was configured with.

    Everything here was previously only in `docker logs` or in the server's .env,
    which meant an SSH session to answer "is it reading" and "is enrichment
    behind".
    """

    def _load(conn):
        return {
            "offset": get_state(conn, "file_offset"),
            "inode": get_state(conn, "file_inode"),
            "classifier_version": get_state(conn, "classifier_version"),
            "retention_last_run": get_state(conn, LAST_RUN_KEY),
            "backup_last_run": backup.last_run(conn),
            "unenriched": count_unenriched_ips(conn),
            "stale": count_stale_ips(conn, settings.enrichment_cache_ttl_days),
        }

    state = await fetch(_load)
    # No lifespan means no queue — a TestClient without one, or a very early
    # request. The page reports what it can rather than failing on an attribute.
    queue = getattr(request.app.state, "new_ips_queue", None)
    return templates.TemplateResponse(
        request,
        "settings_status.html",
        {
            "nav": _settings_nav("status"),
            "state": state,
            "queue_depth": queue.qsize() if queue is not None else None,
            "queue_max": settings.enrichment_queue_maxsize,
            "enricher": enricher.snapshot(),
            "log_path": settings.log_path,
            "log": _log_readability(),
            "dnsbl_enabled": settings.dnsbl_enabled,
            "dnsbl_providers": settings.dnsbl_providers,
            "dnsbl_key_set": bool(settings.dnsbl_dqs_key),
            "unset_site_settings": unset_site_settings(),
            "config_groups": _config_rows(),
            "version": __version__,
        },
    )


@router.get("/settings/exports")
async def settings_exports_redirect():
    """Exports folded into Storage & Retention — archives are the download now.

    Whole-database CSV/JSON is still `/api/export`, documented on the API page.
    """
    return RedirectResponse(url="/settings/storage", status_code=301)


def _storage_redirect() -> RedirectResponse:
    """Every storage action answers with a redirect (POST/Redirect/GET).

    303 rather than 302 so the browser turns the POST into a GET: a reload of
    the settings page must not re-run a restore.
    """
    return RedirectResponse(url="/settings/storage", status_code=303)


@router.get("/settings/storage")
async def settings_storage(request: Request):
    """Retention mode, the active window, and the monthly archives."""

    def _load(conn):
        return (
            archive.get_mode(conn),
            archive.get_rolling_months(conn),
            archive.get_archive_keep_months(conn),
            archive.list_archives(conn),
            get_visit_months(conn),
            get_state(conn, LAST_RUN_KEY),
            backup.last_run(conn),
        )

    mode, rolling_months, archive_keep, archives, months, last_run, backup_last_run = await fetch(
        _load
    )
    snapshots = backup.list_snapshots()
    today = datetime.now(timezone.utc)
    start = archive.window_start(today, rolling_months)
    disk = _disk_usage()
    return templates.TemplateResponse(
        request,
        "settings_storage.html",
        {
            "nav": _settings_nav("storage"),
            "mode": mode,
            "rolling_months": rolling_months,
            "max_rolling_months": archive.MAX_ROLLING_MONTHS,
            "window_start": start.date().isoformat(),
            # The window's own month is the next one to leave it.
            "next_out": start.strftime("%Y-%m"),
            "archive_keep": archive_keep,
            "archive_keep_floor": rolling_months + 1,
            "max_archive_keep": archive.MAX_ARCHIVE_KEEP_MONTHS,
            # What switching expiry on right now would remove, so the number is
            # on the page before the click rather than in the log after it.
            "archives_expiring_now": _expiring_now(archives, archive_keep, today),
            "archives_total_bytes": sum(a.get("size") or 0 for a in archives),
            "oldest_archive": min((a["month"] for a in archives), default=None),
            "archives": archives,
            "months": months,
            "restore_days": settings.archive_restore_days,
            "archive_dir": settings.archive_dir,
            "last_run": last_run,
            "disk": disk,
            "snapshots": snapshots,
            "backup_last_run": backup_last_run,
            "backup_keep": settings.backup_keep,
            "backup_enabled": settings.backup_enabled,
        },
    )


async def _run_archive_action(month: str, action) -> RedirectResponse:
    """Validate the month, run `action(conn, month)` off the loop, redirect.

    Goes through fetch() rather than opening a connection here and handing it to
    a thread: an sqlite3.Connection may only be used on the thread that made it.
    """
    valid = valid_month(month)
    if not valid:
        raise HTTPException(status_code=400, detail="Invalid month")
    try:
        await fetch(partial(action, month=valid))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="No archive for that month") from None
    return _storage_redirect()


@router.post("/settings/storage/mode")
async def settings_storage_mode(mode: str = Form(...)):
    """Switch between rolling and lifetime. Unknown values fall back to rolling."""
    await fetch(lambda conn: archive.set_mode(conn, mode))
    return _storage_redirect()


@router.post("/settings/storage/window")
async def settings_storage_window(months: int = Form(...)):
    """Set how many months before the current one stay active. Clamped 0..24."""
    await fetch(lambda conn: archive.set_rolling_months(conn, months))
    return _storage_redirect()


@router.post("/settings/storage/archive-keep")
async def settings_storage_archive_keep(months: int = Form(...)):
    """Set how long an archive survives its own month. 0 keeps every archive.

    Separate from the window above: that one bounds the database, this one bounds
    the zips beside it. set_archive_keep_months clamps a value below the rolling
    window up to it, so what is stored can differ from what was submitted.
    """
    await fetch(lambda conn: archive.set_archive_keep_months(conn, months))
    return _storage_redirect()


@router.post("/settings/storage/restore/{month}")
async def settings_storage_restore(month: str):
    """Load an archived month back into the active DB, pinned for N days."""
    return await _run_archive_action(month, archive.restore_month)


@router.post("/settings/storage/release/{month}")
async def settings_storage_release(month: str):
    """End a restore early — the month leaves the active DB, the zip stays."""
    return await _run_archive_action(month, archive.release_month)


@router.post("/settings/storage/delete-archive/{month}")
async def settings_storage_delete_archive(month: str):
    """Delete a month's zip. Irreversible — the UI confirms before posting."""
    return await _run_archive_action(month, archive.delete_archive)


@router.post("/settings/storage/delete-month/{month}")
async def settings_storage_delete_month(month: str):
    """Drop a month from the database without archiving it. Irreversible."""
    return await _run_archive_action(month, archive.delete_month)


@router.get("/settings/storage/download/{month}")
async def settings_storage_download(month: str):
    """Serve a month as a zip — from the archive, or built from the database.

    Two gates, because this segment ends up as a filename: valid_month() rejects
    anything that is not YYYY-MM, and resolve_archive() re-checks that the
    resolved path really sits inside the archive directory. A malformed segment
    and an absent month answer 404 alike — which shapes the validator likes is
    not worth telling.

    A live month is zipped to a temp file and deleted once the response is sent;
    nothing leaves this service uncompressed.
    """
    valid = valid_month(month)
    if not valid:
        raise HTTPException(status_code=404, detail="No archive for that month")

    path = archive.resolve_archive(valid)
    if path is not None:
        return FileResponse(path, media_type="application/zip", filename=path.name)

    months = {m["month"] for m in await fetch(get_visit_months)}
    if valid not in months:
        raise HTTPException(status_code=404, detail="No data for that month")

    tmp = await fetch(partial(archive.export_month, month=valid))
    return FileResponse(
        tmp,
        media_type="application/zip",
        filename=f"{valid}.zip",
        background=BackgroundTask(tmp.unlink, missing_ok=True),
    )


@router.post("/settings/storage/backup")
async def settings_storage_backup():
    """Take a snapshot now, rather than waiting for the daily pass.

    Through run_db, not fetch: run_backup opens its own connections, and the
    shield matters here — a cancelled request must not abandon the pass between
    the snapshot and the state write.
    """
    await run_db(backup.run_backup)
    return _storage_redirect()


@router.get("/settings/storage/snapshot/{name}")
async def settings_storage_snapshot(name: str):
    """Download one snapshot. Two gates, as with the archives: the name pattern
    and then the resolved path, which must still sit inside the backup dir."""
    path = backup.resolve_snapshot(name)
    if path is None:
        raise HTTPException(status_code=404, detail="No such snapshot")
    return FileResponse(path, media_type="application/gzip", filename=path.name)


@router.get("/settings/api")
async def settings_api(request: Request):
    """The four JSON endpoints and what each one answers."""
    return templates.TemplateResponse(request, "settings_api.html", {"nav": _settings_nav("api")})
