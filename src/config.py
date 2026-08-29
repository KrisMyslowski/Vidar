"""Application settings loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode


class Settings(BaseSettings):
    """Central configuration. All values can be overridden via env vars or .env file."""

    # Paths
    log_path: Path = Path("/logs/access.log")
    db_path: Path = Path("/data/vidar.db")
    # Monthly archives. Must stay under /data: the container is read_only and
    # that bind mount is the only writable path it has.
    archive_dir: Path = Path("/data/archive")

    # Daily database snapshots. Same rule as archive_dir: must stay under /data,
    # the only writable path the read-only container has. On the same disk as
    # the database, so this guards against corruption and accidental deletion —
    # not against losing the volume. Copy them off the host for that.
    backup_dir: Path = Path("/data/backup")
    backup_enabled: bool = True
    # How many daily snapshots to keep. Each is roughly a fifth of the database.
    backup_keep: int = 7

    # Data retention
    # DEPRECATED, removed in 2.0 — no longer purges anything. Retention is a
    # calendar window now (rolling: the current month + the last N, N set in the
    # UI) or off (lifetime), stored under `retention.mode`.
    #
    # It stays declared only because Settings forbids unknown keys, so dropping
    # the field would stop the container for every operator whose .env still
    # names it. The 2.0 note is the point: a field that does nothing and has no
    # end date is a field nobody ever removes.
    retention_days: int = 90
    # How long a re-imported month stays in the active DB before the daily pass
    # archives it out again.
    archive_restore_days: int = 7
    enrichment_cache_ttl_days: int = 30

    # Start with synthetic traffic instead of a log file, so the dashboard can be
    # looked at without a server, an nginx or a mount behind it. The tailer, the
    # enrichment worker and the daily passes are all skipped: there is nothing to
    # read, and the addresses are RFC 5737 documentation ranges that no provider
    # should be asked about. Seeds only into a database with no visits in it —
    # never over real data. See src/demo.py.
    demo_mode: bool = False

    # Filtering
    filter_static_assets: bool = True
    filter_internal_ips: bool = True

    # Base URL of the monitored site — referers starting with it count as internal
    # navigation in the visitor classifier (humans/browser-internal-nav signal).
    #
    # Deliberately empty: this describes the site being watched, not the service,
    # so there is no value that is right for a second deployment. Unset, the
    # internal-navigation signal is switched off rather than guessed — see the
    # `:host <> ''` guard in classifier/evidence_sql.py, without which an empty
    # host would match every referer instead of none. main.py warns once at
    # startup, and the deploy script refuses to ship without it.
    site_base_url: str = ""

    # Log processor polling interval
    poll_interval_seconds: float = 1.0

    # What to do on the very first start, when no read position is stored yet —
    # a fresh install, or a database restored next to a log that outlived it.
    # False starts at the end of the file like tail(1); True reads what is
    # already there. The default is False because `visits` cannot detect a
    # duplicate: nginx timestamps resolve to the second, so two identical
    # requests in one second are indistinguishable from one request ingested
    # twice, and no uniqueness constraint can tell them apart.
    ingest_existing_backlog: bool = False

    # ip-api.com batch settings (free tier: max 15 req/min, 100 IPs/batch)
    enrichment_batch_size: int = 100

    # Where the watched site's own assets live. Extensions in
    # _PATH_DEPENDENT_EXTENSIONS only count as static underneath one of these:
    # /<assets>/lang/de.json is a language file the site fetches on every page
    # load, and /credentials.json is somebody looking for credentials.
    #
    # Empty by default for the same reason as site_base_url — it describes the
    # observed site. Unset, the ambiguous extensions simply never count as static,
    # which errs toward tracking a request rather than discarding it.
    # NoDecode like the other two CSV lists: without it pydantic-settings tries
    # to JSON-decode the raw value before _split_csv_providers ever sees it, and
    # a plain "/assets/" from a .env aborts startup with a parse error.
    static_asset_prefixes: Annotated[list[str], NoDecode] = []

    # File extensions treated as static assets (filtered from visit tracking)
    static_extensions: set[str] = {
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".map",
        ".json",
    }

    # DNSBL (DNS-based blocklist) checks during enrichment.
    # dnsbl.sorbs.net is deliberately absent: the service was retired and its zone
    # answers nothing, so it only ever contributed lookup latency.
    dnsbl_enabled: bool = True
    dnsbl_providers: Annotated[list[str], NoDecode] = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
    ]
    # Spamhaus refuses queries arriving via public/open resolvers (the container's
    # default path) and answers 127.255.255.254 instead of a listing. Their free Data
    # Query Service takes a registration key and is queried as
    # <key>.zen.dq.spamhaus.net. With a key set, zen.spamhaus.org is rewritten to the
    # DQS host; without one the legacy zone is used and will simply report "not
    # listed". See _dnsbl_lookup() in enricher.py.
    dnsbl_dqs_key: str = ""

    # Paths only ever requested by the watched site's own JavaScript — an i18n
    # fragment loader, say. A client fetching one executed that JS, which is
    # browser evidence the Sec-Fetch headers cannot give us for HTTP/1.1
    # clients. Used by the classifier's human gate — set it to the prefixes your
    # site loads via fetch/XHR.
    #
    # Empty by default, again because it describes the site rather than the
    # service. Unset, the gate simply loses this one piece of evidence; the
    # Sec-Fetch path still works, so HTTP/2 browsers are unaffected.
    js_only_path_prefixes: Annotated[list[str], NoDecode] = []

    # How often to re-run the classifier over IPs whose behaviour changed since they
    # were last classified. Labels are computed per IP over its whole history, so an
    # IP that turns hostile after being seen as benign needs a second look.
    reclassify_interval_minutes: int = 15

    # Enrichment concurrency and caching
    shodan_concurrency: int = 10
    # Ceiling on outbound Shodan requests. The concurrency limit above bounds how
    # many run at once and says nothing about how many run per minute: draining a
    # backlog issued 100 per batch every 4.5 s, roughly 1,300/min, against a free
    # service that publishes no limit. 600 keeps a backlog moving without that.
    shodan_requests_per_minute: int = 600
    # How long to stop calling Shodan entirely after it answers 429.
    shodan_cooldown_seconds: int = 300
    # Bounds the wait on a DNS lookup. The resolver's own timeout applies to the
    # thread either way; this is what stops the enrichment worker from waiting on
    # it. A black-holed resolver otherwise parks a batch for minutes.
    dns_timeout_seconds: float = 5.0
    dnsbl_concurrency: int = 10
    tor_cache_ttl_seconds: int = 86_400  # 24 h
    enrichment_queue_maxsize: int = 10_000

    # Basemap tiles. CARTO needed no key until 2026 and now stamps
    # "API KEY REQUIRED" across every free tile — HTTP 200, a valid PNG, so
    # nothing in the code or the log can see it. Empty here like every other
    # value that belongs to a deployment rather than to the service.
    #
    # Not a secret: it travels in the tile URL and is visible to anyone with the
    # dashboard open. Masked on the status page so a screenshot does not carry
    # it, not because the browser does not see it.
    carto_api_key: str = ""

    # Server location (shown as fixed marker on the geo map)
    server_lat: float | None = None
    server_lon: float | None = None
    server_city: str = ""
    server_country: str = ""
    server_asn: str = ""
    server_ip: str = ""

    # SQLite connection timeout (seconds)
    db_connection_timeout: int = 10

    # /api/export rate limiting
    export_rate_limit: int = 5  # max exports per window per IP
    export_rate_limit_window_s: int = 3600  # window size (1 hour)

    @field_validator("server_lat", "server_lon", mode="before")
    @classmethod
    def _blank_is_unset(cls, v):
        """`SERVER_LAT=` with nothing after it means "no marker", not a crash.

        Writing the key with an empty value is how an operator says a setting
        does not apply, and for an optional float it is the only way to say it
        in a .env at all — the alternative is deleting the line, which loses the
        documentation with it.
        """
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator(
        "dnsbl_providers", "js_only_path_prefixes", "static_asset_prefixes", mode="before"
    )
    @classmethod
    def _split_csv_providers(cls, v):
        """Accept a comma-separated string (operator-friendly) or a real list."""
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    # env_file is overridable so a developer's own .env cannot leak into a test
    # run. Setting VIDAR_ENV_FILE empty disables the file entirely, which is what
    # tests/conftest.py does: without it, any local .env silently supplies values
    # for every setting the suite does not pin, and tests asserting a *default*
    # fail on a machine that happens to have one.
    model_config = {
        "env_prefix": "",
        "env_file": os.environ.get("VIDAR_ENV_FILE", ".env") or None,
    }


settings = Settings()


def unset_site_settings() -> list[str]:
    """Which of the three site-specific settings are empty, each with its cost.

    Read twice: by the startup warning in main.py, and by /settings/status. A
    startup line scrolls out of the log and is then gone, while the weaker
    classification it announced stays — so the page says it too, and both say the
    same thing because they read the same list.

    It lives here rather than in main.py because it reads nothing but settings,
    and a route importing main.py is a circular import.
    """
    unset = []
    if not settings.site_base_url:
        unset.append("SITE_BASE_URL (no internal-navigation detection)")
    if not settings.static_asset_prefixes:
        unset.append("STATIC_ASSET_PREFIXES (.json/.map never count as assets)")
    if not settings.js_only_path_prefixes:
        unset.append("JS_ONLY_PATH_PREFIXES (no JS-fetch browser evidence)")
    return unset
