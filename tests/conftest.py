import os
import re
import tempfile
from pathlib import Path

import pytest

# Override settings before importing any src modules
# Use temp files for LOG_PATH so tail_log doesn't loop on missing file
test_log_fd, test_log_path = tempfile.mkstemp(suffix=".log")
os.close(test_log_fd)
os.environ["LOG_PATH"] = test_log_path
os.environ["DB_PATH"] = ""  # will be overridden per test
# Ignore any .env in the repo root. A developer keeping one is normal, and every
# setting the suite does not pin would otherwise come from it — three tests that
# assert documented defaults failed exactly that way.
os.environ["VIDAR_ENV_FILE"] = ""

_STATIC = Path(__file__).resolve().parent.parent / "src/static"
_BASE_HTML = Path(__file__).resolve().parent.parent / "src/templates/base.html"


def dashboard_css() -> str:
    """Every stylesheet the dashboard loads, concatenated in load order.

    dashboard.css was split into seven contiguous parts, so a test that wants
    "the stylesheet" has to read all of them — and in the order the cascade
    applies them. base.html carries that global set and comes first.

    Every template is then scanned for the same <link>, because a page may pull
    a stylesheet of its own on top — docs.css does, the way a page pulls its own
    scripts rather than growing base.html. Reading only base.html was right while
    it was the whole list; it silently stopped being the whole list, and
    test_assets then measured the markup against a subset of the CSS.
    """
    pattern = r'href="/static/(css/[\w.-]+\.css)'
    hrefs = re.findall(pattern, _BASE_HTML.read_text())
    for template in sorted(_BASE_HTML.parent.rglob("*.html")):
        for href in re.findall(pattern, template.read_text()):
            if href not in hrefs:
                hrefs.append(href)
    return "\n".join((_STATIC / h).read_text() for h in hrefs)


@pytest.fixture(autouse=True)
def reset_module_globals():
    """Reset module-level globals between tests to prevent state leakage."""
    yield
    # Reset enricher globals. The rate gate matters as much as the Tor cache:
    # one test provoking a 429 puts Shodan into a five-minute cooldown that the
    # next test inherits, and every lookup in it returns "no answer".
    import src.enricher as enricher_module

    enricher_module._tor_exits = set()
    enricher_module._tor_exits_loaded_at = 0
    enricher_module._tor_exits_failed_at = 0
    enricher_module._shodan_rate_limited = False
    enricher_module._shodan_gate.reset()

    # Export rate-limit state now lives in the rate_limits table, which the per-test
    # tmp_db fixture recreates fresh — no module-level counter to reset.

    # The dashboard caches its aggregates for a minute. Each test gets its own
    # database, so a surviving entry would answer the next test from the
    # previous one's data.
    #
    # Deliberately not wrapped in try/except. It used to swallow AttributeError,
    # and when these names moved out of routes.dashboard the reset silently
    # stopped happening — three tests then failed on cached numbers from another
    # test's database, which reads as a behaviour bug rather than a stale patch
    # target. If this import or attribute ever moves again, say so here.
    import src.routes._cache as cache_module

    cache_module._agg_cache.clear()
    cache_module._earliest_date_cache = None
    cache_module._earliest_date_cached_at = 0.0
    # Refreshes scheduled by a render belong to the event loop that rendered.
    # That loop is closed when the test ends, so anything still in flight will
    # never complete — and left here it holds "a refresh is running" against the
    # next test forever. One process, one loop, in production.
    cache_module._refresh_tasks.clear()
    cache_module._refreshing.clear()


@pytest.fixture(autouse=True)
def tmp_archive_dir(tmp_path, monkeypatch):
    """Point the archive directory at tmp_path for every test.

    Autouse and unconditional: the default is /data/archive, and archive_dir()
    creates it on first use. A single test reaching that path either fails on a
    read-only root or, worse, starts writing into a real deployment's data dir.
    """
    from src import config

    path = tmp_path / "archive"
    monkeypatch.setattr(config.settings, "archive_dir", path)
    return path


@pytest.fixture(autouse=True)
def tmp_backup_dir(tmp_path, monkeypatch):
    """Point the snapshot directory at tmp_path for every test.

    Same reasoning as tmp_archive_dir above, and the same failure without it:
    backup_dir() creates /data/backup on first use, and merely *rendering*
    Settings › Storage lists the snapshots.
    """
    from src import config

    path = tmp_path / "backup"
    monkeypatch.setattr(config.settings, "backup_dir", path)
    return path


@pytest.fixture
def fast_log(tmp_db, tmp_path, monkeypatch):
    """Isolated temp log + fast polling, for driving tail_log briefly.

    `ingest_existing_backlog` is on because these tests write the file and then
    start the tailer, which is the backlog case by definition. In production the
    default is off: with no stored read position the tailer starts at the end of
    the file, so a database restored beside a surviving log does not re-ingest
    it. tests/test_log_rotation.py covers the placement rules themselves.
    """
    from src import config

    log = tmp_path / "access.log"
    log.write_text("")
    monkeypatch.setattr(config.settings, "log_path", log)
    monkeypatch.setattr(config.settings, "poll_interval_seconds", 0.01)
    monkeypatch.setattr(config.settings, "ingest_existing_backlog", True)
    return log


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Provide a temporary SQLite database path and patch settings."""
    db_path = tmp_path / "test.db"

    # Patch settings.db_path directly to avoid frozen singleton issue
    from src import config

    monkeypatch.setattr(config.settings, "db_path", db_path)

    # Also patch the module-level _DB_PATH used by get_conn() without explicit path
    import src.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", db_path)

    # Also patch environment for any code that reads it directly
    monkeypatch.setenv("DB_PATH", str(db_path))

    # Initialize DB schema
    from src.db import init_db

    init_db(db_path)
    return db_path


@pytest.fixture
def sample_json_line():
    return (
        '{"time":"2026-04-06T13:05:27+00:00","remote_addr":"93.184.216.34",'
        '"request":"GET /index.html HTTP/1.1","status":200,"body_bytes_sent":5988,'
        '"http_referer":"","http_user_agent":"Mozilla/5.0","request_time":0.001,'
        '"ssl_protocol":"TLSv1.3","request_method":"GET","request_uri":"/index.html"}'
    )


@pytest.fixture
def sample_static_line():
    return (
        '{"time":"2026-04-06T13:06:00+00:00","remote_addr":"93.184.216.34",'
        '"request":"GET /assets/css/base.css HTTP/1.1","status":200,"body_bytes_sent":831,'
        '"http_referer":"","http_user_agent":"Mozilla/5.0","request_time":0.000,'
        '"ssl_protocol":"TLSv1.3","request_method":"GET","request_uri":"/assets/css/base.css"}'
    )


@pytest.fixture
def sample_internal_line():
    return (
        '{"time":"2026-04-06T13:07:00+00:00","remote_addr":"172.18.0.1",'
        '"request":"GET / HTTP/1.1","status":200,"body_bytes_sent":5988,'
        '"http_referer":"","http_user_agent":"curl/8.14.1","request_time":0.000,'
        '"ssl_protocol":"TLSv1.3","request_method":"GET","request_uri":"/"}'
    )
