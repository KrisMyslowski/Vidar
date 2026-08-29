"""The preflight has to name the cause, not just fail.

Every check here stands for a misconfiguration that produces an empty dashboard
and no error anywhere — the reason the command exists. The assertions are on the
verdict and on the remedy being named, because a check that says "log format
wrong" without saying which field is missing sends the operator back to the docs.
"""

import json
import os

import pytest

from src.preflight import FAIL, OK, WARN, run_checks


def _by_name(checks):
    return {c.name: c for c in checks}


@pytest.fixture
def good(tmp_path, monkeypatch):
    """A configuration with nothing wrong with it, for each test to break once."""
    from src import config

    log = tmp_path / "access.log"
    log.write_text(
        json.dumps(
            {
                "time": "2026-08-28T12:00:00+00:00",
                "remote_addr": "203.0.113.1",
                "request_uri": "/",
                "status": 200,
                "connection": 7,
                "connection_requests": 1,
            }
        )
        + "\n"
    )
    monkeypatch.setattr(config.settings, "log_path", log)
    monkeypatch.setattr(config.settings, "db_path", tmp_path / "vidar.db")
    monkeypatch.setattr(config.settings, "archive_dir", tmp_path / "archive")
    monkeypatch.setattr(config.settings, "backup_dir", tmp_path / "backup")
    monkeypatch.setattr(config.settings, "site_base_url", "https://example.com")
    monkeypatch.setattr(config.settings, "static_asset_prefixes", ["/assets/"])
    monkeypatch.setattr(config.settings, "js_only_path_prefixes", ["/assets/pages/"])
    monkeypatch.setattr(config.settings, "dnsbl_dqs_key", "key")
    monkeypatch.setattr("time.timezone", 0)
    monkeypatch.setattr("time.daylight", 0)
    return log


def test_a_sound_configuration_passes_everything(good):
    assert [c for c in run_checks() if c.status != OK] == []


def test_a_missing_log_file_names_the_mount(good, monkeypatch):
    from src import config

    monkeypatch.setattr(config.settings, "log_path", good.parent / "gone.log")
    c = _by_name(run_checks())["log file"]
    assert c.status == FAIL
    assert "bind mount" in c.detail


def test_the_old_combined_format_is_reported_as_not_json(good):
    """The default nginx format parses as nothing, and the dashboard stays empty."""
    good.write_text('1.2.3.4 - - [28/Aug/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512\n')
    c = _by_name(run_checks())["log file"]
    assert c.status == FAIL
    assert "nginx-log-format.conf" in c.detail


def test_a_json_log_missing_connection_fields_names_them(good):
    """JSON, valid, inserts fine — and two columns are empty forever."""
    good.write_text(json.dumps({"time": "2026-08-28T12:00:00+00:00", "status": 200}) + "\n")
    c = _by_name(run_checks())["log format"]
    assert c.status == FAIL
    assert "connection" in c.detail and "connection_requests" in c.detail


def test_a_non_utc_log_offset_is_caught(good):
    """The container can be UTC while the nginx host is not; they fail separately."""
    good.write_text(
        json.dumps(
            {"time": "2026-08-28T14:00:00+02:00", "connection": 1, "connection_requests": 1}
        )
        + "\n"
    )
    c = _by_name(run_checks())["timezone"]
    assert c.status == FAIL
    assert "+02:00" in c.detail


def test_a_non_utc_container_clock_is_caught(good, monkeypatch):
    monkeypatch.setattr("time.timezone", -3600)
    c = _by_name(run_checks())["timezone"]
    assert c.status == FAIL
    assert "container" in c.detail


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="mode bits do not apply to root, so the directory stays writable and the "
    "check cannot be made to fail — the condition this test needs is unreachable here",
)
def test_an_unwritable_data_directory_names_the_uid(good, monkeypatch):
    from src import config

    monkeypatch.setattr(config.settings, "archive_dir", good.parent / "archive")
    (good.parent / "archive").mkdir()
    (good.parent / "archive").chmod(0o500)
    try:
        c = _by_name(run_checks())["archives directory"]
        assert c.status == FAIL
        assert "1000" in c.detail
    finally:
        (good.parent / "archive").chmod(0o700)


def test_the_three_site_settings_come_from_the_one_list(good, monkeypatch):
    """unset_site_settings() decides which are blank; preflight only adds the fix.

    Two places deriving "is it set" from the settings object is two places that
    can disagree with the startup warning and with /settings/status.
    """
    from src import config

    monkeypatch.setattr(config.settings, "site_base_url", "")
    monkeypatch.setattr(config.settings, "static_asset_prefixes", [])
    checks = _by_name(run_checks())
    assert checks["SITE_BASE_URL"].status == FAIL
    assert checks["STATIC_ASSET_PREFIXES"].status == FAIL
    assert checks["JS_ONLY_PATH_PREFIXES"].status == OK


def test_static_asset_prefixes_describes_what_actually_changes(good, monkeypatch):
    """Only .json and .map consult the prefix — _PATH_DEPENDENT_EXTENSIONS.

    An earlier draft of this check claimed every CSS and image would start
    counting as a visit. They would not: _is_static_asset returns True for those
    on the extension alone.
    """
    from src import config
    from src.log_processor import _PATH_DEPENDENT_EXTENSIONS

    monkeypatch.setattr(config.settings, "static_asset_prefixes", [])
    detail = _by_name(run_checks())["STATIC_ASSET_PREFIXES"].detail
    assert all(ext in detail for ext in _PATH_DEPENDENT_EXTENSIONS)
    assert "CSS" not in detail and "image" not in detail


def test_a_missing_dnsbl_key_warns_rather_than_fails(good, monkeypatch):
    """A signal you do without is not a broken install."""
    from src import config

    monkeypatch.setattr(config.settings, "dnsbl_dqs_key", "")
    assert _by_name(run_checks())["DNSBL_DQS_KEY"].status == WARN


def test_warnings_alone_do_not_fail_the_run(good, monkeypatch, capsys):
    from src import config
    from src.preflight import main

    monkeypatch.setattr(config.settings, "dnsbl_dqs_key", "")
    assert main() == 0
    assert "1 warned" in capsys.readouterr().out


def test_a_failure_sets_the_exit_status(good, monkeypatch):
    from src import config
    from src.preflight import main

    monkeypatch.setattr(config.settings, "site_base_url", "")
    assert main() == 1
