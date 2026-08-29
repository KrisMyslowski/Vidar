"""Configuration checks for the causes that show up as an empty dashboard.

A misconfiguration here does not raise. Nginx keeps serving, the container keeps
running, `/health` keeps answering ok, and the operator sees a dashboard with no
data and nothing to explain it. Every check below is one of those: something that
is wrong in a way the service cannot notice on its own.

Run it inside the container, where the mounts and the clock are the ones the
service actually has:

    docker compose -f deploy/docker-compose.yml exec vidar python -m src.preflight

Exit status is 1 if anything failed, 0 otherwise — warnings do not fail the run,
because a missing DNSBL key is a signal you do without rather than a broken
install.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .config import settings, unset_site_settings

OK, WARN, FAIL = "ok", "warn", "fail"

# The fields the classifier and the visit table need beyond the obvious ones.
# Their absence is silent: LogEntry defaults them, every row inserts, and the
# columns are simply empty forever. deploy/nginx-log-format.conf is the source.
_REQUIRED_LOG_FIELDS = ("connection", "connection_requests")

# How many lines from the end to look at before giving up on finding a parseable
# one. A log that has just rotated can open with a partial line.
_TAIL_LINES = 50


@dataclass(frozen=True)
class Check:
    """One question, its verdict, and what to do about a bad one."""

    name: str
    status: str
    detail: str


def _last_entries(path: Path, limit: int = _TAIL_LINES) -> list[dict]:
    """The last parseable JSON objects in the log, newest last.

    Reads the tail rather than the file: on a server this is hundreds of
    megabytes, and everything asked of it here is answered by recent lines.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, 64 * 1024)
            fh.seek(size - block)
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            out.append(parsed)
    return out


def _check_log_readable(entries: list[dict]) -> Check:
    path = settings.log_path
    if not path.exists():
        return Check(
            "log file",
            FAIL,
            f"{path} does not exist. Check the /logs bind mount in "
            f"docker-compose.yml and NGINX_LOG_DIR — the container sees the host "
            f"directory at /logs, so LOG_PATH has to name a file below it.",
        )
    if not os.access(path, os.R_OK):
        return Check(
            "log file",
            FAIL,
            f"{path} exists but this process cannot read it. The container runs as "
            f"uid 1000; nginx often writes its logs 0640 root:adm. Either widen the "
            f"file's mode or have logrotate create it readable (see the create line "
            f"in /etc/logrotate.d/nginx).",
        )
    if path.stat().st_size == 0:
        return Check("log file", WARN, f"{path} is readable but empty — no traffic logged yet.")
    if not entries:
        return Check(
            "log file",
            FAIL,
            f"{path} has content but no line in the last {_TAIL_LINES} parsed as JSON. "
            f"Nginx is writing its default combined format; apply "
            f"deploy/nginx-log-format.conf inside the http {{}} block and reload.",
        )
    return Check("log file", OK, f"{path}, {len(entries)} recent lines parsed")


def _check_log_fields(entries: list[dict]) -> Check:
    if not entries:
        return Check("log format", WARN, "no parseable lines to check the fields against")
    newest = entries[-1]
    missing = [f for f in _REQUIRED_LOG_FIELDS if f not in newest]
    if missing:
        return Check(
            "log format",
            FAIL,
            f"the log has no {', '.join(missing)} field. Nothing errors — the columns "
            f"stay empty and every rate-limit and reuse figure derived from them is "
            f"wrong. Update the log_format to deploy/nginx-log-format.conf and reload "
            f"nginx.",
        )
    return Check("log format", OK, f"all {len(_REQUIRED_LOG_FIELDS)} required fields present")


def _check_timezone(entries: list[dict]) -> Check:
    """Both clocks, because they fail independently.

    Vidar compares logged timestamps against UTC-derived bounds. A non-UTC nginx
    host shifts every range window, the retention cutoff and the staleness
    cutoff at once, and nothing reports it — the numbers are just wrong.
    """
    problems = []
    if time.timezone != 0 or (time.daylight and time.altzone != 0):
        problems.append(
            f"this container's clock is {time.tzname[0]}, not UTC — unset TZ in the "
            f"compose service, or set it to UTC"
        )
    stamp = str(entries[-1].get("time", "")) if entries else ""
    if stamp and not (stamp.endswith("+00:00") or stamp.endswith("Z")):
        problems.append(
            f"nginx logged {stamp!r}, which is not UTC — set TZ=UTC on the nginx "
            f"host or its container"
        )
    if problems:
        return Check("timezone", FAIL, "; ".join(problems))
    return Check("timezone", OK, "container is UTC" + (", log offset is UTC" if stamp else ""))


def _check_writable() -> list[Check]:
    """The three directories the service writes to, checked by writing.

    Testing the mode bits is not the same question: the mount can be read-only,
    the uid can be wrong, and the directory can be missing, and only an actual
    write answers all three at once.
    """
    out = []
    for label, path in (
        ("database", settings.db_path.parent),
        ("archives", settings.archive_dir),
        ("snapshots", settings.backup_dir),
    ):
        probe = path / ".preflight"
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe.touch()
            probe.unlink()
        except OSError as exc:
            out.append(
                Check(
                    f"{label} directory",
                    FAIL,
                    f"cannot write {path}: {exc.strerror}. The container runs as uid "
                    f"1000 and everything it writes must be under the /data mount — "
                    f"`chown 1000 {path}` on the host, and check VIDAR_DATA_DIR.",
                )
            )
        else:
            out.append(Check(f"{label} directory", OK, str(path)))
    return out


# What each of the three site settings costs when it is blank, and what to do.
# Which ones are blank is not decided here — unset_site_settings() already
# answers that for the startup warning and for /settings/status, and a third
# opinion would be one that can drift from the other two.
_SITE_SETTING_FIXES = {
    "SITE_BASE_URL": (
        "no request is ever internal navigation, so nobody reaches "
        "humans/browser-internal-nav and the carve-out that keeps a VPN user human "
        "cannot fire either. Set it to your site's own address."
    ),
    "STATIC_ASSET_PREFIXES": (
        "a .json or .map anywhere counts as a visit rather than an asset — which is "
        "the point of the setting, since a .json below your own assets is a "
        "translation file and one anywhere else is somebody hunting for secrets. "
        "Other extensions are unaffected. Set it to where your files are served from."
    ),
    "JS_ONLY_PATH_PREFIXES": (
        "the js_fetch browser signal is absent. Sec-Fetch still identifies HTTP/2 "
        "browsers, but an HTTP/1.1 client loses its only proof of being one."
    ),
}


def _check_site_settings() -> list[Check]:
    """The three settings that encode the observed site's URL layout.

    Vidar ships them blank because it is site-agnostic. None of them breaks
    anything when blank; each costs one specific thing, quietly.
    """
    # unset_site_settings() returns "NAME (short cost)"; the name is the key here.
    blank = {entry.split(" ", 1)[0] for entry in unset_site_settings()}
    out = []
    for name, fix in _SITE_SETTING_FIXES.items():
        if name in blank:
            out.append(Check(name, FAIL, f"unset — {fix}"))
        else:
            value = getattr(settings, name.lower())
            out.append(Check(name, OK, value if isinstance(value, str) else ", ".join(value)))
    return out


def _check_dnsbl() -> Check:
    if not settings.dnsbl_dqs_key:
        return Check(
            "DNSBL_DQS_KEY",
            WARN,
            "unset — the legacy Spamhaus zone refuses queries from cloud resolvers "
            "and answers 127.255.255.254 to everything, so the dnsbl signal stays "
            "empty rather than clean. A free Data Query Service key fills it.",
        )
    return Check("DNSBL_DQS_KEY", OK, "set")


def run_checks() -> list[Check]:
    """Every check, in the order an operator would hit the problems."""
    entries = _last_entries(settings.log_path)
    return [
        _check_log_readable(entries),
        _check_log_fields(entries),
        _check_timezone(entries),
        *_check_writable(),
        *_check_site_settings(),
        _check_dnsbl(),
    ]


def main() -> int:
    checks = run_checks()
    width = max(len(c.name) for c in checks)
    for c in checks:
        print(f"{c.status.upper():<4} {c.name:<{width}}  {c.detail}")
    failed = sum(c.status == FAIL for c in checks)
    warned = sum(c.status == WARN for c in checks)
    print()
    print(f"{len(checks)} checks, {failed} failed, {warned} warned")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
