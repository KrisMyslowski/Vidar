"""Nginx access log ingestion pipeline.

Three stages, all in tail_log():
  Filter  — RFC1918 IPs, static assets, health checks
  Parse   — JSON line → LogEntry → visit kwargs (method/path/UA/port derivation)
  Tail    — inode-aware tail loop, visit insert, IP queue push, offset persistence
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
from collections import deque
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

from .config import settings
from .db import get_conn, run_db
from .models import LogEntry
from .queries import get_state, insert_visit, set_state
from .ua_parser import parse_user_agent

logger = logging.getLogger("vidar.log_processor")

# RFC1918 + loopback + IPv6 private ranges — never enrich or track these
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 Unique Local Addresses (ULA)
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Substrings in User-Agent that indicate health check bots
_SKIP_UA_SUBSTRINGS = [
    "health",
    "uptime",
    "kuma",
    "pingdom",
    "uptimerobot",
]

_REQUEST_LINE_RE = re.compile(r"^([A-Z]+)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?$")

# Deque capacity for the seen-IPs set (oldest entries auto-evicted)
_SEEN_IPS_MAXLEN = 50_000

# Timeout when putting a new IP onto the enrichment queue
_QUEUE_PUT_TIMEOUT_S = 1.0

# Max bytes of log lines to read per poll — bounds memory if a large backlog
# accumulates (downtime, traffic flood); the remainder is read on the next poll.
_MAX_READ_BYTES = 1_000_000

# Share of a batch that has to be unreadable before the tailer says so.
_UNPARSEABLE_WARN_RATIO = 0.5


def _report_unparseable(total: int, unparseable: int, already_warned: bool) -> bool:
    """Report a batch we could mostly not read. Returns the new warned-flag.

    A line that will not parse is dropped and the offset moves past it, which is
    the right handling for a stray byte and exactly the wrong handling for a
    changed nginx log_format: that drops every line, forever, while the reason
    goes to DEBUG under an INFO root logger. The service looked idle.

    Warning on the ratio rather than on each line keeps this to one message per
    run of bad batches — a poll every second would otherwise turn a format
    mismatch into a line of log per second. A handful of bad lines in an
    otherwise readable batch stays at DEBUG: it is real, but there is nothing to
    do about one malformed line, and drowning the real signal has a cost.
    """
    return _report_share(
        total,
        unparseable,
        already_warned,
        "%d of %d log lines could not be parsed. If this persists, the nginx "
        "log_format no longer matches what this service reads — compare it "
        "against deploy/nginx-log-format.conf. Set this logger to "
        "DEBUG for the per-line reason.",
    )


def _report_invalid_ips(total: int, invalid: int, already_warned: bool) -> bool:
    """Report a batch whose remote_addr field is mostly unusable.

    Dropping the line is right — an address that will not parse cannot be
    enriched, classified or mapped — but doing it silently made a broken
    $remote_addr look like an absence of traffic. It also used to be filed as
    "internal" and gated on filter_internal_ips, so turning that switch off
    would have started inserting the garbage instead of revealing it.
    """
    return _report_share(
        total,
        invalid,
        already_warned,
        "%d of %d log lines carry an unusable remote_addr and were dropped. Check "
        "that nginx is sending $remote_addr, and that no proxy in front of it is "
        "overwriting the field.",
    )


# What $time_iso8601 looks like when the nginx host runs UTC. Anything else
# carries a real offset, and every comparison downstream is made against
# UTC-derived bounds.
_UTC_SUFFIXES = ("+00:00", "-00:00", "Z", "z")


def _is_utc(timestamp: str) -> bool:
    return timestamp.endswith(_UTC_SUFFIXES)


def _report_local_time(total: int, non_utc: int, already_warned: bool) -> bool:
    """Report timestamps that are not UTC.

    Visit timestamps are stored exactly as nginx wrote them and compared as
    text against bounds derived from UTC — today, the last 7 days, the
    retention cutoff, the month an archive belongs to. On a host that is not
    UTC every one of those is off by the offset, silently: the dashboard shows
    a window shifted by an hour or two, and retention archives a month whose
    edges do not line up with the one it names.

    nginx-log-format.conf says the host must run UTC. Saying it in a config
    file the service cannot read is not the same as knowing, so it checks.
    """
    return _report_share(
        total,
        non_utc,
        already_warned,
        "%d of %d log lines carry a non-UTC timestamp. Every window on the "
        "dashboard and every retention boundary is derived from UTC and "
        "compared against these as text, so both are shifted by the offset. "
        "Set the nginx host's timezone to UTC — see the note at the top of "
        "deploy/nginx-log-format.conf.",
    )


def _report_share(total: int, count: int, already_warned: bool, message: str) -> bool:
    """Warn once per run of bad batches when `count` is most of `total`.

    Warning on the share rather than on each line is what keeps a persistent
    fault to one message: a poll every second would otherwise turn it into a
    line of log per second, which is its own kind of invisible. A handful in an
    otherwise healthy batch stays quiet — it is real, but there is nothing to be
    done about one malformed line, and drowning the real signal has a cost.
    """
    if total and count / total >= _UNPARSEABLE_WARN_RATIO:
        if not already_warned:
            logger.warning(message, count, total)
        return True
    return False


# What an absent field costs. Named, because a list of missing keys is only
# actionable once the operator knows which feature went with them.
_FIELD_CONSEQUENCES = (
    (("connection", "connection_requests"), "deduplication is inactive"),
    (
        ("sec_fetch_mode", "sec_fetch_dest", "sec_fetch_site"),
        "browser detection loses its strongest signal",
    ),
    (("http_referer",), "internal navigation cannot be detected"),
    (("http_user_agent",), "no client, crawler or health-check detection"),
    (("accept_encoding", "http_version"), "the weak browser signals are gone"),
)


def _missing_field_report(keys: frozenset[str]) -> str | None:
    """What to say about a log line that does not carry every field, or None.

    Only the optional fields reach this: a line missing a required one fails
    validation and _report_unparseable() names it. The rest default silently —
    the lines still parse and a feature is simply gone. LogEntry is the reference
    because nginx-log-format.conf is not in the image.
    """
    missing = {f for f in LogEntry.model_fields if f not in keys}
    if not missing:
        return None
    costs = [note for fields, note in _FIELD_CONSEQUENCES if missing.intersection(fields)]
    tail = f" As a result, {'; '.join(costs)}." if costs else ""
    return (
        f"Log lines are missing {len(missing)} field(s) this service reads: "
        f"{', '.join(sorted(missing))}. Compare the nginx log_format against "
        f"deploy/nginx-log-format.conf.{tail}"
    )


# How long the log may stay unopenable before the tailer says so — long enough
# that a rotation passes unremarked.
_OPEN_FAILURE_QUIET_S = 30.0


# ── Filter ───────────────────────────────────────────────────────────────────


def _is_internal_ip(ip: str) -> bool:
    """Check if IP belongs to a private/loopback network.

    An address that will not parse is not internal. It used to return True here,
    which both filed a broken log field under the wrong reason and hung it on
    filter_internal_ips — a switch it has nothing to do with. skip_reason()
    handles it as its own case.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# Extensions that are only an asset where the site's own assets live. A .json
# under STATIC_ASSET_PREFIXES is a language file or a source map the site fetches
# itself; a .json anywhere else is /config.json, /credentials.json,
# /.well-known/… — exactly the requests a scanner makes, and the blanket
# extension filter dropped them before the classifier ever saw one.
_PATH_DEPENDENT_EXTENSIONS = frozenset({".json", ".map"})


def _is_static_asset(uri: str) -> bool:
    """Check if the request URI points to a static file (CSS, JS, images, etc.)."""
    path = urlsplit(uri).path
    suffix = Path(path).suffix.lower()
    if suffix not in settings.static_extensions:
        return False
    if suffix in _PATH_DEPENDENT_EXTENSIONS:
        return any(path.startswith(prefix) for prefix in settings.static_asset_prefixes)
    return True


def _is_health_check(user_agent: str) -> bool:
    """Check if the User-Agent belongs to an uptime monitoring service."""
    ua_lower = user_agent.lower()
    return any(sub in ua_lower for sub in _SKIP_UA_SUBSTRINGS)


def skip_reason(entry: LogEntry) -> str | None:
    """Why this entry is filtered out, or None to keep it.

    A reason rather than a bool because one of them is not a filter at all:
    an unparseable remote_addr means the log field is broken, and counting that
    as "internal" both hid it and tied it to a switch it has nothing to do with.
    The tail loop reports it; the others are ordinary noise.
    """
    if not _is_valid_ip(entry.remote_addr):
        return "invalid-ip"
    if settings.filter_internal_ips and _is_internal_ip(entry.remote_addr):
        return "internal-ip"
    if settings.filter_static_assets and _is_static_asset(entry.request_uri):
        return "static-asset"
    if _is_health_check(entry.http_user_agent):
        return "health-check"
    return None


def should_skip(entry: LogEntry) -> bool:
    """Whether this log entry is filtered out. See skip_reason() for which."""
    return skip_reason(entry) is not None


# ── Parse ────────────────────────────────────────────────────────────────────


def _line_keys(line: str) -> frozenset[str] | None:
    """The JSON keys a log line carries, or None if it is not a JSON object.

    Parsed again rather than threaded out of parse_log_line(): this runs once per
    batch, that one runs on every line.
    """
    try:
        data = json.loads(line)
    except Exception:
        return None
    return frozenset(data) if isinstance(data, dict) else None


def parse_log_line(line: str) -> LogEntry | None:
    """Parse a single JSON log line. Returns None on failure."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        return LogEntry(**data)
    except Exception as e:
        logger.debug("Skipping non-JSON line: %s", e)
        return None


def _derive_request_fields(entry: LogEntry) -> tuple[str, str]:
    """Recover method/path when nginx leaves request_method/request_uri empty.

    This mainly happens for malformed traffic such as TLS handshakes sent to an HTTP
    port, where nginx still logs the raw request bytes in `request` but cannot extract
    HTTP fields.
    """
    method = (entry.request_method or "").strip()
    path = (entry.request_uri or "").strip()
    if method and path:
        return method, path

    raw_request = (entry.request or "").strip()
    if not raw_request:
        return method or "UNKNOWN", path or "[empty request]"

    match = _REQUEST_LINE_RE.match(raw_request)
    if match:
        return match.group(1), match.group(2)

    if raw_request.startswith("\x16\x03") or any(not ch.isprintable() for ch in raw_request[:12]):
        return "TLS", "[handshake on HTTP port]"

    sanitized = "".join(ch if ch.isprintable() else "?" for ch in raw_request[:80]).strip()
    if not sanitized:
        return "NON-HTTP", "[binary payload]"
    return "NON-HTTP", sanitized


def _derive_server_port(entry: LogEntry) -> int:
    """Return target server port from log data, with fallback inference.

    Preferred source is nginx $server_port. If missing in older log lines,
    infer from TLS presence (443) vs plain HTTP (80).
    """
    if entry.server_port and entry.server_port > 0:
        return entry.server_port
    if (entry.ssl_protocol or "").strip():
        return 443
    return 80


def process_entry(entry: LogEntry) -> dict:
    """Convert a LogEntry to visit insert kwargs."""
    method, path = _derive_request_fields(entry)
    server_port = _derive_server_port(entry)
    ua_info = parse_user_agent(entry.http_user_agent)
    return {
        "ip": entry.remote_addr,
        "timestamp": entry.time,
        "method": method,
        "path": path,
        "server_port": server_port,
        "status": entry.status,
        "bytes_sent": entry.body_bytes_sent,
        "user_agent": entry.http_user_agent,
        "referer": entry.http_referer,
        "request_time": entry.request_time,
        "ssl_protocol": entry.ssl_protocol,
        "browser": ua_info["browser"],
        "os": ua_info["os"],
        "device": ua_info["device"],
        "accept_language": entry.http_accept_language,
        "request_length": entry.request_length,
        "http_x_forwarded_for": entry.http_x_forwarded_for,
        "ssl_cipher": entry.ssl_cipher,
        "connection": entry.connection,
        "connection_requests": entry.connection_requests,
        "limit_req_status": entry.limit_req_status,
        "http_version": entry.http_version,
        "sec_fetch_dest": entry.sec_fetch_dest,
        "sec_fetch_mode": entry.sec_fetch_mode,
        "sec_fetch_site": entry.sec_fetch_site,
        "accept_encoding": entry.accept_encoding,
        "ssl_session_reused": entry.ssl_session_reused,
    }


# ── Tail ─────────────────────────────────────────────────────────────────────


_FINGERPRINT_BYTES = 256


def _fingerprint(fd: int) -> str:
    """A short, stable identity for what the file currently holds.

    Inode and size cannot see a copytruncate that regrew past our offset: same
    inode, bigger file, nothing to notice. _starts_a_line() catches it only when
    the new content is laid out differently enough that the old offset lands
    mid-line — and a log of same-shaped lines is exactly where that fails. The
    opening bytes change whenever the file is replaced in place, whatever the
    new lines look like.

    Empty until the file holds at least _FINGERPRINT_BYTES: a shorter prefix is
    still growing, so comparing it against the same prefix one poll later reads
    as a replacement and re-ingests everything. Below that size the inode, the
    file size and the line-boundary check carry it alone.

    Reads through os.pread rather than the file object: a BufferedReader
    satisfies seek(0)+read() from bytes it already holds, so a file replaced in
    place still fingerprints as its old contents — which is exactly the case
    this exists to catch. pread also leaves the read position alone.
    """
    head = os.pread(fd, _FINGERPRINT_BYTES, 0)
    if len(head) < _FINGERPRINT_BYTES:
        return ""
    return hashlib.sha256(head).hexdigest()


def _starts_a_line(fd: int, offset: int) -> bool:
    """Whether `offset` sits at the beginning of a line.

    copytruncate-style rotation empties the file in place and nginx keeps
    writing into the same inode. If it grows back past our offset between two
    polls, `size < offset` never holds, the seek lands in the middle of a line,
    and every read from then on is byte-misaligned — silently, and until the
    next real rotation. One byte settles it: what precedes a line start is
    always a newline.
    """
    if offset == 0:
        return True
    return os.pread(fd, 1, offset - 1) == b"\n"


def _read_batch(fh: BinaryIO, offset: int) -> tuple[list[bytes], int]:
    """Read whole lines from `offset`, bounded to _MAX_READ_BYTES.

    A large backlog (downtime, flood) must not spike memory, so the remainder
    waits for the next poll. Binary mode keeps the offset in exact bytes.
    """
    fh.seek(offset)
    raw_lines: list[bytes] = []
    bytes_read = 0
    while bytes_read < _MAX_READ_BYTES:
        raw = fh.readline()
        if not raw:
            break
        raw_lines.append(raw)
        bytes_read += len(raw)

    if raw_lines and not raw_lines[-1].endswith(b"\n"):
        if len(raw_lines) == 1 and len(raw_lines[0]) >= _MAX_READ_BYTES:
            # A single unterminated line that already exceeds the read budget
            # can never complete within one read — consume it (the JSON parse
            # skips it) instead of stalling the tailer forever.
            logger.warning(
                "Consuming oversized unterminated log line (%d bytes)",
                len(raw_lines[0]),
            )
        else:
            # nginx is still writing this line — leave it for the next poll so
            # a half-written line is never parsed (and lost).
            raw_lines.pop()

    return raw_lines, offset + sum(len(raw) for raw in raw_lines)


def _write_batch(
    lines: list[str], position: tuple[int, int, str], want_keys: bool = False
) -> tuple[int, int, list[str]]:
    """Insert one batch and persist the read position. Blocking; runs in a thread.

    Returns (unparseable, invalid addresses, the distinct IPs inserted). It does
    no queueing of its own: the caller owns the enrichment queue, and putting to
    it used to happen *inside* this transaction, holding the write lock across
    an await of up to a second while the enrichment worker could be blocking the
    same loop in C on busy_timeout — so the timeout guarding that await could
    not fire either.
    """
    unparseable = 0
    invalid_ips = 0
    non_utc = 0
    batch_ips: list[str] = []
    seen: set[str] = set()
    # For the missing-field check, and only while the caller still wants it: the
    # answer cannot change within a run, so parsing a line twice every second
    # forever to re-establish it is work nobody reads. Taken before
    # skip_reason() — a filtered request describes the format as well as a kept
    # one.
    first_keys: frozenset[str] | None = None

    with get_conn() as conn:
        for line in lines:
            entry = parse_log_line(line)
            if entry is None:
                unparseable += 1
                continue
            if want_keys and first_keys is None:
                first_keys = _line_keys(line)
            reason = skip_reason(entry)
            if reason:
                invalid_ips += reason == "invalid-ip"
                continue
            non_utc += not _is_utc(entry.time)

            try:
                insert_visit(conn, **process_entry(entry))
            except sqlite3.OperationalError:
                # Transient/fatal DB condition (locked, disk full): roll the
                # whole batch back and retry on the next poll — never advance
                # the offset past unwritten data.
                raise
            except Exception:
                # A single un-insertable line (bad data) must not roll back
                # the batch or stall the offset forever — log and skip it.
                logger.exception("Skipping un-insertable log line for %s", entry.remote_addr)
                continue

            if entry.remote_addr not in seen:
                seen.add(entry.remote_addr)
                batch_ips.append(entry.remote_addr)

        new_offset, inode, fingerprint = position
        set_state(conn, "file_offset", str(new_offset))
        set_state(conn, "file_inode", str(inode))
        set_state(conn, "file_fingerprint", fingerprint)

    return unparseable, invalid_ips, non_utc, batch_ips, first_keys


async def _queue_new_ips(
    ips: list[str],
    seen_ips: set[str],
    seen_ips_order: deque,
    queue: asyncio.Queue,
) -> None:
    """Hand IPs we have not seen this run to the enricher, dropping on a full queue."""
    for ip in ips:
        if ip in seen_ips:
            continue
        # Mirror the deque's auto-eviction before append() triggers it: discard
        # seen_ips_order[0] from the set so both structures stay in sync. The
        # guard above ensures each IP appears at most once in seen_ips_order, so
        # this is always safe.
        if len(seen_ips_order) == _SEEN_IPS_MAXLEN:
            seen_ips.discard(seen_ips_order[0])
        seen_ips_order.append(ip)
        seen_ips.add(ip)
        try:
            await asyncio.wait_for(queue.put(ip), timeout=_QUEUE_PUT_TIMEOUT_S)
        except asyncio.TimeoutError:
            logger.debug("Enrichment queue full, skipping IP enrichment for %s", ip)


def _path_replaced(path: Path, inode: int) -> bool:
    """Whether the path now names a different file than the one we are reading."""
    try:
        return os.stat(path).st_ino != inode
    except OSError:
        # Gone for the moment — mid-rotation, say. Keep the descriptor and wait;
        # there is nothing to switch to yet.
        return False


async def tail_log(new_ips_queue: asyncio.Queue) -> None:
    """Continuously tail the access log, insert visits, queue new IPs.

    The descriptor is held across polls rather than reopened each time. Reopening
    by path made rotation lossy: on an inode change the loop reset to zero and
    read the *new* file, so whatever nginx appended to the old one after the last
    poll was never read by anyone. Holding it means the old file is drained to
    EOF first and only then swapped — and it closes the window between stat() and
    open(), where a rotation used to apply the old file's offset to the new file.
    """
    log_path = settings.log_path

    # Restore file position from DB to survive container restarts
    with get_conn() as conn:
        saved_offset = get_state(conn, "file_offset")
        saved_inode = get_state(conn, "file_inode")
        saved_fingerprint = get_state(conn, "file_fingerprint")

    offset = int(saved_offset) if saved_offset else 0
    last_inode = int(saved_inode) if saved_inode else 0
    last_fingerprint = saved_fingerprint or ""

    # No stored position at all: a first run, or a database restored next to a
    # log file that outlived it. Reading from byte 0 re-ingests every line the
    # file still holds, and `visits` has no uniqueness constraint to absorb that
    # — nginx's second-resolution timestamps cannot even provide one, so a
    # restore quietly doubles everything still on disk. Start at the end, the
    # way tail(1) does, unless the backlog was explicitly asked for.
    place_at_end = not saved_offset and not settings.ingest_existing_backlog

    # Two structures for O(1) lookup with bounded FIFO eviction:
    # deque tracks insertion order and auto-evicts the oldest entry when full;
    # set mirrors the deque contents for O(1) `in` tests.
    seen_ips_order: deque[str] = deque(maxlen=_SEEN_IPS_MAXLEN)
    seen_ips: set[str] = set()
    consecutive_errors = 0
    format_warned = False
    ip_warned = False
    tz_warned = False
    fields_warned = False
    # When the current run of failed opens began, or None when the file is fine.
    unopenable_since: float | None = None
    open_warned = False
    fh: BinaryIO | None = None

    try:
        while True:
            try:
                if fh is None:
                    try:
                        fh = open(log_path, "rb")
                    except OSError as exc:
                        # Right for the second a rotation takes, wrong for a bad
                        # mount, a typo in LOG_PATH or a file UID 1000 cannot
                        # read — indistinguishable from here, and permanent. The
                        # loop used to spin on those without ever saying so.
                        now = asyncio.get_running_loop().time()
                        if unopenable_since is None:
                            unopenable_since = now
                        elif not open_warned and now - unopenable_since >= _OPEN_FAILURE_QUIET_S:
                            open_warned = True
                            logger.warning(
                                "Cannot read %s after %.0fs (%s). Nothing is being ingested. "
                                "Check that the log directory mounted at the container's "
                                "path is the one nginx writes to, and that UID 1000 can read "
                                "the file: sudo -u '#1000' head -1 <path>",
                                log_path,
                                now - unopenable_since,
                                exc.strerror or exc,
                            )
                        await asyncio.sleep(settings.poll_interval_seconds)
                        continue
                    if open_warned:
                        logger.info("Reading %s again", log_path)
                    unopenable_since = None
                    open_warned = False
                    inode = os.fstat(fh.fileno()).st_ino
                    if place_at_end:
                        offset = fh.seek(0, os.SEEK_END)
                        logger.info(
                            "No stored read position: starting at the end of %s, "
                            "skipping %d bytes already in the file. Set "
                            "INGEST_EXISTING_BACKLOG=true to read them instead.",
                            log_path,
                            offset,
                        )
                        place_at_end = False
                        last_fingerprint = _fingerprint(fh.fileno())
                    elif inode != last_inode:
                        offset = 0
                        last_fingerprint = _fingerprint(fh.fileno())
                    # A matching inode keeps the *stored* fingerprint: comparing
                    # it against the file as it stands now is the only way to
                    # notice a copytruncate that happened while we were down.
                    last_inode = inode

                fd = fh.fileno()
                current = _fingerprint(fd)
                replaced = bool(last_fingerprint and current and current != last_fingerprint)
                if offset and (
                    os.fstat(fd).st_size < offset or replaced or not _starts_a_line(fd, offset)
                ):
                    # Reopen rather than seek: the buffered reader is holding
                    # bytes from the file as it was, and would serve them again.
                    logger.info("Log file truncated or replaced in place; reading it afresh")
                    fh.close()
                    fh = None
                    offset = 0
                    last_inode = 0
                    continue

                raw_lines, new_offset = _read_batch(fh, offset)

                if not raw_lines:
                    if _path_replaced(log_path, last_inode):
                        # Drained, and the path now names a different file. Reading
                        # the old descriptor to EOF before switching is the whole
                        # point of holding it: everything nginx wrote to the old
                        # inode after our last poll has been consumed by now.
                        logger.info("Log file rotated; switching to the new file")
                        fh.close()
                        fh = None
                        offset = 0
                        last_inode = 0
                        continue
                    await asyncio.sleep(settings.poll_interval_seconds)
                    continue

                lines = [raw.decode("utf-8", errors="replace") for raw in raw_lines]

                # The fingerprint travels with the offset: a copytruncate while
                # the service is down is otherwise indistinguishable from no
                # rotation at all, and the stored offset would then be applied
                # to a file that no longer holds those bytes.
                last_fingerprint = _fingerprint(fd)
                position = (new_offset, last_inode, last_fingerprint)

                # Off the loop. Every call in there is synchronous sqlite3, and
                # routes/_cache.py states the rule: a blocking query in a
                # coroutine stalls the event loop — which for the tailer means
                # stalling itself, and the enrichment worker with it. An
                # OperationalError still surfaces here, so the offset below is
                # only advanced once the batch is committed.
                unparseable, invalid_ips, non_utc, batch_ips, first_keys = await run_db(
                    _write_batch, lines, position, not fields_warned
                )

                offset = new_offset
                consecutive_errors = 0
                await _queue_new_ips(batch_ips, seen_ips, seen_ips_order, new_ips_queue)
                format_warned = _report_unparseable(len(lines), unparseable, format_warned)
                ip_warned = _report_invalid_ips(len(lines), invalid_ips, ip_warned)
                tz_warned = _report_local_time(len(lines), non_utc, tz_warned)
                # Once per run. A shortened log_format costs features rather than
                # lines, so nothing above can see it.
                if not fields_warned and first_keys is not None:
                    fields_warned = True
                    report = _missing_field_report(first_keys)
                    if report:
                        logger.warning("%s", report)

            except Exception:
                logger.exception("Error in log processor")
                consecutive_errors += 1
                backoff = min(2**consecutive_errors, 60)
                await asyncio.sleep(backoff)
                continue

            await asyncio.sleep(settings.poll_interval_seconds)
    finally:
        if fh is not None:
            fh.close()
