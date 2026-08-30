"""The canonical visit event, and the log formats that produce it.

Two things live here, and the distinction is the point:

`Visit` is what Vidar understands a request to *be* — the vocabulary everything
downstream speaks. The database columns, the evidence query, the classifier and
the templates all use these names.

`LogEntry` is one *source's* way of writing a request down: nginx's JSON access
log. It is an adapter input, not the model. `log_processor.process_entry()` maps
one onto the other, and that mapping is the boundary — the only place where a
field name from a log format is allowed to appear.

The boundary already existed; it just had no name. Writing it down is what stops
the next feature from reaching across it. Most of what looks nginx-specific is
not: `sec_fetch_mode`, `accept_encoding` and `http_x_forwarded_for` are HTTP
headers, `ssl_protocol` and `ssl_cipher` are TLS facts. Any web server can log
them. `NGINX_ONLY_FIELDS` is the short list that genuinely cannot travel.
"""

from __future__ import annotations

from typing import TypedDict

from pydantic import BaseModel

# ── The canonical event ──────────────────────────────────────────────────────


class Visit(TypedDict):
    """One request, as Vidar understands it, whatever wrote the log.

    A `total=True` TypedDict on purpose: an adapter must decide what to do about
    a field its source does not carry, rather than leaving it out and having the
    absence surface three layers down as a missing dict key.

    What an adapter puts there when the source is silent matters, and the answer
    is not "a default that reads like data". An empty string means "the source
    said nothing", which is what the classifier already treats as no evidence.
    A zero in `connection` means the same. The distinction that must survive is
    between *this request had no Sec-Fetch header* and *this source cannot tell
    us about Sec-Fetch headers* — the first is evidence, the second is a gap in
    coverage, and only the second belongs on the status page rather than in a
    verdict.
    """

    ip: str
    timestamp: str
    method: str
    path: str
    server_port: int
    status: int
    bytes_sent: int
    user_agent: str
    referer: str
    request_time: float
    ssl_protocol: str
    browser: str
    os: str
    device: str
    accept_language: str
    request_length: int
    http_x_forwarded_for: str
    ssl_cipher: str
    connection: int
    connection_requests: int
    limit_req_status: str
    http_version: str
    sec_fetch_dest: str
    sec_fetch_mode: str
    sec_fetch_site: str
    accept_encoding: str
    ssl_session_reused: str


# Without these a visit is not a visit: there is nobody to attribute it to and
# no point in time to place it at. Everything else narrows a verdict; these two
# decide whether there is anything to judge.
REQUIRED_FIELDS = ("ip", "timestamp")

# Fields no format but nginx's produces under these names. A second adapter
# leaves them empty, and the cost is named rather than silently absorbed:
# without connection/connection_requests a re-read of the log cannot be told
# from a repeated request, and limit_req_status is nginx's own rate limiter
# reporting on itself — there is nothing to translate it from.
NGINX_ONLY_FIELDS = (
    "connection",
    "connection_requests",
    "limit_req_status",
    "ssl_session_reused",
)


# ── nginx: the one adapter that exists ───────────────────────────────────────


class LogEntry(BaseModel):
    """One line of the nginx JSON access log, as nginx writes it.

    Field names mirror `deploy/nginx-log-format.conf` exactly, which is why they
    look the way they do — `remote_addr` rather than `ip`, `body_bytes_sent`
    rather than `bytes_sent`. That is the source's vocabulary and it stops at
    `process_entry()`.

    Everything except `time`, `remote_addr`, `request`, `status` and
    `body_bytes_sent` defaults, so a log_format missing a field still parses and
    `_missing_field_report()` says which feature went with it. A line missing a
    required field fails validation instead and is reported separately.
    """

    time: str
    remote_addr: str
    request: str
    status: int
    body_bytes_sent: int
    http_referer: str = ""
    http_user_agent: str = ""
    request_time: float = 0.0
    ssl_protocol: str = ""
    request_method: str = ""
    request_uri: str = ""
    server_port: int = 0
    http_accept_language: str = ""
    request_length: int = 0
    http_x_forwarded_for: str = ""
    ssl_cipher: str = ""
    connection: int = 0
    connection_requests: int = 0
    limit_req_status: str = ""
    http_version: str = ""
    sec_fetch_dest: str = ""
    sec_fetch_mode: str = ""
    sec_fetch_site: str = ""
    accept_encoding: str = ""
    ssl_session_reused: str = ""
