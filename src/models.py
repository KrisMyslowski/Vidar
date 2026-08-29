"""Pydantic models — typed wrappers around raw nginx log data.

LogEntry: maps one JSON line from the nginx access log to a validated Python object.
          Used by log_processor.py to parse and validate each incoming log entry.
"""

from __future__ import annotations

from pydantic import BaseModel


class LogEntry(BaseModel):
    """Raw parsed JSON log line from nginx. Fields match the nginx json_log format."""

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
