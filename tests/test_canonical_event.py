"""The boundary between a log format and Vidar's own vocabulary.

`Visit` says what a request is; `LogEntry` says how nginx writes one down;
`process_entry()` maps the second onto the first. A TypedDict is documentation
at runtime — Python enforces nothing — so these tests are what makes the
declaration true rather than aspirational.

The point of the boundary is that a second log format costs one adapter and
nothing else. That only holds while the three sides agree, and they drift the
moment someone adds a column without adding a field.
"""

from __future__ import annotations

import inspect

from src.log_processor import process_entry
from src.models import NGINX_ONLY_FIELDS, REQUIRED_FIELDS, LogEntry, Visit
from src.queries.visits import insert_visit


def _sample() -> LogEntry:
    return LogEntry(
        time="2026-08-29T10:00:00+00:00",
        remote_addr="203.0.113.7",
        request="GET /index.html HTTP/2.0",
        status=200,
        body_bytes_sent=512,
    )


def test_the_adapter_produces_exactly_the_canonical_event():
    """No extra key, no missing one.

    An adapter that returns more than Visit declares is a field nothing
    downstream knows about; one that returns less is a KeyError somewhere far
    from the cause.
    """
    assert set(process_entry(_sample())) == set(Visit.__annotations__)


def test_the_canonical_event_is_what_the_database_takes():
    """insert_visit() is the first consumer, and it was the de-facto contract
    long before Visit named it. If the two ever disagree, the name is a lie."""
    accepted = set(inspect.signature(insert_visit).parameters) - {"conn"}
    assert set(Visit.__annotations__) == accepted


def test_the_required_fields_are_the_ones_without_a_default():
    """A visit needs somebody to attribute it to and a point in time.

    Everything else narrows a verdict; these two decide whether there is
    anything to judge at all. They are also the fields whose absence fails
    LogEntry validation outright rather than defaulting.
    """
    no_default = {
        name
        for name, f in LogEntry.model_fields.items()
        if f.is_required() and name not in ("request", "status", "body_bytes_sent")
    }
    assert no_default == {"time", "remote_addr"}
    assert set(REQUIRED_FIELDS) == {"ip", "timestamp"}


def test_the_nginx_only_fields_really_are_nginx_only():
    """The short list is the argument for the boundary being cheap.

    Everything else in the event is an HTTP header, a TLS fact or a rename —
    portable to any web server. An earlier reading of this codebase counted
    `sec_fetch_mode` as nginx-specific and concluded the coupling was deep; it
    is an HTTP header, and the conclusion was wrong. These four are the real
    list, and a second adapter leaves exactly them empty.
    """
    assert set(NGINX_ONLY_FIELDS) <= set(Visit.__annotations__)
    portable = set(Visit.__annotations__) - set(NGINX_ONLY_FIELDS)
    for header in ("sec_fetch_mode", "accept_encoding", "http_x_forwarded_for"):
        assert header in portable, f"{header} is an HTTP header, not an nginx field"
    for tls in ("ssl_protocol", "ssl_cipher"):
        assert tls in portable, f"{tls} is a TLS fact any server can log"


def test_a_source_field_name_never_reaches_the_canonical_event():
    """`remote_addr` and friends stop at the boundary.

    If one of these turns up in Visit, the rename was skipped and the log
    format's vocabulary has started leaking downstream again.
    """
    source_only = {"remote_addr", "body_bytes_sent", "http_referer", "http_user_agent", "time"}
    assert not source_only & set(Visit.__annotations__)
