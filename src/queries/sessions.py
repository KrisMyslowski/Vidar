"""One address's visits, cut into sessions.

The cut is a window function over `visits`, and it is cheap for the reason the
index exists: `idx_visits_ip_timestamp` hands the rows over already ordered, so
LAG costs no sort. Measured on 520 000 visits — 0.10 ms for an address with 66
of them, 24 ms for one with 20 000, against 0.42 ms and 70 ms for the evidence
query that already runs on the same address. Nothing is stored; see
`src/sessions.py` for why that is the point rather than a shortcut.

The aggregates here are chosen to be exactly what `behaviour_for()` reads, plus
what a reader needs to see the session at all. Adding a column here without a
rule that reads it is how a query becomes a place things accumulate.
"""

from __future__ import annotations

import sqlite3

from ..classifier.evidence_sql import _CONTENT_REQUEST_CASE, _INTERNAL_NAV_CASE, _classify_params
from ..classifier.patterns import _CONVENTION_404_MATCH
from ..sessions import SESSION_GAP_SECONDS, behaviour_for

# Whole seconds, because that is the resolution the log has. The obvious
# alternative — (julianday(a) - julianday(b)) * 86400 — is a difference of two
# doubles around 2 461 000 scaled back up, and the rounding survives: a gap of
# exactly 1800 s comes out as 1800.000013, so the boundary case lands on the
# wrong side and which side is decided by floating point noise rather than by
# the rule. strftime('%s') is integer arithmetic and needs no tolerance.
_GAP_SQL = "(strftime('%s', timestamp) - strftime('%s', prev_ts))"


def get_sessions(conn: sqlite3.Connection, ip: str, limit: int = 50) -> list[dict]:
    """This address's sessions, newest first, with the behaviour of each.

    A session is a run of requests with no gap longer than SESSION_GAP_SECONDS.
    The boundary is decided in SQL and the rows come back one per session, so an
    address with 20 000 visits produces tens of rows here rather than 20 000
    crossing into Python.

    `limit` bounds what a page can be asked to render, not what is true: the
    count of sessions is reported separately by count_sessions().
    """
    rows = conn.execute(
        f"""
        WITH ordered AS (
            SELECT v.id, v.timestamp, v.path, v.status, v.method, v.referer,
                   v.sec_fetch_site,
                   {_CONTENT_REQUEST_CASE} AS is_content,
                   LAG(v.timestamp) OVER (ORDER BY v.timestamp, v.id) AS prev_ts,
                   {_INTERNAL_NAV_CASE} AS is_internal_nav,
                   CASE WHEN v.status = 404 AND NOT ({_CONVENTION_404_MATCH})
                        THEN 1 ELSE 0 END AS is_probe_404,
                   CASE WHEN v.status BETWEEN 200 AND 299 THEN 1 ELSE 0 END AS is_ok
            FROM visits v
            WHERE v.ip = :ip
        ),
        marked AS (
            SELECT *,
                   SUM(CASE WHEN prev_ts IS NULL OR {_GAP_SQL} > :gap
                            THEN 1 ELSE 0 END)
                       OVER (ORDER BY timestamp, id) AS session_no
            FROM ordered
        ),
        per_path AS (
            SELECT session_no, COUNT(*) AS hits
            FROM marked GROUP BY session_no, path
        )
        SELECT m.session_no,
               MIN(m.timestamp) AS started,
               MAX(m.timestamp) AS ended,
               COUNT(*)         AS requests,
               COUNT(DISTINCT m.path) AS unique_paths,
               SUM(m.is_probe_404)    AS probe_404,
               COUNT(DISTINCT CASE WHEN m.is_probe_404 THEN m.path END)
                   AS distinct_404_paths,
               SUM(m.is_ok)           AS ok_requests,
               SUM(m.is_content)      AS content_requests,
               COUNT(DISTINCT CASE WHEN m.is_ok THEN m.path END) AS distinct_2xx_paths,
               SUM(m.is_internal_nav) AS internal_nav,
               SUM(CASE WHEN m.method = 'POST' THEN 1 ELSE 0 END) AS post_requests,
               SUM(CASE WHEN m.status IN (401, 403) THEN 1 ELSE 0 END) AS refused,
               -- Correlated, and measured against the obvious alternative of
               -- folding per_path to one row per session and joining it: 82 ms
               -- correlated against 90 ms joined, on an address with 20 000
               -- visits. per_path is small enough that the extra join costs
               -- more than the re-scan saves.
               (SELECT MAX(hits) FROM per_path p WHERE p.session_no = m.session_no)
                   AS max_path_repeats,
               -- SQLite carries the row that produced a bare MIN() through the
               -- other bare columns of the same aggregate. That is what makes
               -- these the *entry* path and referer rather than an arbitrary
               -- pair, and it is a documented guarantee, not a coincidence.
               MIN(m.id) AS entry_id, m.path AS entry_path, m.referer AS entry_referer
        FROM marked m
        GROUP BY m.session_no
        ORDER BY m.session_no DESC
        LIMIT :limit
    """,
        {**_classify_params(ip), "gap": SESSION_GAP_SECONDS, "limit": limit},
    ).fetchall()

    out = []
    for row in rows:
        session = dict(row)
        session["duration"] = _duration_seconds(session["started"], session["ended"])
        # Paths the client asked for and did not get: everything it asked for,
        # minus what came back 2xx. Behaviour is read from this rather than
        # from 404s, because a redirect, a 404, a 503 and a 403 all mean the
        # same thing to the client — and keying on 404s went quiet in exactly
        # the two places where the probing was heaviest.
        #
        # Subtraction, so the row adds up: Read + Unserved is Paths, in every
        # session. An earlier version counted error paths instead, to keep a
        # redirect from reading as a failure. It cost the identity — a path
        # that answered only 3xx fell in neither column, one that answered both
        # 200 and 404 fell in both, and 51 of 1 568 real sessions did not add
        # up — and bought nothing: across that week exactly one session changed
        # label, the operator's own afternoon of poking at the site, which the
        # clever version called enumeration and this one does not.
        session["unserved_paths"] = session["unique_paths"] - session["distinct_2xx_paths"]
        session["behaviour"] = behaviour_for(session)
        out.append(session)
    return out


def count_sessions(conn: sqlite3.Connection, ip: str) -> int:
    """How many sessions this address has, whatever a page chose to show."""
    row = conn.execute(
        f"""
        WITH ordered AS (
            SELECT v.timestamp,
                   LAG(v.timestamp) OVER (ORDER BY v.timestamp, v.id) AS prev_ts
            FROM visits v WHERE v.ip = :ip
        )
        SELECT SUM(CASE WHEN prev_ts IS NULL OR {_GAP_SQL} > :gap THEN 1 ELSE 0 END)
        FROM ordered
    """,
        {"ip": ip, "gap": SESSION_GAP_SECONDS},
    ).fetchone()
    return row[0] or 0


def _duration_seconds(started: str, ended: str) -> int:
    """Wall-clock length of a session, in whole seconds.

    Zero is a real answer and means "inside one second", not "instant" — the log
    resolves to the second and cannot say more. Every surface showing this has
    to carry that caveat rather than implying a precision the data lacks.
    """
    from datetime import datetime

    try:
        return int(
            (datetime.fromisoformat(ended) - datetime.fromisoformat(started)).total_seconds()
        )
    except ValueError:
        return 0
