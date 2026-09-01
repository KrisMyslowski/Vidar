"""Sessions that ran the same program at the same time.

One query, and the expensive one in this codebase. Sessionising *every* address
is the case VID-14 measured at 242 ms over 500 000 visits against 0.1 ms for a
single one, and this does four more passes on top of it: 395 ms over 82 000
visits of realistically shaped traffic, 1.7 s over a 520 000-visit set where
every address probes. That is why it is here and not on a per-visitor surface,
why the route caches it, and why nothing else may reach for it per request.

The cost is spread evenly over five passes rather than sitting in one place —
509 / 273 / 363 / 232 / 264 ms on the larger set — so there is nothing to fix
by tuning one of them. One thing was tried and removed: dropping addresses with
fewer than SIGNATURE_PATHS distinct probe paths before the window functions,
which cannot change the result. It saved 11 % on realistic traffic and cost
40 % where every address probes, because the extra pass is paid either way and
only sometimes earns anything.

The signature is built by pivot — MAX(CASE WHEN rn = k …) — rather than by
`GROUP_CONCAT(path ORDER BY …)`. The aggregate ORDER BY needs SQLite 3.44, and
both this machine (3.53) and the deploy image (3.46) have it, which is exactly
the kind of agreement that turns into an undocumented minimum version the day
someone deploys on an older base image. The pivot works everywhere and says
plainly how long a signature is.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta

from ..classifier.patterns import _CONVENTION_404_MATCH
from ..incidents import INCIDENT_GAP_SECONDS, MIN_ADDRESSES, SIGNATURE_PATHS, score
from ..sessions import SESSION_GAP_SECONDS
from ._shared import _date_conditions

# The signature columns, one per position. Built here rather than written out
# so SIGNATURE_PATHS stays the single place the length is decided.
# char(10), not '\\n': SQLite string literals carry no backslash escapes, so
# '\\n' is the two characters \\ and n and the Python split found nothing to split.
# A newline cannot occur inside a logged path — nginx would have ended the line —
# which is what makes it safe as a separator where an ordinary character is not.
_SIG_PIVOT = " || char(10) || ".join(
    f"COALESCE(MAX(CASE WHEN rn = {k} THEN path END), '')" for k in range(1, SIGNATURE_PATHS + 1)
)

_GAP = "(strftime('%s', timestamp) - strftime('%s', prev_ts))"


# The chain from raw visits to one row per session, with its signature.
#
# Two queries read it: get_incidents() groups these spans into events, and
# get_incident_sessions() hands the spans themselves back for one event. A
# second copy is how the two would start disagreeing about what a session is,
# and that would surface as an incident whose panel lists a different set of
# addresses than its own row counts.
#
# Built here so the module-level fragments are substituted once; `{where}`
# stays open because the window is per call, and the caller closes it with
# .format(where=...).
_SESSION_SPANS_CTE = f"""        WITH ordered AS (
            SELECT v.ip, v.id, v.timestamp, v.path,
                   LAG(v.timestamp) OVER (PARTITION BY v.ip ORDER BY v.timestamp, v.id)
                       AS prev_ts
            FROM visits v
            WHERE v.status = 404 AND NOT ({_CONVENTION_404_MATCH})
              {{where}}
        ),
        marked AS (
            SELECT ip, id, timestamp, path,
                   SUM(CASE WHEN prev_ts IS NULL OR {_GAP} > :session_gap
                            THEN 1 ELSE 0 END)
                       OVER (PARTITION BY ip ORDER BY timestamp, id) AS session_no
            FROM ordered
        ),
        -- Everything the rest needs comes out of this one grouping, including
        -- the session's span. Reaching back into `marked` for it instead meant
        -- touching the full probe set a second time: 2.9 s against 1.7 s on
        -- 520 000 visits, and `marked` is the widest thing in the query.
        first_hit AS (
            SELECT ip, session_no, path, MIN(id) AS first_id, COUNT(*) AS hits,
                   MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts
            FROM marked GROUP BY ip, session_no, path
        ),
        per_session AS (
            SELECT ip, session_no, MIN(first_ts) AS started, MAX(last_ts) AS ended,
                   SUM(hits) AS probe_404
            FROM first_hit GROUP BY ip, session_no
        ),
        ranked AS (
            SELECT ip, session_no, path, hits,
                   ROW_NUMBER() OVER (PARTITION BY ip, session_no ORDER BY first_id) AS rn
            FROM first_hit
        ),
        sessions AS (
            SELECT r.ip, r.session_no, {_SIG_PIVOT} AS signature
            FROM ranked r
            WHERE r.rn <= {SIGNATURE_PATHS}
            GROUP BY r.ip, r.session_no
            -- A signature shorter than its full length is a session that
            -- probed fewer paths than it takes to identify a program. Two
            -- addresses that each asked for /.env once are not a campaign.
            HAVING COUNT(*) = {SIGNATURE_PATHS}
        ),
        spans AS (
            SELECT s.signature, s.ip, p.started, p.ended, p.probe_404
            FROM sessions s
            JOIN per_session p ON p.ip = s.ip AND p.session_no = s.session_no
        )
"""


def get_incidents(
    conn: sqlite3.Connection,
    since: str | None = None,
    until: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Runs of one program across several addresses, most notable first.

    Empty is a valid and frequent answer, especially on a small site. The page
    has to say that rather than showing an empty table — correlation without
    volume is noise, and a surface that manufactures incidents to avoid looking
    idle is worse than one that admits there were none.

    **`limit` cuts after the ordering, not before it.** It used to be a SQL
    LIMIT on a query with no ORDER BY, and the score that orders these rows is
    computed in Python afterwards — so the limit kept an arbitrary handful and
    the sort then ordered only those. Against a real month, asking for three
    returned incidents scoring 44, 39 and 37 while the actual top three scored
    135, 104 and 101. A page whose whole purpose is to surface the worst was
    able to drop exactly the worst.

    Latent rather than live at the default of 50 against twelve incidents, and
    it would have become live the moment a busier deployment crossed it.
    """
    # Named, not positional: the window sits inside the first of five CTEs and
    # every other parameter sits elsewhere. Ordering those by hand is how
    # get_exposures bound its window to a class name and went silently empty.
    conds, window = _date_conditions(since, until, column="v.timestamp", named=True)
    where = "".join(f" AND {c}" for c in conds)
    spans_cte = _SESSION_SPANS_CTE.format(where=where)
    rows = conn.execute(
        f"""
        {spans_cte},
        chained AS (
            SELECT *,
                   SUM(CASE WHEN prev_ts IS NULL OR {_GAP} > :incident_gap
                            THEN 1 ELSE 0 END)
                       OVER (PARTITION BY signature ORDER BY started, ip) AS incident_no
            FROM (
                SELECT signature, ip, started AS timestamp, started, ended, probe_404,
                       LAG(started) OVER (PARTITION BY signature ORDER BY started, ip)
                           AS prev_ts
                FROM spans
            )
        )
        SELECT c.signature,
               c.incident_no,
               MIN(c.started) AS started,
               MAX(c.ended)   AS ended,
               COUNT(DISTINCT c.ip)   AS addresses,
               COUNT(DISTINCT NULLIF(i.asn, '')) AS asns,
               SUM(c.probe_404)       AS probe_404,
               COUNT(DISTINCT CASE WHEN i.is_hosting THEN c.ip END)    AS hosting,
               COUNT(DISTINCT CASE WHEN i.dnsbl_listed THEN c.ip END)  AS blocklisted,
               -- No ORDER BY inside the aggregate, so no version floor: the
               -- member list is a set and the page sorts it. DISTINCT in
               -- GROUP_CONCAT works only with the default separator, which is
               -- why it is a comma and the split below matches.
               GROUP_CONCAT(DISTINCT c.ip) AS member_ips
        FROM chained c
        LEFT JOIN ip_intel i ON i.ip = c.ip
        GROUP BY c.signature, c.incident_no
        HAVING COUNT(DISTINCT c.ip) >= :min_addresses
    """,
        {
            **window,
            "session_gap": SESSION_GAP_SECONDS,
            "incident_gap": INCIDENT_GAP_SECONDS,
            "min_addresses": MIN_ADDRESSES,
        },
    ).fetchall()
    return _decorate(rows)[:limit]


def _decorate(rows) -> list[dict]:
    """Attach the paths and the sort key, then order by it.

    Sorting happens here rather than in SQL because the key lives in
    src/incidents.py, where its weights can be read next to the reasoning for
    them. A weight buried in an ORDER BY is a weight nobody revisits.
    """
    out = []
    for row in rows:
        incident = dict(row)
        signature = incident.pop("signature")
        incident["paths"] = [p for p in signature.split("\n") if p]
        # A short name for the signature, because a URL has to carry it and the
        # signature itself is five paths — on this deployment one of them is a
        # 120-character PHP payload. The digest is over the same canonical form
        # the pivot builds, so it is stable across calls and across processes.
        incident["digest"] = _signature_digest(signature)
        incident["members"] = sorted((incident.pop("member_ips") or "").split(","))
        incident["duration"] = _seconds_between(incident["started"], incident["ended"])
        incident["score"] = score(incident)
        out.append(incident)
    out.sort(key=lambda i: (-i["score"], i["started"]))
    return out


def _seconds_between(started: str, ended: str) -> int:
    """Wall-clock length of a run, in whole seconds.

    Zero means "inside one second", not "instant": the log resolves to the
    second and cannot say more. Unparseable is zero rather than an exception —
    LogEntry.time is an unvalidated string and one bad row must not take the
    page down.
    """
    try:
        return int(
            (datetime.fromisoformat(ended) - datetime.fromisoformat(started)).total_seconds()
        )
    except (ValueError, TypeError):
        return 0


def _signature_digest(signature: str) -> str:
    """A short, stable name for one signature."""
    return hashlib.sha256(signature.encode()).hexdigest()[:16]


def _padded(since: str) -> str:
    """One session gap earlier, so a boundary can be recognised at the edge.

    Session starts are found by looking for silence before a request. Cut the
    visits at the incident's first moment and an address that was already busy
    looks as though it had just started — its run would be split at the cut and
    the tail could carry the signature. An unparseable bound means no padding
    rather than no answer; the caller still holds the result to the incident's
    own window.
    """
    try:
        return (datetime.fromisoformat(since) - timedelta(seconds=SESSION_GAP_SECONDS)).isoformat()
    except (ValueError, TypeError):
        return since


def get_incident_sessions(
    conn: sqlite3.Connection, since: str, until: str, digest: str
) -> tuple[str, list[dict]]:
    """The signature an incident carries, and the sessions it is made of.

    The signature comes back because the caller needs it to ask what those
    sessions requested, and only this query knows it — the digest is a name for
    it, not a way back to it.

    An incident is a signature and a stretch of time, and that pair names it —
    no stored id, the same way a session needs none. The signature travels as a
    digest because five paths do not fit comfortably in a URL.

    **The window is padded backwards by one session gap**, and that is the whole
    correctness of this query. Session boundaries are found by looking for
    silence before a request; truncate the visits at the incident's first
    moment and the first request of every member session has nothing before it,
    which is right — but a session that had a neighbour just before the cut
    would be split there and carry a different first five paths. Padding by the
    gap means the emptiness that defines a start is inside the window and can
    be seen. Sessions that then begin before the incident are dropped: they are
    not part of it.
    """
    padded = _padded(since)
    conds, window = _date_conditions(padded, until, column="v.timestamp", named=True)
    where = "".join(f" AND {c}" for c in conds)
    rows = conn.execute(
        f"""
        {_SESSION_SPANS_CTE.format(where=where)}
        SELECT s.signature, s.ip, s.started, s.ended, s.probe_404,
               COALESCE(i.asn, '') AS asn,
               COALESCE(i.org, '') AS org,
               COALESCE(i.country_code, '') AS country_code,
               -- The full signal set, not just two of them: the panel draws the
               -- same ip_signal_bar as every other surface, and selecting a
               -- subset here made an address on Tor read as having no signals.
               COALESCE(i.is_tor, 0)       AS is_tor,
               COALESCE(i.is_proxy, 0)     AS is_proxy,
               COALESCE(i.is_hosting, 0)   AS is_hosting,
               COALESCE(i.dnsbl_listed, 0) AS dnsbl_listed,
               COALESCE(i.dnsbl_sources, '') AS dnsbl_sources,
               (SELECT GROUP_CONCAT(tag) FROM ip_intel_tags WHERE ip = s.ip) AS tags,
               (i.ip IS NOT NULL)          AS enriched
        FROM spans s
        LEFT JOIN ip_intel i ON i.ip = s.ip
        WHERE s.started >= :from_ts AND s.started <= :to_ts
        ORDER BY s.started, s.ip
    """,
        {**window, "session_gap": SESSION_GAP_SECONDS, "from_ts": since, "to_ts": until},
    ).fetchall()
    # Matched in Python rather than in SQL: the digest is ours, not SQLite's,
    # and hashing in the query would mean registering a second scalar function
    # for one comparison over a handful of rows.
    signature, out = "", []
    for row in rows:
        session = dict(row)
        found = session.pop("signature")
        if _signature_digest(found) != digest:
            continue
        signature = found
        session["duration"] = _seconds_between(session["started"], session["ended"])
        out.append(session)
    return signature, out


def get_incident_paths(
    conn: sqlite3.Connection, since: str, until: str, signature: str
) -> list[dict]:
    """What an incident asked for, in the order the paths first arrived.

    Only the paths the incident is built from — requests for something that
    does not exist, convention files excluded, the same set every other figure
    on the row counts. Widening it to every request the member sessions made
    would put a different total under a row that already states one, and two
    numbers describing one event is how a page stops being believed.

    Unbounded on purpose: the largest campaign on the reference deployment
    asks for 266 distinct paths, which is a list, not a load. The caller
    decides how much of it to draw at once and pages the rest.
    """
    padded = _padded(since)
    conds, window = _date_conditions(padded, until, column="v.timestamp", named=True)
    where = "".join(f" AND {c}" for c in conds)
    rows = conn.execute(
        f"""
        {_SESSION_SPANS_CTE.format(where=where)}
        SELECT m.path,
               COUNT(DISTINCT m.ip) AS addresses,
               COUNT(*)             AS requests,
               MIN(m.id)            AS first_id
        FROM marked m
        JOIN sessions s    ON s.ip = m.ip AND s.session_no = m.session_no
        JOIN per_session p ON p.ip = m.ip AND p.session_no = m.session_no
        WHERE s.signature = :signature
          AND p.started >= :from_ts AND p.started <= :to_ts
        GROUP BY m.path
        ORDER BY first_id
    """,
        {
            **window,
            "session_gap": SESSION_GAP_SECONDS,
            "signature": signature,
            "from_ts": since,
            "to_ts": until,
        },
    ).fetchall()
    marks = set(signature.split("\n"))
    return [{**dict(r), "in_signature": r["path"] in marks} for r in rows]
