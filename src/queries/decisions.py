"""What somebody would need to know in order to decide.

The third part of the sentence this project is filtered by — *who does what on
my server, why, and how do I deal with it* — has been unanswered. Answering it
does not mean acting: Vidar recommends and exports, and something else is the
hand. CrowdSec, nftables or a shell script can help themselves from here.

**The selection is the operator's, and it is always stated.** This does not
return "the bad addresses"; it returns the addresses matching criteria that
come back with the answer. A feed whose membership rule is invisible is a
blocklist, and a blocklist nobody can open is the thing this whole project
argues against.

**Every address carries its reason.** The evidence is what makes a feed
reviewable rather than obeyed, and it is the cheap half of the query — the
class and the counts are already stored.

**Nothing here is a score.** A number would collapse the evidence into a rank
that has to be trusted, which is the opposite direction from the rest of the
dashboard.
"""

from __future__ import annotations

import sqlite3

from ..classifier.patterns import _CONVENTION_404_MATCH
from ..taxonomy import VALID_CLASSES, VALID_GROUPS
from ._shared import _date_conditions

# What Vidar suggests when asked nothing in particular: the group that means
# "this address did something abusive here", over the last week.
#
# A default is a recommendation and has to read as one — it is named in every
# response, so nobody can mistake it for a verdict the tool arrived at on its
# own. Seven days because a feed is for what is happening, and an address that
# stopped a month ago is history rather than a decision.
DEFAULT_GROUPS = ("threats",)
DEFAULT_DAYS = 7

# Above this a feed stops being reviewable and starts being obeyed. It is a
# ceiling on the answer, not on the truth: the response says when it was hit,
# so a caller can narrow instead of quietly receiving a prefix.
MAX_ADDRESSES = 5000


def get_decisions(
    conn: sqlite3.Connection,
    classes: tuple[str, ...] = (),
    groups: tuple[str, ...] = (),
    since: str | None = None,
    until: str | None = None,
    limit: int = MAX_ADDRESSES,
) -> list[dict]:
    """Addresses matching the selection, each with what is known about it.

    Ordered by how much the address did here rather than by any judgement of
    it: probes first, then requests. Sorting by a score would be the thing this
    is deliberately not.
    """
    conds, params = _date_conditions(since, until, column="v.timestamp", named=True)
    where = "".join(f" AND {c}" for c in conds)

    selectors, selector_params = [], {}
    for n, value in enumerate(classes):
        selectors.append(f"i.visitor_class = :cls{n}")
        selector_params[f"cls{n}"] = value
    for n, value in enumerate(groups):
        selectors.append(f"i.visitor_class LIKE :grp{n}")
        selector_params[f"grp{n}"] = f"{value}/%"
    if not selectors:
        return []

    rows = conn.execute(
        f"""
        SELECT v.ip,
               i.visitor_class,
               COUNT(*) AS requests,
               SUM(CASE WHEN v.status = 404 AND NOT ({_CONVENTION_404_MATCH})
                        THEN 1 ELSE 0 END) AS probes,
               MIN(v.timestamp) AS first_seen,
               MAX(v.timestamp) AS last_seen,
               COALESCE(i.asn, '') AS asn,
               COALESCE(i.org, '') AS org,
               COALESCE(i.country_code, '') AS country_code,
               COALESCE(i.is_hosting, 0) AS hosting,
               COALESCE(i.is_tor, 0) AS tor,
               COALESCE(i.dnsbl_listed, 0) AS blocklisted
        FROM visits v
        JOIN ip_intel i ON i.ip = v.ip
        WHERE ({" OR ".join(selectors)})
          {where}
        GROUP BY v.ip
        ORDER BY probes DESC, requests DESC, v.ip
        LIMIT :limit
    """,
        {**params, **selector_params, "limit": limit},
    ).fetchall()
    return [dict(r) for r in rows]


def valid_selection(
    classes: tuple[str, ...], groups: tuple[str, ...]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Drop anything that is not a real class or group.

    Silently, and on purpose: an unknown name selects nothing, so keeping it
    could only ever widen the feed by accident. The response reports what it
    actually used, so a typo shows up as a selection that does not say what the
    caller wrote.
    """
    return (
        tuple(c for c in classes if c in VALID_CLASSES),
        tuple(g for g in groups if g in VALID_GROUPS),
    )
