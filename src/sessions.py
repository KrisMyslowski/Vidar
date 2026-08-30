"""What an address *did*, as a third axis beside what it is and where it sits.

Identity (`visitor_class`) and the network signals are orthogonal already, and
that split is what keeps the classifier honest. Behaviour was the axis missing
from it: a human can scrape and a search crawler can enumerate, and with only
two axes the priority chain has to weigh such cases against each other and crown
a winner. It no longer has to.

Behaviour belongs to a **session**, not to an address. One address can read two
pages in the morning and walk a scanner list at night, and an address-level
label would have to pick one and be wrong about the other half of the evidence.

**Sessions are computed when they are read, never stored.** Measured on a
synthetic 520 000-visit database: sessionising one address costs 0.10 ms at 66
visits and 24 ms at 20 000, against 0.42 ms and 70 ms for the evidence query
that already runs on the same address — `idx_visits_ip_timestamp` hands the rows
over in order, so no sort happens. Only the all-addresses-at-once form is
expensive (242 ms), and no surface asks for it per request. Not storing it means
no migration, no backfill, and no session that goes stale when a month is
re-imported from an archive with its original visit ids.
"""

from __future__ import annotations

from typing import NamedTuple

# ── Where one session ends and the next begins ───────────────────────────────

# Thirty minutes of silence. This is a model decision with no correct answer,
# so it is written down rather than tuned quietly:
#
#   * It is the web-analytics convention, which matters less for being right
#     than for being the number a reader already has an intuition about.
#   * Long enough that somebody who stops to actually read a page does not come
#     back as a second visitor. Ten minutes splits real reading.
#   * Short enough that a scanner's next sweep — hours or days later — is a new
#     session rather than one endless one. Without an upper bound, the busiest
#     addresses collapse into a single session covering the whole retention
#     window, which is the one shape that carries no information at all.
#
# Changing it changes every session count retroactively, because nothing is
# stored. That is the argument for it being a constant here with this comment
# attached, and not an environment variable somebody adjusts between two
# screenshots.
SESSION_GAP_SECONDS = 1800

# nginx logs `$time_iso8601`, which resolves to the second. Everything below a
# second is invisible: two requests in the same second have no order in time
# (`id` orders them, which is arrival order, not necessarily wall-clock order)
# and a duration of 0 means "under two seconds", not "instant". Any surface
# showing pace has to say so rather than implying a precision the log does not
# carry.
TIME_RESOLUTION_SECONDS = 1


class Behaviour(NamedTuple):
    """One kind of thing an address does in a session."""

    key: str
    label: str
    what: str


# The chain below is a priority chain, in this order, first match wins — the
# same shape as the classifier's, and for the same reason: a session that looks
# like two things at once needs a rule about which one it is called, not a
# score that hides the question.
BEHAVIOURS: tuple[Behaviour, ...] = (
    Behaviour(
        "brute-force",
        "Brute force",
        "The same path, over and over, mostly refused. Someone trying credentials "
        "or tokens against one door rather than looking for doors.",
    ),
    Behaviour(
        "enumeration",
        "Enumeration",
        "A list being walked: many different paths that do not exist, in one "
        "stretch. The paths are the input, not the target — most of them were "
        "never going to be here.",
    ),
    Behaviour(
        "recon",
        "Recon",
        "A short look for the well-known things — an admin panel, a config file, "
        "a phpinfo. Few requests, and the ones chosen say what was hoped for.",
    ),
    Behaviour(
        "scraping",
        "Scraping",
        "Many pages that do exist, taken quickly and without following links. "
        "Reading the site the way a program reads it.",
    ),
    Behaviour(
        "browsing",
        "Browsing",
        "Pages that exist, reached from one another, at a pace a person could "
        "produce. What the site is for.",
    ),
)

BEHAVIOUR_LABELS = {b.key: b.label for b in BEHAVIOURS}
BEHAVIOUR_TIPS = {b.key: b.what for b in BEHAVIOURS}

# The generic severity badges the detail page already uses for its non-taxonomy
# statements (Verified Browser, Rate Limited), not the --grp-*/--sig-* tokens.
# Borrowing a group colour would undo the whole point: a human that scrapes
# would wear an "automated" colour, and the third axis would read as the first.
# Behaviour has no colour of its own in the legend, and inventing one is a
# decision for whoever puts behaviour on a surface that needs a legend.
BEHAVIOUR_BADGES = {
    "brute-force": "badge-red",
    "enumeration": "badge-red",
    "recon": "badge-yellow",
    "scraping": "badge-yellow",
    "browsing": "badge-green",
}


# ── The thresholds, and why each one is where it is ──────────────────────────

# One request is an event, not a behaviour. There is no pace, no sequence and
# no choice of second path to read anything out of, and most sessions on a
# quiet site are exactly this. They are left uncharacterised rather than shoved
# into "browsing", which would make browsing the majority label by construction.
_MIN_REQUESTS_FOR_BEHAVIOUR = 2

# Brute force is defined by repetition against one target, not by volume. Five
# is the point where "the link was clicked twice" stops being an explanation.
_BRUTE_REPEATS = 5

# Eight distinct paths that do not exist, and more than half the session spent
# on them. Both halves are needed: eight alone catches a broken deployment
# whose own pages 404, and the ratio alone catches a two-request session that
# happened to miss twice.
_ENUM_DISTINCT_404 = 8
_ENUM_404_SHARE = 0.5

# Recon is the small version of the same thing, and is separated from it by
# size rather than by kind. Above this it is enumeration, which the chain
# reaches first.
_RECON_MAX_REQUESTS = 8

# Eight distinct pages that do exist. A reader who opens eight pages without
# ever following a link between them is not reading, whatever else is true.
_SCRAPE_DISTINCT_2XX = 8


def behaviour_for(session: dict) -> str:
    """The behaviour key for one session, or '' when there is not enough to say.

    '' is a normal and frequent answer. Most sessions on a small site are one
    request, and a label applied to those would say more about the threshold
    than about the visitor.
    """
    if session["requests"] < _MIN_REQUESTS_FOR_BEHAVIOUR:
        return ""
    if session["max_path_repeats"] >= _BRUTE_REPEATS and (
        session["post_requests"] >= _BRUTE_REPEATS or session["refused"] >= _BRUTE_REPEATS
    ):
        return "brute-force"
    if (
        session["distinct_404_paths"] >= _ENUM_DISTINCT_404
        and session["probe_404"] > session["requests"] * _ENUM_404_SHARE
    ):
        return "enumeration"
    if session["probe_404"] and session["requests"] <= _RECON_MAX_REQUESTS:
        return "recon"
    if session["distinct_2xx_paths"] >= _SCRAPE_DISTINCT_2XX and not session["internal_nav"]:
        return "scraping"
    if session["internal_nav"] or session["ok_requests"] >= _MIN_REQUESTS_FOR_BEHAVIOUR:
        return "browsing"
    return ""
