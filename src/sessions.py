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
# statements (Browser signal, Rate Limited), not the --grp-*/--sig-* tokens.
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

# One thing is an event, not a behaviour: no pace, no sequence, and no second
# path to read anything out of. Most sessions on a quiet site are exactly this,
# and they are left uncharacterised rather than shoved into "browsing", which
# would make browsing the majority label by construction.
#
# "One thing" is the harder half. Raw request count is wrong in both
# directions: a visit arriving on port 80 is two rows for one page, and the
# botnet below has 529 rows that never reached the site at all. What separates
# them is how many *distinguishable* things the client did — the paths it asked
# for, or the requests that actually got through, whichever says more.
_MIN_ACTIONS_FOR_BEHAVIOUR = 2

# Brute force is defined by repetition against one target, not by volume. Five
# is the point where "the link was clicked twice" stops being an explanation.
_BRUTE_REPEATS = 5

# Eight distinct paths the server never served, and more than half the paths
# the session asked for. Both halves are needed: eight alone catches a site
# whose own links have gone stale, and the share alone catches a two-request
# session that happened to miss twice.
_ENUM_UNSERVED_PATHS = 8
_ENUM_UNSERVED_SHARE = 0.5

# Recon is the small version of the same thing, separated from it by size
# rather than by kind. Above this it is enumeration, which the chain reaches
# first.
_RECON_MAX_REQUESTS = 8

# Eight distinct pages that the server actually served. A reader who opens
# eight pages without ever following a link between them is not reading,
# whatever else is true.
_SCRAPE_SERVED_PATHS = 8


def behaviour_for(session: dict) -> str:
    """The behaviour key for one session, or '' when there is not enough to say.

    **Measured on what the client asked for, not on what the server answered.**
    That distinction was not obvious until production showed both ways it
    matters, and both had the same shape: a rule keyed on 404s went quiet
    exactly where the probing was heaviest.

    One address made 117 036 requests, every one of them a port-80 redirect to
    HTTPS it never followed — 527 distinct paths per session with names like
    `/Aqua.arm6`, a botnet looking for somewhere to drop a payload. Nothing was
    ever a 404 because nothing ever reached the site, so a rule counting 404s
    saw a session that had done nothing at all.

    Another probed hard enough that the server started refusing: 2 837 of its
    6 029 requests answered 404 and 3 181 answered 503. Its 404 share fell to
    47 % and slid under a 50 % threshold — so probing harder made it *less*
    likely to be called an enumerator, which is backwards.

    `unserved_paths` — distinct paths that never came back 2xx — is the same
    question asked of the request instead of the response. A redirect, a 404, a
    503 and a 403 all mean the client did not get the thing it asked for.

    '' is a normal and frequent answer. Most sessions on a small site are one
    request, and a label applied to those would say more about the threshold
    than about the visitor.
    """
    if max(session["unique_paths"], session["content_requests"]) < _MIN_ACTIONS_FOR_BEHAVIOUR:
        return ""
    if session["max_path_repeats"] >= _BRUTE_REPEATS and (
        session["post_requests"] >= _BRUTE_REPEATS or session["refused"] >= _BRUTE_REPEATS
    ):
        return "brute-force"
    if (
        session["unserved_paths"] >= _ENUM_UNSERVED_PATHS
        and session["unserved_paths"] > session["unique_paths"] * _ENUM_UNSERVED_SHARE
    ):
        return "enumeration"
    # Recon asks for the well-known things, and those come back 404 — so it is
    # keyed on paths that do not exist, not on paths that were merely not
    # served. A redirect is not a short look for anything, and a session of two
    # port-80 redirects knows nothing about anything. `content_requests` rather
    # than `requests` is what makes "short" mean short: the documented rule is
    # that a port-80 redirect never belongs in a denominator.
    if session["probe_404"] and 1 <= session["content_requests"] <= _RECON_MAX_REQUESTS:
        return "recon"
    if session["distinct_2xx_paths"] >= _SCRAPE_SERVED_PATHS and not session["internal_nav"]:
        return "scraping"
    if session["internal_nav"] or session["ok_requests"] >= _MIN_ACTIONS_FOR_BEHAVIOUR:
        return "browsing"
    return ""
