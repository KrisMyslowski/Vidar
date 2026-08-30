"""From nine thousand addresses to ten events.

A visitor list answers "who came". It cannot answer "what happened", and that
is the question somebody actually has. One row saying an address requested
twelve paths that do not exist is a curiosity; eleven addresses across three
operators requesting *the same twelve paths in the same order within seven
minutes* is an event, and it is the kind of thing you can show to someone.

**An incident is a signature plus a stretch of time.** The signature is the
first few paths a session probed, in the order it probed them — a scanner is a
program, and a program starts the same way every time it runs. Sessions
carrying the same signature close together in time are one run of that program,
however many addresses it came from.

The prefix is deliberate. A full path set breaks apart the moment one address
stops early or one extra path is tried, and the failure would be silent: two
incidents where there is one, each below the reporting threshold, so the event
disappears entirely rather than looking wrong. A prefix survives the tail
differing, which is where tools differ.

**Under-reporting is the safe direction here.** A security surface that cries
wolf is read once and then ignored; one that occasionally misses a small event
is still read. Every threshold below is set on that side.
"""

from __future__ import annotations

# How many paths make a signature. Five is enough that two unrelated scanners
# agreeing by accident is implausible — the reference deployment carries 26 609
# distinct probed paths — and few enough that a tool which stops early still
# matches one that ran longer.
SIGNATURE_PATHS = 5

# Sessions with the same signature further apart than this are separate runs.
# An hour: a distributed scan spreads its addresses over minutes, not days, and
# the same tool returning tomorrow is a second event rather than a longer first
# one. A campaign that trickles for a week does split into daily incidents —
# that is a visible, honest under-reporting rather than one incident whose
# duration is meaningless.
INCIDENT_GAP_SECONDS = 3600

# Correlation without volume is noise. Two addresses running the same tool an
# hour apart is a tool being popular, not a coordinated event; the word
# "incident" has to mean something or the page stops being read. Three is the
# smallest number where "the same program, from different places, at the same
# time" is a better explanation than coincidence.
MIN_ADDRESSES = 3


# ── The sort key ─────────────────────────────────────────────────────────────
#
# This is a sort key and nothing else. It is not a measurement, it does not
# estimate a probability, and no decision should hang on its value — the
# columns beside it are the evidence, and the number exists only so the page
# can put the interesting rows first.
#
# Which is why every weight is here rather than inside a query, and why
# score_parts() hands back the contributions and not just the total. A number
# whose derivation cannot be opened is exactly the regression this page is
# meant to avoid: it would put a score where the evidence used to be.

# Coordination is what makes an incident an incident, so the address count
# carries the most weight per unit.
_W_ADDRESSES = 3
# Spread across operators. One misconfigured host at one provider explains a
# lot of traffic; the same program from three networks explains none of it.
_W_ASNS = 2
# Somebody else already thinks these addresses are trouble. An outside opinion
# agreeing with ours is worth more than either alone.
_W_BLOCKLISTED = 4
# Volume, deliberately capped. An address hammering one path all night is a
# large number and not an event, and uncapped it would sort the page by traffic
# rather than by coordination.
_W_PROBES_PER_UNIT = 1
_PROBE_UNIT = 50
_PROBE_CAP = 10


def score_parts(incident: dict) -> list[tuple[str, int, int]]:
    """The contributions to an incident's sort key: (what, count, points).

    Returned rather than folded away so the page can show the arithmetic. The
    counts are the same numbers already in the row, so a reader can check the
    total against what they can see rather than trusting it.
    """
    probes = min(incident["probe_404"] // _PROBE_UNIT, _PROBE_CAP)
    return [
        ("addresses", incident["addresses"], incident["addresses"] * _W_ADDRESSES),
        ("networks", incident["asns"], incident["asns"] * _W_ASNS),
        ("on blocklists", incident["blocklisted"], incident["blocklisted"] * _W_BLOCKLISTED),
        (
            f"probes (per {_PROBE_UNIT}, capped at {_PROBE_CAP})",
            incident["probe_404"],
            probes * _W_PROBES_PER_UNIT,
        ),
    ]


def score(incident: dict) -> int:
    """The sort key. See score_parts() for what it is made of."""
    return sum(points for _, _, points in score_parts(incident))
