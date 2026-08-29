"""Every explanation says WHAT a thing is and HOW that was determined.

The registry had the shape long before it had the discipline: CLASS_TIPS
honoured it almost everywhere, GROUP_TIPS broke it in three of five entries with
a HOW that restated the WHAT ("Automated bot or crawler." / "Bot UA or known
crawler signals.") or listed the member classes instead of the evidence. These
hold the contract mechanically, because prose has no other way to stay honest.
"""

import pytest

from src.taxonomy import CLASS_TIPS, GROUP_TIPS, SIGNALS, VALID_CLASSES, VISITOR_CATEGORIES
from src.template_filters import _PATH_TIPS

# WHAT is one claim; HOW is the observable evidence behind it — a header, a log
# field, an API response, a path family. HOW gets more room because naming the
# evidence means naming it: the pattern lists are the useful half, and cutting
# them to fit a tighter budget would remove exactly what makes it evidence.
MAX_WHAT = 60
MAX_HOW = 140


def _starts_a_sentence(half: str) -> bool:
    """Sentence case, except where the first word is a name that is not.

    phpMyAdmin, ip-api.com and nginx are spelled the way their authors spell
    them; capitalising them to satisfy a rule would be the rule winning over the
    thing it describes. A stylised name is recognisable — it carries a capital
    somewhere after the first character, or it is one of the few that carry none.
    """
    first = half.split()[0].rstrip(".,;:")
    return (
        half[0].isupper()
        or half[0].isdigit()
        or any(c.isupper() for c in first[1:])
        or first.lower() in {"ip-api", "ip-api.com", "nginx", "curl", "zgrab", "masscan"}
    )


ALL_TIPS = (
    [(f"class {k}", v) for k, v in CLASS_TIPS.items()]
    + [(f"group {k}", v) for k, v in GROUP_TIPS.items()]
    + [(f"signal {s.key}", s.tip) for s in SIGNALS]
    # The probe-path tooltips are the fourth registry of explanations and were
    # outside this contract until a review noticed. They reach the same tooltip.
    + [(f"path {k}", v) for k, v in _PATH_TIPS.items()]
)


@pytest.mark.parametrize("name,tip", ALL_TIPS, ids=[n for n, _ in ALL_TIPS])
class TestEveryPair:
    def test_has_both_halves(self, name, tip):
        assert len(tip) == 2 and all(tip), f"{name} is missing a half"

    def test_stays_within_budget(self, name, tip):
        what, how = tip
        assert len(what) <= MAX_WHAT, f"{name}: WHAT is {len(what)} chars"
        assert len(how) <= MAX_HOW, f"{name}: HOW is {len(how)} chars"

    def test_both_halves_are_sentences(self, name, tip):
        for half in tip:
            assert _starts_a_sentence(half), f"{name}: {half[:30]!r} does not start a sentence"
            assert half.endswith("."), f"{name}: {half[-30:]!r} does not end one"

    def test_the_how_is_not_the_what_again(self, name, tip):
        """The failure this file exists for. "Automated bot or crawler." explained
        by "Bot UA or known crawler signals." tells a reader nothing they did not
        have from the label."""
        what, how = tip
        opening = " ".join(how.lower().split()[:4])
        assert not what.lower().startswith(opening), f"{name}: HOW restates WHAT"


class TestCoverage:
    def test_every_class_has_one(self):
        missing = sorted(VALID_CLASSES - set(CLASS_TIPS))
        assert not missing, f"classes with no tooltip: {missing}"

    def test_every_group_the_taxonomy_names_has_one(self):
        """Both the names the taxonomy declares and the ones it displays, which
        are now the same set — see test_the_group_has_one_name."""
        from src.taxonomy import GROUPS_WITH_UNKNOWN

        names = {g for g, _ in VISITOR_CATEGORIES} | set(GROUPS_WITH_UNKNOWN)
        missing = sorted(names - set(GROUP_TIPS))
        assert not missing, f"groups with no tooltip: {missing}"

    def test_the_unknown_group_and_class_say_the_same_thing(self):
        """They are one filter — ?class=unknown — and carried two different
        explanations on the same page."""
        assert GROUP_TIPS["unknown"] == CLASS_TIPS["unknown"]

    def test_the_group_has_one_name(self):
        """It was "other" in VISITOR_CATEGORIES and "unknown" everywhere it was
        displayed, so three maps here carried both spellings and the filter rail
        translated between them on every render."""
        assert "other" not in GROUP_TIPS
        assert "other" not in {g for g, _ in VISITOR_CATEGORIES}

    def test_every_signal_has_one(self):
        assert all(s.tip for s in SIGNALS)


class TestAmericanSpelling:
    """The codebase wrote both. Picking one is arbitrary; writing both is not."""

    BRITISH = ("organisation", "behaviour", "recognised", "analyse", "colour", "centre")

    @pytest.mark.parametrize("name,tip", ALL_TIPS, ids=[n for n, _ in ALL_TIPS])
    def test_no_british_spelling(self, name, tip):
        joined = " ".join(tip).lower()
        found = [w for w in self.BRITISH if w in joined]
        assert not found, f"{name}: {found}"
