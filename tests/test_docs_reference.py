"""data-reference.md calls itself authoritative, so hold it to that.

Two tables in it restate something the code owns, and a restatement drifts. The
config table had: Settings grew to 38 fields while the table described 29, and
the nine it lost were the whole backup block plus every SERVER_* label — absent
from the one document that claims to be their home.

tests/test_config.py does this for .env.example and is why that file stayed
complete. This is the same guard for the prose.
"""

from __future__ import annotations

import re
from pathlib import Path

from src.config import Settings
from src.taxonomy import VALID_SIGNALS

DOC = Path(__file__).resolve().parent.parent / "docs" / "data-reference.md"


def _section(number: str) -> str:
    """The text of one numbered section, up to the next heading of any depth."""
    text = DOC.read_text(encoding="utf-8")
    start = re.search(rf"^#+ {re.escape(number)}[ .]", text, re.M)
    assert start, f"section {number} is gone from data-reference.md"
    rest = text[start.end() :]
    end = re.search(r"^#+ ", rest, re.M)
    return rest[: end.start()] if end else rest


def _first_column(section: str) -> set[str]:
    """Backticked names in the first cell of every table row in `section`."""
    return set(re.findall(r"^\|\s*`([a-z_0-9]+)`\s*\|", section, re.M))


def test_the_config_table_lists_every_setting():
    documented = _first_column(_section("7"))
    fields = set(Settings.model_fields)
    assert not fields - documented, f"settings missing from §7: {sorted(fields - documented)}"


def test_the_config_table_invents_nothing():
    documented = _first_column(_section("7"))
    fields = set(Settings.model_fields)
    assert not documented - fields, f"§7 documents non-settings: {sorted(documented - fields)}"


def test_the_signal_table_lists_every_signal():
    """§4.2.8 said six and omitted is_mobile, which had become filterable."""
    documented = _first_column(_section("4.2.8"))
    assert (
        not VALID_SIGNALS - documented
    ), f"signals missing from §4.2.8: {sorted(VALID_SIGNALS - documented)}"
