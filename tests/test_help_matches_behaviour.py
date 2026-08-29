"""What the help says you can type has to be what the search accepts.

The Signals tab is generated from the registry, so it printed `has_tags` and
`dnsbl_listed` as the values to use — and both resolved to nothing. The term was
dropped in silence while the page still drew a pill claiming the filter, so the
reader saw an unfiltered list under a label that said otherwise. Generated help
is only trustworthy if what it generates is reachable.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src import search
from src.main import app
from src.queries._shared import _term_sql
from src.taxonomy import SIGNALS
from tests.test_dashboard_routes import dashboard_db  # noqa: F401


def _resolves(value: str) -> bool:
    """Whether `signal:<value>` produces a WHERE fragment rather than nothing."""
    terms, unknown = search.parse(f"signal:{value}")
    assert terms and not unknown, f"signal:{value} did not parse"
    intel, _params, visit, _vp = _term_sql(terms[0], "v.ip")
    return bool(intel or visit)


class TestEverySignalNameWorks:
    @pytest.mark.parametrize("sig", SIGNALS, ids=lambda s: s.key)
    def test_the_key_the_help_prints(self, sig):
        """The Signals tab shows s.key as the value to type."""
        assert _resolves(sig.key), f"signal:{sig.key} filters nothing"

    @pytest.mark.parametrize("sig", SIGNALS, ids=lambda s: s.key)
    def test_the_short_form_the_help_lists(self, sig):
        """And the short forms, which the tab lists underneath."""
        assert _resolves(sig.alias), f"signal:{sig.alias} filters nothing"

    def test_the_syntax_table_lists_every_short_form(self):
        """The note beside `signal:tor` had lost `mobile` when that signal
        became filterable. It is generated now."""
        note = next(f.note for f in search.FIELDS if f.name == "signal")
        for sig in SIGNALS:
            assert sig.alias in note, f"{sig.alias} missing from the syntax help"


class TestTheSearchSpanIsNamedHonestly:
    """The help named five categories on every grouping — one of them ("geo")
    not a field at all — while the IP grouping searches eleven columns and each
    aggregation searches two or three."""

    @pytest.fixture
    def client(self, dashboard_db):  # noqa: F811
        from src.config import settings

        with patch.object(settings, "db_path", dashboard_db):
            yield TestClient(app)

    def test_the_ip_grouping_names_the_real_field_list(self, client):
        text = client.get("/visitors").text
        for name in search.BROAD_FIELDS:
            label = next(f.label for f in search.FIELDS if f.name == name)
            assert f"<code>{label}</code>" in text, f"{label} not named in the help"
        assert "geo" not in text.split("Anything else")[1].split("</p>")[0]

    @pytest.mark.parametrize(
        "group,expected",
        [
            ("asn", "org, ISP and ASN"),
            ("country", "country name and code"),
            ("path", "path and user-agent"),
        ],
    )
    def test_each_aggregation_names_its_own_columns(self, client, group, expected):
        text = client.get(f"/visitors?group={group}").text
        assert expected in text
        # And does not also claim the broad list, which it does not search.
        assert "Anything else is matched against" not in text


class TestClearingTheChipsKeepsTheWindow:
    """The documented rule is that the range tabs own the time window. The All
    chip deleted date_from and date_to along with the drill-downs, so clearing a
    class selection silently threw away a custom range set elsewhere on the
    page."""

    def test_the_javascript_does_not_touch_the_date_params(self):
        from pathlib import Path

        js = (Path(__file__).resolve().parent.parent / "src/static/js/filters.js").read_text()
        body = js.split("function buildFilterUrl")[1].split("function initFilterBar")[0]
        assert "'date_from'" not in body and "'date_to'" not in body
