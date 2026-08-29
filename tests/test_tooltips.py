"""One mechanism decides what a tooltip is made of.

Two forms drifted apart before this: the filter chips grew What/How pairs while
stat_card and th_tip hard-wired the single line, and analysis.html rebuilt <th>
markup by hand to get a pair out of a macro that had none. Every explanation now
goes through macros/_tip.html, and these hold that.
"""

import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.routes._app import templates
from tests.test_dashboard_routes import dashboard_db  # noqa: F401

TEMPLATES = Path(__file__).resolve().parent.parent / "src/templates"

PAGES = ["/", "/visitors", "/analysis", "/exposure", "/visitors/203.0.113.10", "/settings/storage"]


@pytest.fixture
def html(dashboard_db):  # noqa: F811
    from src.config import settings

    with patch.object(settings, "db_path", dashboard_db):
        client = TestClient(app)
        return "\n".join(client.get(p).text for p in PAGES)


class TestTheSwitch:
    """TIP_TITLES writes a native title= alongside. Both are implemented; it is
    off, because with it on the browser draws its own delayed box beside the
    styled one, saying the same thing in a different place."""

    def test_it_is_off(self):
        assert templates.env.globals["TIP_TITLES"] is False

    def test_no_native_tooltip_sits_on_a_tooltipped_element(self, html):
        doubled = re.findall(r'data-tip(?:-what)?="[^"]*"[^>]*title="', html)
        assert not doubled, f"{len(doubled)} element(s) would show two tooltips"

    def test_turning_it_on_writes_the_title(self, dashboard_db):  # noqa: F811
        """The other half of "both implemented" — proven, not assumed.

        The template cache is cleared around the flip, and that is the point
        rather than a workaround: Jinja folds `{% if TIP_TITLES %}` away while
        compiling, because the global is a constant. The branch costs nothing at
        render time, and the switch is a deploy-time decision, not a runtime one.
        A test that flips it therefore has to recompile.
        """
        from src.config import settings

        templates.env.globals["TIP_TITLES"] = True
        templates.env.cache.clear()
        try:
            with patch.object(settings, "db_path", dashboard_db):
                text = TestClient(app).get("/visitors").text
        finally:
            templates.env.globals["TIP_TITLES"] = False
            templates.env.cache.clear()
        titled = re.findall(r'data-tip-what="[^"]*" data-tip-source="[^"]*" title="', text)
        assert titled, "the switch is on and nothing carries a title"


class TestNothingWritesAttributesByHand:
    """The macro is the only author. A template that writes the attributes
    itself is how the two forms came apart in the first place."""

    @pytest.mark.parametrize("template", sorted(TEMPLATES.rglob("*.html")), ids=lambda p: p.name)
    def test_no_template_emits_tooltip_attributes_directly(self, template):
        if template.name == "_tip.html":
            return  # the one place that may
        text = template.read_text()
        found = re.findall(r'\bdata-tip(?:-what|-source)?="', text)
        assert not found, f"{len(found)} hand-written tooltip attribute(s) — use tip_attrs()"


class TestTheMacroTakesBothForms:
    """A string is still understood so the remaining call sites can move over
    file by file. The pair is the target."""

    def test_a_string_renders_the_single_line_form(self, html):
        assert 'data-tip="' in html

    def test_a_pair_renders_what_and_how(self, html):
        assert 'data-tip-what="' in html and 'data-tip-source="' in html

    def test_an_empty_tip_renders_no_attribute(self, html):
        assert 'data-tip=""' not in html
        assert 'data-tip-what=""' not in html


class TestNothingInteractiveIsUnexplained:
    """Eleven live controls carried no explanation of any kind.

    Not an oversight one at a time — the rail grew chip by chip and each new one
    inherited whatever the last had. The All chip, the Signals menu that hides
    the whole second dimension of the taxonomy, the search box, the range tabs
    that scope every number on the page, the date fields that silently override
    the preset: all of them changed what the reader was looking at and said
    nothing about it.
    """

    def _rail(self, html):
        return html.split('class="filter-rail-row"')[1].split("filter-rail-searchrow")[0]

    def test_the_all_chip_explains_itself(self, html):
        rail = self._rail(html)
        chip = rail.split("filter-toggle--all")[1].split(">")[0]
        assert "data-tip-what" in chip
        assert "aria-pressed" in chip, "a toggle has to say whether it is on"

    def test_the_signals_menu_explains_the_second_dimension(self, html):
        assert "What is known about an IP, beyond what it is." in html

    def test_the_search_box_has_a_name_and_an_explanation(self, html):
        box = html.split('type="search"')[1].split(">")[0]
        assert "aria-label" in box, "the placeholder disappears on focus"
        assert "data-tip-what" in box

    def test_every_chip_count_says_what_it_counts(self, html):
        """A bare number beside a label. That it means distinct IPs inside the
        selected range, rather than requests or all-time, is not guessable."""
        assert "Distinct IPs in this group." in html

    def test_the_range_tabs_say_what_they_govern(self, html):
        assert "Scope every number on this page to" in html

    def test_the_date_fields_say_they_override_the_preset(self, html):
        assert "overrides the preset" in html or "marks the range as custom" in html


class TestTheJavaScriptFollowsTheSameShape:
    """Three tooltips are built in JS, where a Jinja macro cannot reach.

    map.js writes the class legend and the viewport pill, overflow.js the [+N]
    chip. They cannot go through tip_attrs(), so the rule they *can* be held to
    is the attribute shape: a pair writes both halves, never one. A lone
    data-tip-what renders a How row reading "undefined".
    """

    JS = Path(__file__).resolve().parent.parent / "src/static/js"

    @pytest.mark.parametrize("name", ["map.js", "overflow.js"], ids=["map", "overflow"])
    def test_a_pair_is_never_written_half(self, name):
        src = (self.JS / name).read_text()
        whats = src.count("data-tip-what") + src.count("tipWhat")
        hows = src.count("data-tip-source") + src.count("tipSource")
        assert whats == hows, f"{name}: {whats} What against {hows} How"
