"""Static assets and markup stay in sync.

Two directions for the stylesheet, both of which went wrong during the
release-UI rebuild: a rule whose markup was deleted lingers forever because
nothing points at it, and a class written into a template without a rule
silently does nothing.

The favicon is here for the same reason — it is markup pointing at a file, and
nothing else would notice if the two stopped agreeing.
"""

import re
from pathlib import Path

from tests.conftest import dashboard_css

SRC = Path(__file__).resolve().parent.parent / "src"
# Every part of the split stylesheet, in load order — see conftest.dashboard_css.
CSS_TEXT = dashboard_css()

# Class names assembled at runtime, so no template contains them literally:
# facet-rows--{{ variant }}, badge-{{ color }} from the taxonomy maps, and the
# sort state that sortable_th sets from Python.
DYNAMIC = {
    "facet-rows--top",
    "facet-rows--card",
    "facet-rows--code",
    "facet-rows--split",
    "badge-red",
    "badge-yellow",
    "badge-blue",
    "badge-purple",
    "badge-muted",
    "badge-green",
    "badge-teal",
    "badge-orange",
    "sort-asc",
    "sort-desc",
}
# Leaflet and MarkerCluster emit these; we only style them.
THIRD_PARTY = ("leaflet", "marker", "mcluster")


def _defined_classes() -> set[str]:
    return set(re.findall(r"\.([a-z][a-z0-9-]{2,})", CSS_TEXT))


def _markup() -> str:
    # rglob, not glob: the blocks live in templates/macros/ since the split, and
    # a non-recursive scan reported all 35 of their classes as unreachable rules.
    parts = [p.read_text() for p in (SRC / "templates").rglob("*.html")]
    parts += [p.read_text() for p in (SRC / "static/js").glob("*.js")]
    parts += [(SRC / "taxonomy.py").read_text(), (SRC / "template_filters.py").read_text()]
    return "\n".join(parts)


def test_no_rule_without_markup():
    """A rule nobody can reach is a rule nobody can trust — it reads as intent."""
    markup = _markup()
    orphans = sorted(
        c
        for c in _defined_classes()
        if c not in markup and c not in DYNAMIC and not c.startswith(THIRD_PARTY)
    )
    assert not orphans, f"CSS rules with no markup: {orphans}"


def test_no_markup_without_rule():
    """The other direction: a class in a template that no rule ever styles.

    Both `mix-bar--linked` and `label-help--right` sat in templates for months
    without a single declaration behind them.
    """
    defined = _defined_classes()
    used: set[str] = set()
    for template in (SRC / "templates").rglob("*.html"):
        for attr in re.findall(r'class="([^"]*)"', template.read_text()):
            # Skip Jinja expressions — those resolve to the DYNAMIC names above.
            if "{" in attr:
                continue
            used.update(c for c in attr.split() if "-" in c)
    unstyled = sorted(c for c in used if c not in defined and not c.startswith(THIRD_PARTY))
    assert not unstyled, f"classes in markup with no CSS rule: {unstyled}"


# ── Favicon ──────────────────────────────────────────────────────────────────

FAVICON = SRC / "static" / "img" / "favicon.svg"


def test_the_markup_points_at_a_file_that_exists():
    """One <link rel="icon"> in base.html, and something behind it."""
    links = re.findall(
        r'<link rel="icon" href="/static/([^?"]+)', (SRC / "templates" / "base.html").read_text()
    )
    assert len(links) == 1, f"expected one icon link, found {links}"
    assert (SRC / "static" / links[0]).is_file()


def test_the_icon_is_painted_for_both_themes():
    """A single colour goes invisible on one of the two tab strips.

    The product has no brand hue: near-black on light, white on dark. Whoever
    works in one theme would never notice the icon vanishing in the other, so
    both branches are asserted.

    Matched on the paint property rather than a literal `fill:` — the mark went
    from a filled silhouette to a stroked one and the old wording failed for a
    change that was not a fault.
    """
    svg = FAVICON.read_text()
    assert "prefers-color-scheme: dark" in svg
    colours = re.findall(r"(?:fill|stroke)\s*:\s*#[0-9a-fA-F]{3,6}", svg)
    assert len(colours) >= 2, f"expected a light and a dark paint, found {colours}"
    assert len(set(colours)) >= 2, f"both branches paint the same: {colours}"


def test_the_icon_is_well_formed():
    import xml.etree.ElementTree as ET

    ET.parse(FAVICON)


def test_favicon_ico_is_served():
    """The four JSON tabs from settings_api.html ask for this path.

    No database fixture: the route reads a file and nothing else.
    """
    from fastapi.testclient import TestClient

    from src.main import app

    response = TestClient(app).get("/favicon.ico")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"


def test_no_script_formats_a_number_in_the_viewer_s_locale():
    """fmtnum() in template_filters.py groups with a comma whatever the locale,
    so a bare toLocaleString() next to it showed 1,234 in a table cell and 1.234
    in the map legend of the same page. utils.js fmtNum() is the one formatter."""
    bare = [
        f"{js.name}:{n}"
        for js in sorted((SRC / "static" / "js").glob("*.js"))
        for n, line in enumerate(js.read_text().splitlines(), 1)
        if "toLocaleString()" in line
    ]
    assert bare == [], f"bare toLocaleString() follows the viewer's locale: {bare}"
