"""Contrast promises the token file makes, checked against the values in it.

tokens.css states ratios in its comments; a comment cannot notice when a value
beside it is edited. These are the ones a control or a label depends on, per
theme, computed with the WCAG relative-luminance formula.
"""

import re
from pathlib import Path

import pytest

TOKENS = Path(__file__).resolve().parent.parent / "src/static/css/tokens.css"


def _block(selector: str) -> dict[str, str]:
    text = TOKENS.read_text()
    body = re.search(re.escape(selector) + r"\s*\{(.*?)\n\}", text, re.S).group(1)
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", body))


def _theme(name: str) -> dict[str, str]:
    dark = _block(":root")
    return dark if name == "dark" else {**dark, **_block('[data-theme="light"]')}


def _luminance(hex_colour: str) -> float:
    channels = [int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _ratio(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("ground", ["bg", "bg-card"])
def test_control_border_reaches_three_to_one(theme, ground):
    """WCAG 1.4.11: the edge of an input or a tab strip must be seen to be used.
    --border itself is 1.32:1 in dark mode, which is why --border-control exists."""
    t = _theme(theme)
    assert _ratio(t["border-control"], t[ground]) >= 3.0


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("token", ["text", "text-muted"])
def test_label_ink_reaches_four_and_a_half_to_one(theme, token):
    """Badges carry --text since their own hue failed; this keeps that ink honest."""
    t = _theme(theme)
    assert _ratio(t[token], t["bg-card"]) >= 4.5


# ── Token discipline ────────────────────────────────────────────────────────
# The review found twelve literal font sizes, eighteen literal radii, ten
# z-index values in four files and three tokens nothing read. Each drifted in
# one edit at a time, which is the only way it can be caught.

CSS_DIR = TOKENS.parent
SRC = TOKENS.parents[2]
BREAKPOINTS = {640, 900, 1100}


def _strip_comments(css: str) -> str:
    # Newlines survive, so a reported line number is the file's own.
    return re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), css, flags=re.S)


def _stylesheets() -> dict[str, str]:
    return {
        p.name: _strip_comments(p.read_text())
        for p in sorted(CSS_DIR.glob("*.css"))
        if p.name != "tokens.css"
    }


def _declarations(prop: str):
    for name, css in _stylesheets().items():
        for m in re.finditer(rf"(?<![\w-]){prop}\s*:\s*([^;}}]+)", css):
            line = css.count("\n", 0, m.start()) + 1
            yield f"{name}:{line}", m.group(1).strip()


def test_no_colour_literal_outside_the_token_file():
    found = [
        f"{name}: {hit}"
        for name, css in _stylesheets().items()
        for hit in re.findall(r"#[0-9a-fA-F]{3,8}\b", css)
    ]
    assert not found, found


def test_font_sizes_come_from_the_scale():
    """em stays allowed: inline code tracks the text around it, not a step."""
    bad = [
        f"{where} {value}"
        for where, value in _declarations("font-size")
        if not re.fullmatch(r"var\(--[\w-]+\)|inherit|[\d.]+em", value)
    ]
    assert not bad, bad


def test_radii_come_from_the_scale():
    bad = [
        f"{where} {value}"
        for where, value in _declarations("border-radius")
        if not all(re.fullmatch(r"var\(--[\w-]+\)|0", part) for part in value.split())
    ]
    assert not bad, bad


def test_paddings_in_pixels_come_from_the_scale():
    """rem paddings predate the scale and still scale with the root size; a px
    padding never did, and every one found sat a pixel or two off a step."""
    bad = [
        f"{where} {value}"
        for where, value in _declarations("padding")
        if re.search(r"(?<![\w-])\d+(\.\d+)?px", value)
    ]
    assert not bad, bad


def test_stacking_comes_from_the_scale():
    bad = [
        f"{where} {value}"
        for where, value in _declarations("z-index")
        if not re.fullmatch(r"var\(--z-[\w-]+\)", value)
    ]
    assert not bad, bad


def test_durations_come_from_the_scale():
    bad = [
        f"{where} {value}"
        for prop in ("transition", "animation")
        for where, value in _declarations(prop)
        if re.search(r"(?<![\w-])[\d.]+m?s\b", value)
    ]
    assert not bad, bad


def test_only_the_documented_breakpoints():
    widths = {
        f"{name}: {w}px"
        for name, css in _stylesheets().items()
        for w in re.findall(r"@media[^{]*?width:\s*(\d+)px", css)
        if int(w) not in BREAKPOINTS
    }
    assert not widths, widths


def test_every_token_has_a_reader():
    """A token nobody reads reads as intent. JS asks for one by bare name
    (cssVar('heat')), Python and templates by --name."""
    tokens_css = _strip_comments(TOKENS.read_text())
    defined = set(re.findall(r"--([\w-]+)\s*:", tokens_css))
    corpus = "\n".join(
        [re.sub(r"--[\w-]+\s*:", "", tokens_css), *_stylesheets().values()]
        + [p.read_text() for p in (SRC / "static/js").glob("*.js")]
        + [p.read_text() for p in (SRC / "templates").rglob("*.html")]
        + [p.read_text() for p in SRC.glob("*.py")]
    )
    unread = sorted(
        t for t in defined if not re.search(rf"(?:--|['\"]){re.escape(t)}(?![\w-])", corpus)
    )
    assert not unread, unread
