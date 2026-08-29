"""The Content-Security-Policy and the markup it has to permit.

A CSP fails in the browser, not on the server: a page whose script-src forbids
what it loads still renders, still returns 200, and every existing test stays
green while the map is dead. So what is checkable without a browser is checked
here — that the header is present and well formed, that the nonce in it is the
nonce in the markup and changes per response, and that no template reintroduces
an inline handler the policy would block.

What this cannot prove is that the allow-list is complete. That needs a browser
with the console open — see the note in docs/testing.md.
"""

import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.main import app

TEMPLATES = Path(__file__).resolve().parent.parent / "src/templates"


@pytest.fixture
def client(tmp_db):
    """FastAPI test client with patched DB path — same shape the route tests use."""
    from src.config import settings

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def _directives(header: str) -> dict[str, str]:
    return {
        part.split(" ", 1)[0]: part.split(" ", 1)[1] if " " in part else ""
        for part in (p.strip() for p in header.split(";"))
        if part
    }


class TestTheHeader:
    def test_every_response_carries_a_policy(self, client):
        assert "Content-Security-Policy" in client.get("/health").headers

    def test_scripts_are_restricted_to_self_a_nonce_and_the_leaflet_cdn(self, client):
        d = _directives(client.get("/").headers["Content-Security-Policy"])
        assert d["default-src"] == "'self'"
        assert re.fullmatch(r"'self' 'nonce-[\w-]{16,}' https://unpkg\.com", d["script-src"])

    def test_script_src_never_allows_inline(self, client):
        """The whole point. A nonce plus 'unsafe-inline' would also mean nothing:
        browsers ignore 'unsafe-inline' once a nonce is present."""
        d = _directives(client.get("/").headers["Content-Security-Policy"])
        assert "'unsafe-inline'" not in d["script-src"]
        assert "'unsafe-eval'" not in d["script-src"]

    def test_map_tiles_and_leaflet_stylesheets_are_allowed(self, client):
        d = _directives(client.get("/").headers["Content-Security-Policy"])
        assert "https://*.basemaps.cartocdn.com" in d["img-src"]
        assert "data:" in d["img-src"]
        # Loaded from unpkg as well as the scripts — a style-src of just 'self'
        # would strip the map's own CSS.
        assert "https://unpkg.com" in d["style-src"]


class TestTheNonce:
    def test_the_markup_carries_the_nonce_from_the_header(self, client):
        resp = client.get("/")
        nonce = _directives(resp.headers["Content-Security-Policy"])["script-src"]
        nonce = re.search(r"'nonce-([\w-]+)'", nonce).group(1)
        assert f'<script nonce="{nonce}">' in resp.text

    def test_a_second_request_gets_a_different_nonce(self, client):
        """A fixed nonce is the same as no nonce: anything injected once could
        carry it forever."""
        first, second = client.get("/"), client.get("/")
        assert (
            first.headers["Content-Security-Policy"] != second.headers["Content-Security-Policy"]
        )


class TestTheMarkupStaysCompatible:
    """A nonce covers <script> elements. It cannot cover an on* attribute, and
    there is no hash-free way to allow one — so a template that grows an inline
    handler silently loses that button under the policy."""

    @pytest.mark.parametrize("template", sorted(TEMPLATES.rglob("*.html")), ids=lambda p: p.name)
    def test_no_template_uses_an_inline_event_handler(self, template):
        found = re.findall(r"\son[a-z]+\s*=", template.read_text())
        assert not found, f"inline handler(s) {found} — move it to static/js/actions.js"

    def test_only_the_theme_bootstrap_is_inline_and_it_is_nonced(self):
        """Executable inline scripts, that is. `type="application/json"` blocks are
        data, not script, and CSP does not apply to them."""
        base = (TEMPLATES / "base.html").read_text()
        inline = re.findall(r"<script(?![^>]*\bsrc=)(?![^>]*application/json)[^>]*>", base)
        assert len(inline) == 1, f"expected one inline script, found {inline}"
        assert "nonce=" in inline[0]
