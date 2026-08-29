"""The documentation pages: the list, the order, the rendering, and the slug.

The slug is the part that has to hold. It names a file, and this repo has
already paid once for treating a URL segment as a filename with a single check
between it and open() — see the archive routes. Here the whole defence is that
the slug is never joined onto a path until it has been found in the set of
documents actually on disk, so most of what follows is about that.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.routes import docs as docs_module

REAL_DOCS = Path(docs_module.DOCS_DIR)


@pytest.fixture
def client(tmp_db):
    """tmp_db because base.html's nav badge reads the database on every page,
    docs pages included — the documents themselves need none."""
    return TestClient(app)


@pytest.fixture
def docs_dir(tmp_path, monkeypatch):
    """A documents directory of our own, so the tests do not read the real one."""
    monkeypatch.setattr(docs_module, "DOCS_DIR", tmp_path)
    docs_module._documents.cache_clear()
    yield tmp_path
    docs_module._documents.cache_clear()


def _write(directory, name, body):
    (directory / name).write_text(body, encoding="utf-8")


class TestTheDocumentList:
    def test_every_document_in_the_repo_is_offered(self, client):
        """The real docs/, not a fixture: a document added to the tree should
        appear without anyone remembering to register it here."""
        from pathlib import Path

        expected = {p.stem for p in Path(docs_module.DOCS_DIR).glob("*.md")}
        assert {slug for slug, _ in docs_module._documents()} == expected

    def test_the_order_file_sets_the_order(self, docs_dir):
        for name in ("charlie.md", "alpha.md", "bravo.md"):
            _write(docs_dir, name, f"# {name}\n")
        _write(docs_dir, ".order", "bravo.md\nalpha.md\n")
        assert [s for s, _ in docs_module._documents()] == ["bravo", "alpha", "charlie"]

    def test_a_document_missing_from_order_is_appended_not_hidden(self, docs_dir):
        """The failure this guards against is silent: a doc that stops being
        listed because .order was not updated looks like a doc that was never
        written."""
        _write(docs_dir, "listed.md", "# Listed\n")
        _write(docs_dir, "forgotten.md", "# Forgotten\n")
        _write(docs_dir, ".order", "listed.md\n")
        assert [s for s, _ in docs_module._documents()] == ["listed", "forgotten"]

    def test_order_ignores_comments_blanks_and_unknown_names(self, docs_dir):
        _write(docs_dir, "real.md", "# Real\n")
        _write(docs_dir, ".order", "# a comment\n\ndeleted.md\nreal.md\n")
        assert [s for s, _ in docs_module._documents()] == ["real"]

    def test_the_nav_label_is_the_documents_own_heading(self, docs_dir):
        _write(docs_dir, "data-reference.md", "# Data Reference\n\nBody.\n")
        assert docs_module._documents() == (("data-reference", "Data Reference"),)

    def test_a_document_without_a_heading_falls_back_to_its_filename(self, docs_dir):
        _write(docs_dir, "no-heading.md", "Just prose.\n")
        assert docs_module._documents() == (("no-heading", "No heading"),)


class TestTheSlugNamesAFileAndIsTreatedAsSuch:
    @pytest.mark.parametrize(
        "slug",
        [
            "nonexistent",
            "../../etc/passwd",
            "..%2f..%2fetc%2fpasswd",
            "../pyproject",
            "usage.md",
        ],
    )
    def test_anything_not_on_the_list_is_a_404(self, client, slug):
        assert client.get(f"/docs/{slug}", follow_redirects=False).status_code == 404

    def test_a_traversal_never_reads_outside_the_docs_directory(self, client, docs_dir):
        """pyproject.toml sits one level above docs/ and is the nearest real
        file a traversal could reach."""
        _write(docs_dir, "usage.md", "# Usage\n")
        response = client.get("/docs/../pyproject")
        assert response.status_code == 404
        assert "build-system" not in response.text


class TestRendering:
    def test_tables_become_tables(self, client, docs_dir):
        """469 table rows across the docs, so the table rule is not optional."""
        _write(docs_dir, "t.md", "# T\n\n| A | B |\n|---|---|\n| 1 | 2 |\n")
        body = client.get("/docs/t").text
        assert "<table>" in body and "<th>A</th>" in body

    def test_raw_html_in_a_document_is_escaped(self, client, docs_dir):
        """html=False is why markdown-it was chosen. A document is trusted
        content, but it must not be able to put a tag into a page whose CSP
        forbids inline script — that would fail closed as a broken page at
        best, and this keeps the question from arising."""
        _write(docs_dir, "x.md", "# X\n\n<script>alert(1)</script>\n\n<b>bold</b>\n")
        body = client.get("/docs/x").text
        assert "<script>alert(1)</script>" not in body
        assert "&lt;script&gt;" in body
        assert "<b>bold</b>" not in body

    def test_a_cross_document_link_points_at_the_route(self, client, docs_dir):
        """`[…](api.md)` resolves on GitHub and would 404 here."""
        _write(
            docs_dir, "a.md", "# A\n\nSee [the API](api.md) and [data](data-reference.md#tags).\n"
        )
        _write(docs_dir, "api.md", "# API\n")
        body = client.get("/docs/a").text
        assert 'href="/docs/api"' in body
        assert 'href="/docs/data-reference#tags"' in body

    def test_an_external_link_is_left_alone(self, client, docs_dir):
        _write(docs_dir, "a.md", "# A\n\n[semver](https://semver.org)\n")
        assert 'href="https://semver.org"' in client.get("/docs/a").text

    def test_the_page_carries_the_nav_and_the_title(self, client, docs_dir):
        _write(docs_dir, "usage.md", "# Using the Dashboard\n")
        _write(docs_dir, "api.md", "# API Reference\n")
        body = client.get("/docs/usage").text
        assert "Documentation" in body
        assert 'href="/docs/api"' in body
        assert 'class="active"' in body


class TestCrossReferences:
    """Every `#anchor` in the docs has to land on a heading.

    The references are the reason the renderer gives headings an id at all:
    markdown-it emits none, so a link that GitHub resolves would be a live link
    to nowhere in the dashboard. That makes the anchors easy to break silently —
    renaming a heading changes its slug and nothing complains — so they are
    checked here rather than by anyone noticing.
    """

    @staticmethod
    def _headings(path):
        from src.routes.docs import _slug

        return {_slug(h) for h in re.findall(r"^#{1,6} (.+)$", path.read_text(), re.M)}

    @pytest.mark.parametrize("doc", sorted(REAL_DOCS.glob("*.md")), ids=lambda p: p.name)
    def test_every_anchor_resolves(self, doc):
        targets = {}
        for link in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            if link.startswith("#"):
                targets.setdefault(doc, set()).add(link[1:])
            elif ".md#" in link and not link.startswith("http"):
                name, _, frag = link.partition("#")
                targets.setdefault(REAL_DOCS / name, set()).add(frag)
        for path, anchors in targets.items():
            assert path.is_file(), f"{doc.name} links to a missing file: {path.name}"
            missing = anchors - self._headings(path)
            assert not missing, f"{doc.name} -> {path.name}: no heading for {sorted(missing)}"

    @pytest.mark.parametrize("doc", sorted(REAL_DOCS.glob("*.md")), ids=lambda p: p.name)
    def test_a_linked_heading_slugs_the_same_under_either_whitespace_rule(self, doc):
        """A hand-written anchor must not depend on how runs of space are collapsed.

        _slug joins on `\\s+`, so " — " between two words leaves one hyphen. A
        slugger that replaces each space separately leaves two, and GitHub renders
        these documents as well. test_every_anchor_resolves cannot see the
        difference because it calls _slug for both halves of its comparison.

        Only headings something links to are constrained: a reader reaches the rest
        through the table of contents each renderer builds for itself. The fix is to
        write the heading so the two rules agree — a colon or parentheses rather
        than a spaced dash.
        """
        from src.routes.docs import _slug

        per_space = lambda h: re.sub(  # noqa: E731
            r"\s", "-", re.sub(r"[^\w\s-]", "", re.sub(r"`([^`]*)`", r"\1", h).lower()).strip()
        )
        linked = set()
        for link in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            if link.startswith("#"):
                linked.add(link[1:])
            elif ".md#" in link and not link.startswith("http"):
                linked.add(link.partition("#")[2])
        for h in re.findall(r"^#{1,6} (.+)$", doc.read_text(), re.M):
            if _slug(h) in linked and _slug(h) != per_space(h):
                pytest.fail(f"{doc.name}: {h!r} is linked but slugs two ways")

    @pytest.mark.parametrize("doc", sorted(REAL_DOCS.glob("*.md")), ids=lambda p: p.name)
    def test_slugs_are_unique_within_a_document(self, doc):
        """Two headings sharing a slug send two references to the same place."""
        from src.routes.docs import _slug

        heads = re.findall(r"^#{1,6} (.+)$", doc.read_text(), re.M)
        slugs = [_slug(h) for h in heads]
        dupes = {s for s in slugs if slugs.count(s) > 1}
        assert not dupes, f"{doc.name}: duplicate slugs {sorted(dupes)}"

    @pytest.mark.parametrize("doc", sorted(REAL_DOCS.glob("*.md")), ids=lambda p: p.name)
    def test_a_reference_points_at_the_document_it_names(self, doc):
        """A link that resolves can still be wrong, and that is the worse fault.

        Converting "[data-reference.md](data-reference.md) §7." to a link, the
        trailing full stop broke the cross-document match; the intra-document
        rule then matched the bare §7 and produced a confident link to the
        current file's own section 7. It resolved, so the anchor check passed.
        """
        pattern = r"\[([a-z-]+\.md)\]\(\1\)\s*\[§[0-9][0-9.a]*\]\(([^)]+)\)"
        for named, href in re.findall(pattern, doc.read_text()):
            target = href.split("#")[0] or doc.name
            assert target == named, f"{doc.name}: text says {named}, link goes to {target}"

    @pytest.mark.parametrize("doc", sorted(REAL_DOCS.glob("*.md")), ids=lambda p: p.name)
    def test_no_section_reference_is_left_unlinked(self, doc):
        """A bare §4.2.8 is a reference the reader has to resolve by scrolling."""
        text = re.sub(r"\[[^\]]*\]\([^)]*\)", "", doc.read_text())
        assert "§" not in text, f"{doc.name}: unlinked section reference"


class TestTheEntryPoints:
    def test_a_trailing_slash_lands_on_the_index(self, client):
        """/docs/ is the index with a slash, not a document with an empty name."""
        assert client.get("/docs/").url.path == "/docs/usage"

    def test_the_openapi_ui_no_longer_owns_this_path(self, client):
        """FastAPI serves Swagger at /docs by default. It is off, and the proof
        is that /docs answers with our own page rather than its shell."""
        assert "swagger" not in client.get("/docs").text.lower()

    def test_docs_redirects_to_the_first_document(self, client):
        response = client.get("/docs", follow_redirects=False)
        assert response.status_code == 301
        assert response.headers["location"] == "/docs/usage"

    def test_the_book_is_in_the_sidebar_of_every_page(self, client):
        assert 'href="/docs"' in client.get("/docs/usage").text

    def test_the_book_is_marked_active_only_on_a_docs_page(self, client):
        assert "sidebar-docs active" in client.get("/docs/usage").text
        assert "sidebar-docs active" not in client.get("/settings/storage").text
