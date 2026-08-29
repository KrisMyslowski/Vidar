"""The documentation pages — docs/*.md rendered into the dashboard.

The seven documents under docs/ were readable on GitHub and nowhere else, which
is the wrong place: Deployment and Data Reference are wanted while operating the
service, through the tunnel, not while browsing a repository.

They ship in the image. deploy/Dockerfile copies docs/ next to src/, and
.dockerignore keeps only docs/img/ out — no .md references an image, and the
screenshots are for the README.

Nothing here touches the database.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from markdown_it import MarkdownIt

from ._app import templates

router = APIRouter()

# /app/docs in the container, <repo>/docs in a checkout — this file sits at
# src/routes/docs.py under both, so the same three parents reach it.
DOCS_DIR = Path(__file__).resolve().parent.parent.parent / "docs"

ORDER_FILE = ".order"

# ── Rendering ────────────────────────────────────────────────────────────────
# html=False is the point of this renderer and has to be asked for: the
# commonmark preset ships html=True, because the spec requires raw HTML to pass
# through. This page is served under a CSP that forbids inline script, so a tag
# arriving from a document would either be inert or break the page. Escaped, the
# question does not arise. Every <script>/<host> placeholder in the docs today
# sits inside a code fence and would be escaped either way; this keeps that true
# for whatever gets written later. tests/test_docs.py pins it.
_md = MarkdownIt("commonmark", {"html": False}).enable("table")


def _link_open(self, tokens, idx, options, env):
    """Point cross-document links at the route instead of the file.

    The docs link to each other as `[…](data-reference.md)`, which resolves on
    GitHub and 404s here. Rewritten to /docs/<slug>, keeping any #anchor.
    External links are left exactly as they are.
    """
    token = tokens[idx]
    href = token.attrGet("href") or ""
    match = re.fullmatch(r"([A-Za-z0-9._-]+)\.md(#.*)?", href)
    if match:
        token.attrSet("href", f"/docs/{match.group(1)}{match.group(2) or ''}")
    return self.renderToken(tokens, idx, options, env)


_md.add_render_rule("link_open", _link_open)


def _slug(text: str) -> str:
    """GitHub's heading slug, so one anchor works in both places.

    The documents are read on GitHub as well as here, and a link that resolves
    in one and dangles in the other is worse than no link. GitHub lowercases,
    drops everything that is not a word character, space or hyphen, and joins
    the rest with hyphens; backticks go with the punctuation, so
    "7. Config settings (`src/config.py`)" becomes "7-config-settings-srcconfigpy".

    tests/test_docs.py asserts the slugs stay unique per document — a collision
    would silently send two references to the same place.
    """
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"[^\w\s-]", "", text.lower(), flags=re.UNICODE)
    return re.sub(r"\s+", "-", text.strip())


def _heading_open(self, tokens, idx, options, env):
    """Give every heading an id, which markdown-it does not do on its own.

    Without this a `#section` link renders as a live link that goes nowhere —
    it resolves on GitHub, which generates its own anchors, and dies here.
    """
    tokens[idx].attrSet("id", _slug(tokens[idx + 1].content))
    return self.renderToken(tokens, idx, options, env)


_md.add_render_rule("heading_open", _heading_open)


# ── The document list ────────────────────────────────────────────────────────


def _title(path: Path) -> str:
    """The document's first `# ` heading, or its filename if it has none."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem.replace("-", " ").capitalize()


def _ordered_names(available: set[str]) -> list[str]:
    """Filenames in .order first, then whatever it did not mention.

    Unlisted documents are appended rather than dropped: a doc that vanishes
    from the dashboard because someone forgot to edit .order is a bug, not a
    configuration choice.
    """
    listed: list[str] = []
    order_path = DOCS_DIR / ORDER_FILE
    if order_path.is_file():
        for line in order_path.read_text(encoding="utf-8").splitlines():
            name = line.strip()
            if name and not name.startswith("#") and name in available:
                if name not in listed:
                    listed.append(name)
    return listed + sorted(available - set(listed))


@lru_cache(maxsize=1)
def _documents() -> tuple[tuple[str, str], ...]:
    """(slug, title) for every document, in display order.

    Cached: the files are baked into the image and cannot change under a running
    container. Call _documents.cache_clear() in a test that writes new ones.
    """
    if not DOCS_DIR.is_dir():
        return ()
    available = {p.name for p in DOCS_DIR.glob("*.md") if p.is_file()}
    return tuple(
        (name[: -len(".md")], _title(DOCS_DIR / name)) for name in _ordered_names(available)
    )


def _nav(active: str) -> list[dict]:
    """Sub-nav entries for subnav_base.html, with `active` marked."""
    return [
        {"label": title, "href": f"/docs/{slug}", "active": slug == active}
        for slug, title in _documents()
    ]


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/docs")
async def docs_index():
    """Docs has no page of its own — the first document is the landing page."""
    documents = _documents()
    if not documents:
        raise HTTPException(status_code=404, detail="No documentation is installed")
    return RedirectResponse(url=f"/docs/{documents[0][0]}", status_code=301)


@router.get("/docs/{slug}")
async def docs_page(request: Request, slug: str):
    """One rendered document.

    The slug becomes a filename, so it is checked against the documents actually
    found on disk before a path is built from it — a membership test rather than
    a sanitiser, because a whitelist cannot be talked out of its contents by an
    encoding trick. validators.valid_choice() is the wrong tool here: it answers
    with a default, and there is no sensible default document for a bad slug.
    """
    titles = dict(_documents())
    if slug not in titles:
        raise HTTPException(status_code=404, detail="No such document")

    path = DOCS_DIR / f"{slug}.md"
    title = titles[slug]
    return templates.TemplateResponse(
        request,
        "docs.html",
        {
            "nav": _nav(slug),
            "nav_title": "Documentation",
            "doc_title": title,
            "body": _md.render(path.read_text(encoding="utf-8")),
        },
    )
