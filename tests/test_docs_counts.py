"""The countable facts in the docs, held to the code that owns them.

Every number the documentation states about the code had drifted by the time it
was checked: the endpoint count in api.md, the routes its table promised to list
"in one place", the signal count beside them, the test totals in testing.md.
Prose cannot notice that it has gone stale; these tests notice for it.

test_docs_reference.py does the same for data-reference.md's two tables.
"""

from __future__ import annotations

import re
from pathlib import Path

from src.main import app
from src.taxonomy import VALID_SIGNALS

DOCS = Path(__file__).resolve().parent.parent / "docs"
_WORDS = {3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}

# Served, and deliberately not part of the surface a reader is told about.
_UNLISTED = {"/openapi.json", "/favicon.ico"}


def _paths():
    return {r.path for r in app.routes if getattr(r, "methods", None)} - _UNLISTED


def test_every_route_is_named_in_the_api_reference():
    """api.md §7 says the URL surface is documented in one place. /report,
    /incidents/case, /exposure/finding and /visitors/{ip}/session were missing
    from it."""
    text = (DOCS / "api.md").read_text(encoding="utf-8")
    missing = sorted(
        p
        for p in _paths()
        if f"`GET {p}`" not in text and f"`POST {p}`" not in text and p not in text
    )
    assert missing == [], f"api.md does not mention: {missing}"


def test_the_api_endpoint_count_is_the_number_of_api_routes():
    text = (DOCS / "api.md").read_text(encoding="utf-8")
    n = len({p for p in _paths() if p.startswith("/api/")})
    assert f"{_WORDS[n].capitalize()} endpoints live under `/api`" in text


def test_the_signal_count_is_the_number_of_signals():
    text = (DOCS / "api.md").read_text(encoding="utf-8")
    stated = re.search(r"`signal` accepts the (\w+) signal keys", text)
    assert stated and stated.group(1) == _WORDS[len(VALID_SIGNALS)]


def test_every_test_file_is_named_in_testing_md():
    """testing.md §4 says what each suite protects, and named 37 of 56 — the
    behaviour axis and the document tests among the missing."""
    from fnmatch import fnmatch

    text = (DOCS / "testing.md").read_text(encoding="utf-8")
    named = set(re.findall(r"`(test_[\w*]+\.py)`", text))
    files = sorted(p.name for p in (DOCS.parent / "tests").glob("test_*.py"))
    missing = [f for f in files if not any(fnmatch(f, n) for n in named)]
    assert missing == [], f"testing.md does not name: {missing}"


def test_every_stated_class_count_is_the_taxonomy():
    """ "18 classes in 5 groups" is written in five places, one of them a changelog
    entry that is history rather than a claim. It is right today; the signal count
    written beside it in api.md was not, and nothing would have said so."""
    from src.taxonomy import VALID_CLASSES, VISITOR_CATEGORIES

    classes, groups = len(VALID_CLASSES), len(VISITOR_CATEGORIES)
    root = DOCS.parent
    wrong = [
        f"{path.relative_to(root)}: {m.group(0)}"
        for path in [root / "README.md", *sorted(DOCS.glob("*.md"))]
        if path.name != "changelog.md"
        for m in re.finditer(
            r"(\d+) (?:identity )?classes (?:in|across) (\d+) groups", path.read_text()
        )
        if (int(m.group(1)), int(m.group(2))) != (classes, groups)
    ]
    assert wrong == [], wrong


def test_every_stated_column_count_is_the_schema(tmp_db):
    """data-reference.md heads its two table sections with a column count, and
    architecture.md repeats both. A migration adds a column and the four numbers
    go stale in silence."""
    from src.db import get_conn

    with get_conn(tmp_db) as conn:
        actual = {
            t: len(conn.execute(f"PRAGMA table_info({t})").fetchall())
            for t in ("visits", "ip_intel")
        }
    wrong = []
    for name in ("data-reference.md", "architecture.md"):
        text = (DOCS / name).read_text(encoding="utf-8")
        for table, stated in re.findall(r"`(visits|ip_intel)`[^\n]*?\b(\d+) columns", text):
            if int(stated) != actual[table]:
                wrong.append(f"{name}: {table} says {stated}, the schema has {actual[table]}")
    assert wrong == [], wrong
