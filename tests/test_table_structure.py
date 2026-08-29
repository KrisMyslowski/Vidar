"""Header row and body rows describe the same columns, with typed widths.

Tables are `table-layout: fixed` and take every column's width from the header
row, so the `<th>` is both the label and the width. `columns.js` hides a column
by its `data-col` attribute on the `<th>` and every `<td>`. Two things have to
hold for that to work, and both have been broken in production:

* header and body must carry the identical `data-col` sequence — with the key
  on the body cells but not the header, hiding City left the header a column
  longer than its rows and every value sat under the wrong heading;
* in a table with a column picker every column needs a width class, because a
  fixed-layout table hands the entire leftover width to an unsized column. When
  ISP was the unsized one and got hidden, there was nothing left to absorb the
  slack.

Neither is visible in a render test, so it is checked here. What the browser
then actually lays out is measured in test_layout_browser.py.
"""

import re
from html.parser import HTMLParser
from unittest.mock import patch

import pytest

from tests.conftest import dashboard_css
from tests.test_dashboard_routes import client, dashboard_db  # noqa: F401

PAGES = [
    "/",
    "/visitors",
    "/visitors?group=asn",
    "/visitors?group=country",
    "/visitors?group=client",
    "/visitors?group=path",
    "/analysis",
    "/exposure",
    "/visitors/203.0.113.10",
]

# Every width class the stylesheet defines for a header cell, read out of the
# stylesheet rather than copied from it. The copy was a list to keep in step by
# hand, and a new class was one edit away from failing this test in a way that
# looks like a markup bug.
#
# `width: auto` does not count, and that exclusion is the point of the test
# below rather than a detail: c-actions is a real class that deliberately
# declares no width, so a table with a column picker using it would sail through
# a check that only asked "does this cell carry a c-* class" — while being
# exactly the unsized column the check exists to forbid.
WIDTH_CLASSES = {
    name
    for name, width in re.findall(r"th\.(c-[\w-]+)\s*\{\s*width:\s*([\w.%-]+)", dashboard_css())
    if width != "auto"
}
assert WIDTH_CLASSES, "no th.c-* width rules found — has the selector changed?"


class _Tables(HTMLParser):
    """Collects each table's header and body rows as (data-col, class) cells."""

    def __init__(self):
        super().__init__()
        self.tables = []
        self._t = None
        self._row = None
        self._in_head = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "table":
            self._t = {"head": [], "body": []}
        elif self._t is None:
            return
        elif tag == "thead":
            self._in_head = True
        elif tag == "tr":
            self._row = []
        elif tag in ("th", "td") and self._row is not None:
            # Empty states span the whole table and describe no column.
            key = "\x00colspan" if a.get("colspan") else a.get("data-col")
            self._row.append((key, set((a.get("class") or "").split())))

    def handle_endtag(self, tag):
        if tag == "thead":
            self._in_head = False
        elif tag == "tr" and self._t is not None and self._row is not None:
            if not any(k == "\x00colspan" for k, _ in self._row):
                self._t["head" if self._in_head else "body"].append(self._row)
            self._row = None
        elif tag == "table" and self._t is not None:
            self.tables.append(self._t)
            self._t = None


def _tables(html: str):
    p = _Tables()
    p.feed(html)
    return [t for t in p.tables if t["head"]]


def _render(client, dashboard_db, path):  # noqa: F811
    with patch("src.config.settings.db_path", dashboard_db):
        return client.get(path).text


@pytest.mark.parametrize("path", PAGES)
def test_header_and_body_describe_the_same_columns(client, dashboard_db, path):  # noqa: F811
    html = _render(client, dashboard_db, path)
    tables = _tables(html)
    assert tables, f"{path} renders no table with a header"
    for i, t in enumerate(tables):
        keys = [k for k, _ in t["head"][0]]
        for row in t["head"] + t["body"]:
            got = [k for k, _ in row]
            assert got == keys, f"{path} table #{i}: {got} vs header {keys}"


@pytest.mark.parametrize("path", PAGES)
def test_no_colgroup_survives(client, dashboard_db, path):  # noqa: F811
    """The width lives on the <th>. A <col> beside it is a second, silent
    source that the header and body cannot be checked against."""
    assert "<colgroup" not in _render(client, dashboard_db, path)


@pytest.mark.parametrize("path", PAGES)
def test_hideable_tables_type_every_column(client, dashboard_db, path):  # noqa: F811
    """No unsized column where a column can be hidden.

    A fixed-layout table gives an unsized column the whole leftover width. That
    is fine until it is the column that disappears — then the table shrinks to
    the sum of the rest and leaves the container half empty.
    """
    html = _render(client, dashboard_db, path)
    for i, t in enumerate(_tables(html)):
        head = t["head"][0]
        if not any(key for key, _ in head):  # nothing hideable in this table
            continue
        untyped = [n for n, (_, classes) in enumerate(head) if not (classes & WIDTH_CLASSES)]
        assert not untyped, f"{path} table #{i}: header cells without a width class: {untyped}"


@pytest.mark.parametrize("path", PAGES)
def test_every_offered_column_is_addressable(client, dashboard_db, path):  # noqa: F811
    """A column the picker offers must carry `data-col` on header and cells."""
    html = _render(client, dashboard_db, path)
    offered = set(re.findall(r'data-col-toggle="(\w+)"', html))
    for t in _tables(html):
        present = {k for k, _ in t["head"][0] if k}
        for row in t["body"]:
            present &= {k for k, _ in row if k}
        offered -= present
    assert not offered, f"{path}: picker offers columns nothing can hide: {sorted(offered)}"
