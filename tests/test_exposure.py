"""What the site gave away — the other reading of the same data.

Every other query in the codebase describes visitors. These describe what
visitors got, which is the operator's own attack surface as reported daily by
the people probing it.

The tests are mostly about *not* reporting things. A security surface that cries
wolf is read once and then ignored, so each case below is a false positive that
an earlier draft produced against a live log.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

from src.db import get_conn
from src.queries import insert_visit, set_visitor_class, upsert_ip_intel
from src.queries.analysis import get_exposure_detail, get_exposures, get_probe_echo

HUMAN = "humans/browser-direct"
PROBER = "bots/vulnerability-probers"


def _paths(html):
    """The finding paths, in the order the Findings table renders them.

    Keyed on data-col, which only the sortable Findings table carries — the
    Served block below it also labels a Path column, and matching the label
    alone read both tables as one list.
    """
    return re.findall(r'data-col="path"[^>]*>\s*<code>([^<]+)</code>', html)


def _hit(conn, ip, path, status=200, cls=PROBER, bytes_sent=100, ts=None, enriched=True):
    if enriched:
        upsert_ip_intel(conn, {"ip": ip})
        set_visitor_class(conn, ip, cls)
    insert_visit(
        conn,
        ip=ip,
        timestamp=ts or "2026-08-20T10:00:00+00:00",
        method="GET",
        path=path,
        status=status,
        bytes_sent=bytes_sent,
    )


def test_a_file_only_probers_ever_got_is_an_exposure(tmp_db):
    """The whole feature in one case: .DS_Store on the reference deployment.

    Served with 200, 6 148 bytes, fetched by 31 addresses and by no human and no
    search crawler in three months. It leaks the filenames of the web root, and
    nobody had noticed although the data had been in the database for months.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store", bytes_sent=6148)
        _hit(conn, "203.0.113.2", "/.DS_Store", bytes_sent=6148)
    with get_conn(tmp_db) as conn:
        found = get_exposures(conn)
    assert [f["path"] for f in found] == ["/.DS_Store"]
    assert found[0]["ips"] == 2


def test_a_path_benign_visitors_also_fetch_is_not_an_exposure(tmp_db):
    """A prober fetching the homepage proves nothing about the homepage.

    On the reference log 2 699 prober requests got `/` with a 200 — as did 102
    humans and 121 search crawlers. Reporting that as a finding would bury the
    real one under the whole site.

    Two benign addresses, because that is where the line is: see
    test_one_benign_address_does_not_hide_a_finding for the other side of it.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.3", "/", cls=HUMAN)
        _hit(conn, "203.0.113.31", "/", cls="bots/search-crawlers")
        _hit(conn, "203.0.113.4", "/")
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn) == []


def test_a_redirect_is_not_a_hit(tmp_db):
    """Success is 2xx, never "not an error".

    158 531 prober requests on the reference log are the HTTP→HTTPS redirect. An
    earlier draft read `status < 400` and would have reported every probe as a
    successful one.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.5", "/.env", status=301)
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn) == []


def test_an_acme_challenge_is_not_an_exposure(tmp_db):
    """It has the exact shape of a finding and is the opposite of one.

    Fetched by a certificate authority and by nobody else, ever — no human, no
    crawler. The convention list that keeps `robots.txt` out of the 404 ratio
    keeps this out of here.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.6", "/.well-known/acme-challenge/tokenvalue")
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn) == []


def test_encoded_spellings_fold_into_one_finding(tmp_db):
    """`/.DS_Store`, `/%2eDS_Store` and `//%2eDS_Store` are one file.

    Against the live log this turned eight rows into one. Seven rows of noise
    around a single real finding is how a security surface stops being read.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.7", "/.DS_Store")
        _hit(conn, "203.0.113.8", "/%2eDS_Store")
        _hit(conn, "203.0.113.9", "//%2eDS_Store")
    with get_conn(tmp_db) as conn:
        found = get_exposures(conn)
    assert len(found) == 1
    assert found[0]["path"] == "/.DS_Store"
    assert found[0]["ips"] == 3
    assert len(found[0]["spellings"]) == 3


def test_an_encoded_convention_path_is_still_a_convention_path(tmp_db):
    """`/robots%2etxt` never appears in the log spelled normally, so the SQL
    cannot see that it is robots.txt. Decoding is what catches it."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.10", "/robots%2etxt")
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn) == []


def test_the_default_sort_reproduces_the_order_the_page_had(tmp_db, client):
    """A commit that adds sorting must not change what the page shows first.

    _fold_encodings has always returned `(-ips, -hits)`; the default sort key
    has to be that same order, or the page silently reorders on the release that
    makes it sortable.
    """
    with get_conn(tmp_db) as conn:
        for ip in range(1, 4):
            _hit(conn, f"203.0.113.{ip}", "/.git/config")
        for ip in range(4, 6):
            _hit(conn, f"203.0.113.{ip}", "/.env")
        _hit(conn, "203.0.113.9", "/dump.sql")

    default = _paths(client.get("/exposure?range=all").text)
    explicit = _paths(client.get("/exposure?range=all&sort=addresses&order=DESC").text)
    assert default == ["/.git/config", "/.env", "/dump.sql"]
    assert explicit == default


def test_every_column_sorts_on_its_value_not_its_rendering(tmp_db, client):
    """The rendered text cannot carry the order: sort.js parses every ISO date
    to the number 2026 and reads 980 B as larger than 6 KB. The route sorts the
    underlying values before anything is formatted."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/b.sql", bytes_sent=980, ts="2026-08-20T10:00:00+00:00")
        _hit(conn, "203.0.113.2", "/a.bak", bytes_sent=6144, ts="2026-08-10T10:00:00+00:00")
        _hit(conn, "203.0.113.3", "/a.bak", ts="2026-08-11T10:00:00+00:00")

    by_size = _paths(client.get("/exposure?range=all&sort=size&order=DESC").text)
    by_first = _paths(client.get("/exposure?range=all&sort=first&order=ASC").text)
    by_path = _paths(client.get("/exposure?range=all&sort=path&order=ASC").text)
    # 6 144 B beats 980 B, which the rendered "6.0 KB" vs "980.0 B" would not.
    assert by_size == ["/a.bak", "/b.sql"]
    assert by_first == ["/a.bak", "/b.sql"]
    assert by_path == ["/a.bak", "/b.sql"]


def test_the_custom_range_form_keeps_the_sort(tmp_db, client):
    """It is a GET to the bare path: whatever it does not carry is gone.

    The macro states the rule for the pages that already had state — the custom
    range must not silently drop the selection — and these two joined that club
    the moment their columns became sortable.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.env")
    text = client.get("/exposure?range=all&sort=size&order=ASC&vsort=requests&vorder=DESC").text
    form = re.search(r"<form[^>]*range-custom-form.*?</form>", text, re.S)
    assert form, "no custom range form"
    hidden = dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', form.group(0)))
    # Both blocks: Served sorts on its own parameters and is just as easy to
    # drop here as the findings above it.
    assert hidden == {
        "sort": "size",
        "order": "ASC",
        "vsort": "requests",
        "vorder": "DESC",
    }, hidden


def test_an_unknown_sort_key_falls_back_rather_than_erroring(tmp_db, client):
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.env")
    assert client.get("/exposure?range=all&sort=nonsense&order=sideways").status_code == 200


def test_the_benign_test_is_not_scoped_to_the_selected_range(tmp_db):
    """A path does not stop being part of the site on a quiet day.

    The counts are windowed — that is what the range tabs are for — but the rule
    the page states is "nothing benign *ever* asked for it". Windowed too, a
    narrow range reported the site's own homepage as an exposure, because the
    two humans who account for it visited last week.
    """
    with get_conn(tmp_db) as conn:
        for i, ip in enumerate(("203.0.113.30", "203.0.113.31")):
            _hit(conn, ip, "/", cls=HUMAN, ts=f"2026-08-0{i + 1}T10:00:00+00:00")
        _hit(conn, "203.0.113.32", "/", ts="2026-08-20T10:00:00+00:00")
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn, "2026-08-19", "2026-08-21") == []


def test_a_path_the_sites_own_javascript_fetches_is_not_a_finding(tmp_db):
    """No crawler follows a link that is not in the HTML, so a fragment loaded
    by fetch() has exactly the shape of a finding and is a content page."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.20", "/fragments/about.html")
    # A neutral prefix, not the one this deployment happens to use: the mirror
    # gate rejects any .env value that reaches a published file, and it caught
    # exactly this fixture.
    with patch("src.config.settings.js_only_path_prefixes", ["/fragments/"]):
        with get_conn(tmp_db) as conn:
            assert get_exposures(conn) == []
    # And with the prefixes unset — the default — nothing is lost that was not
    # there to lose: the same path is reported exactly as before.
    with patch("src.config.settings.js_only_path_prefixes", []):
        with get_conn(tmp_db) as conn:
            assert [f["path"] for f in get_exposures(conn)] == ["/fragments/about.html"]


def test_a_normalisation_probe_returns_the_homepage_not_a_finding(tmp_db):
    """`//`, `/./` and `/%2f` are the same resource spelled to look different."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.11", "/", cls=HUMAN)
        _hit(conn, "203.0.113.41", "/", cls="bots/search-crawlers")
        _hit(conn, "203.0.113.12", "//")
        _hit(conn, "203.0.113.13", "/./")
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn) == []


def test_a_query_string_probe_is_counted_but_never_listed(tmp_db):
    """A static server ignores the query, so the homepage answers 200.

    `/?voellig=erfunden` returns the same 6 987 bytes as `/` — checked against
    the live site. 125 distinct URLs on the reference log are that one fact, and
    listing them as 125 exposures would be a false alarm 125 times over.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.14", "/?phpinfo=-1")
        _hit(conn, "203.0.113.15", "/?rest_route=/wp/v2/users/")
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn) == []
        echo = get_probe_echo(conn)
    assert echo == {"urls": 2, "ips": 2}


def test_one_benign_address_does_not_hide_a_finding(tmp_db):
    """A leak must not disappear because one visitor was judged differently.

    The address that fetched `//%2eDS_Store` on the reference log was
    `automated/headless-browser` under classifier v5 and `humans/browser-referred`
    under v6. With a veto of one, reclassifying it took the whole finding away —
    31 addresses of evidence overruled by a single verdict that had just changed.

    Two independent benign addresses is a pattern; one is a coin flip.
    """
    with get_conn(tmp_db) as conn:
        for n in range(20, 25):
            _hit(conn, f"203.0.113.{n}", "/.DS_Store")
        _hit(conn, "203.0.113.26", "/.DS_Store", cls=HUMAN)
    with get_conn(tmp_db) as conn:
        found = get_exposures(conn)
    assert [f["path"] for f in found] == ["/.DS_Store"]
    assert found[0]["ips"] == 6
    assert found[0]["benign_ips"] == 1


def test_two_benign_addresses_mean_the_path_belongs_to_the_site(tmp_db):
    """Where the line is, stated as a test rather than left in a constant."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.30", "/some/page.html")
        _hit(conn, "203.0.113.31", "/some/page.html", cls=HUMAN)
        _hit(conn, "203.0.113.32", "/some/page.html", cls="bots/search-crawlers")
    with get_conn(tmp_db) as conn:
        assert get_exposures(conn) == []


def test_the_window_narrows_the_findings_rather_than_emptying_them(tmp_db):
    """Every visit to the page passes a window — the default tab is 90 days.

    The ten tests above this one all called get_exposures() unbounded, so all
    ten passed while the page showed nothing at all: the benign class list and
    the window were bound in the wrong order, the window received a class name,
    and `v.timestamp >= \'bots/ai-crawlers\'` matched no row ever. A query
    tested only unbounded is a query tested in the one shape nobody uses.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/.DS_Store")
    with get_conn(tmp_db) as conn:
        assert [f["path"] for f in get_exposures(conn, "2026-08-01", "2026-08-31")] == [
            "/.DS_Store"
        ]
        assert get_exposures(conn, "2026-01-01", "2026-01-31") == []


def test_the_window_applies_to_the_probe_echo_too(tmp_db):
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/?rest_route=/wp/v2/users/")
    with get_conn(tmp_db) as conn:
        assert get_probe_echo(conn, "2026-08-01", "2026-08-31")["urls"] == 1
        assert get_probe_echo(conn, "2026-01-01", "2026-01-31")["urls"] == 0


# ── The page ─────────────────────────────────────────────────────────────────
#
# The query decides what is a finding; these decide whether the reader can do
# anything with it. A path and a byte count are a fright, not information.


@pytest.fixture
def client(tmp_db):
    from fastapi.testclient import TestClient

    from src.config import settings
    from src.main import app

    with patch.object(settings, "db_path", tmp_db):
        yield TestClient(app)


def test_served_shows_the_whole_surface_the_findings_are_a_subset_of(client, tmp_db):
    """The findings table says "1 path". It does not say one of how many.

    Same result set, split on the benign threshold, so the two blocks cannot
    disagree about a number they share.
    """
    with get_conn(tmp_db) as conn:
        # A page two crawlers fetch, and a file only probers ever got.
        for ip, cls in (("203.0.113.1", HUMAN), ("203.0.113.2", HUMAN)):
            _hit(conn, ip, "/about.html", cls=cls)
        _hit(conn, "203.0.113.3", "/.DS_Store")

    text = client.get("/exposure?range=all").text
    served = re.findall(r'data-label="Path" class="col-path"><code>([^<]+)</code>', text)
    assert served == ["/about.html", "/.DS_Store"]
    # The finding is one of them, and the table above lists only it.
    assert _paths(text) == ["/.DS_Store"]
    assert ">Finding</span>" in text and ">Site</span>" in text


def test_served_keeps_the_paths_the_findings_logic_sets_aside(client, tmp_db):
    """robots.txt is not a finding — nobody but a convention fetches it — but it
    is something this server hands out, and a list of what it hands out that
    omits it answers a stranger question than either."""
    with get_conn(tmp_db) as conn:
        for n in range(4):
            _hit(conn, f"203.0.113.{n + 1}", "/robots.txt", cls=HUMAN)
        _hit(conn, "203.0.113.9", "/.DS_Store")

    text = client.get("/exposure?range=all").text
    served = re.findall(r'data-label="Path" class="col-path"><code>([^<]+)</code>', text)
    assert "/robots.txt" in served
    # And it is not counted as a finding, however few benign addresses it has.
    assert _paths(text) == ["/.DS_Store"]


def _panel(client, path, **params):
    """The slide-over for one finding, where its explanation now lives."""
    from urllib.parse import urlencode

    query = urlencode({"path": path, **params})
    return client.get(f"/exposure/finding?{query}").text


def test_a_finding_carries_its_explanation(client, tmp_db):
    """All four answers, one click from the row rather than on the page.

    They used to sit under the table, one panel per family. Per-path advice
    belongs beside the path it is about, and the same registry answers here.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store", bytes_sent=6148)
        _hit(conn, "203.0.113.2", "/.DS_Store", bytes_sent=6148)
    text = _panel(client, "/.DS_Store")
    assert "Operating-system metadata" not in text  # the title is the row's job
    for question in (
        "What it is",
        "Why it was asked for",
        "Check it yourself",
        "How to stop serving it",
    ):
        assert question in text, question
    # And the page itself no longer repeats any of it.
    assert "What it is" not in client.get("/exposure").text


def test_the_check_names_the_site_it_is_addressed_to(client, tmp_db):
    """A command the reader is invited to paste must not still say {host}."""
    from src.config import settings

    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/.DS_Store")
    with patch.object(settings, "site_base_url", "https://example.com"):
        text = _panel(client, "/.DS_Store")
    assert "curl -sI https://example.com/.DS_Store" in text
    assert "{host}" not in text and "{path}" not in text


def test_a_blank_site_url_leaves_an_obvious_placeholder(client, tmp_db):
    """SITE_BASE_URL ships unset, and a wrong hostname is worse than none.

    The three site settings are blank by design so a verbatim .env.example
    cannot pass the deploy gate — which means this panel has to render before
    anybody fills them in, and the command it prints must not look real.
    """
    from src.config import settings

    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/.DS_Store")
    with patch.object(settings, "site_base_url", ""):
        text = _panel(client, "/.DS_Store")
    assert "your-site.example" in text


def test_a_finding_with_no_family_renders_no_explanation(client, tmp_db):
    """None is a normal answer, and the panel says nothing rather than filler.

    Inventing a family broad enough to cover everything would produce a
    paragraph that applies to any file and helps with none of them.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/leftover-draft.html")
        _hit(conn, "203.0.113.2", "/leftover-draft.html")
    text = _panel(client, "/leftover-draft.html")
    assert "/leftover-draft.html" in text
    assert "What it is" not in text
    # But it does get the one piece of advice that needs no knowledge of it.
    assert "curl -sI https://" in text


def test_a_path_that_is_not_a_finding_says_so_rather_than_erroring(client, tmp_db):
    """The panel renders whatever comes back — a status page inside a slide-over
    reads as a broken panel, not as an answer."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
    resp = client.get("/exposure/finding?path=/not-a-finding")
    assert resp.status_code == 200
    assert "not a finding in the selected range" in resp.text


def test_the_panel_answers_for_every_spelling_of_the_path(client, tmp_db):
    """A finding is the fold of its percent-encoded spellings. A panel keyed on
    the canonical path alone would describe a subset of the row that opened it."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/%2eDS_Store")
        _hit(conn, "203.0.113.3", "/%2eDS_Store")
    text = _panel(client, "/.DS_Store")
    assert "3 from 3" in text, text[:0] or "the panel counted only one spelling"
    assert "/%2eDS_Store" in text


def test_the_panel_says_whether_it_is_still_served(client, tmp_db):
    """The one line that decides whether there is anything to do today, and the
    only one asked without the window: a file is on disk or it is not."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/.DS_Store")
    assert "still served" in _panel(client, "/.DS_Store")

    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.4", "/.DS_Store", status=404, ts="2026-08-25T10:00:00+00:00")
    assert "no longer served" in _panel(client, "/.DS_Store")


# ── The fold and the counts it carries ───────────────────────────────────────


def test_one_address_under_two_spellings_is_one_address(tmp_db):
    """The fold adds a distinct count to a distinct count, which is not one.

    `/.DS_Store` and `/%2eDS_Store` are the same file reached two ways. An
    address that tried both is one address that got it, and the column says
    "distinct addresses". Summing the per-spelling counts reports two.
    """
    with get_conn(tmp_db) as conn:
        for path in ("/.DS_Store", "/%2eDS_Store"):
            _hit(conn, "198.51.100.7", path)
        _hit(conn, "198.51.100.8", "/.DS_Store")
    with get_conn(tmp_db) as conn:
        (finding,) = get_exposures(conn)

    assert finding["path"] == "/.DS_Store"
    assert finding["spellings"] == ["/%2eDS_Store", "/.DS_Store"]
    assert finding["ips"] == 2, "two addresses, one of which wrote the path two ways"
    assert finding["hits"] == 3, "requests do add up — three were made"


def test_the_site_threshold_is_not_reached_by_counting_one_visitor_twice(tmp_db):
    """The sum decided Site from Finding, not only what the column displayed.

    Two benign addresses make a path part of the site. One benign address that
    wrote the path two ways is one benign address, and the path is still a
    finding.
    """
    with get_conn(tmp_db) as conn:
        for path in ("/.DS_Store", "/%2eDS_Store"):
            _hit(conn, "198.51.100.7", path, cls=HUMAN)
        _hit(conn, "198.51.100.9", "/.DS_Store")
    with get_conn(tmp_db) as conn:
        rows = get_exposures(conn, findings_only=False)

    (row,) = [r for r in rows if r["path"] == "/.DS_Store"]
    assert row["benign_ips"] == 1, "one human, however it spelled the path"
    assert row["is_finding"], "one benign address is below the threshold of two"


def _served(html):
    """The Served block's paths, in render order.

    Keyed on the Kind cell, which only Served has — the findings table above it
    also labels a Path column, and matching the label alone reads both as one.
    """
    block = html.split("Served")[-1]
    return re.findall(
        r'<td data-label="Path" class="col-path"><code>([^<]+)</code>.*?data-label="Kind"',
        block,
        re.S,
    )


def test_served_sorts_on_its_own_columns(tmp_db, client):
    """It is the block that answers "one of how many", and it was the one table
    on this page a reader could not re-order."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/b.sql", bytes_sent=980)
        for n in (1, 2, 3):
            _hit(conn, f"203.0.113.{n}", "/a.bak", bytes_sent=6144)
    base = "/exposure?range=all"
    assert _served(client.get(f"{base}&vsort=path&vorder=ASC").text) == ["/a.bak", "/b.sql"]
    assert _served(client.get(f"{base}&vsort=path&vorder=DESC").text) == ["/b.sql", "/a.bak"]
    # 6 144 B beats 980 B, which the rendered "6.0 KB" vs "980.0 B" would not.
    assert _served(client.get(f"{base}&vsort=size&vorder=DESC").text) == ["/a.bak", "/b.sql"]
    assert _served(client.get(f"{base}&vsort=requests&vorder=DESC").text) == ["/a.bak", "/b.sql"]


def test_the_two_blocks_sort_independently(tmp_db, client):
    """They share a URL. Ordering Served must not reorder the findings above it,
    which is why it carries its own parameters rather than the same `sort`."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/b.sql", bytes_sent=980)
        _hit(conn, "203.0.113.2", "/a.bak", bytes_sent=6144)
    html = client.get("/exposure?range=all&sort=path&order=DESC&vsort=path&vorder=ASC").text
    assert _paths(html) == ["/b.sql", "/a.bak"], "findings descending"
    assert _served(html) == ["/a.bak", "/b.sql"], "served ascending, at the same time"


def test_served_opens_in_the_order_it_always_did(tmp_db, client):
    """Making a table sortable must not change what it shows first: Site before
    Finding, then the most benign, then the most requested."""
    with get_conn(tmp_db) as conn:
        for n in (1, 2):
            _hit(conn, f"203.0.113.{n}", "/index.html", cls=HUMAN)
        _hit(conn, "203.0.113.9", "/.env")
    html = client.get("/exposure?range=all").text
    assert _served(html) == ["/index.html", "/.env"], "the site page leads, the finding follows"


def test_every_column_header_carries_the_whole_selection(tmp_db, client):
    """A header link is a fresh URL: whatever it does not carry is gone.

    Two tables share this page, so each header has to carry the window *and*
    the other block's order. Missed once already — the two tails were set inside
    the Findings `{% call %}`, which is its own scope, so Served rendered them
    empty and every header there dropped the range.
    """
    from html import unescape
    from urllib.parse import parse_qs, urlparse

    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.env")
    html = client.get("/exposure?range=all&sort=size&order=ASC&vsort=requests&vorder=DESC").text
    hrefs = [unescape(h) for h in re.findall(r"<th[^>]*><a[^>]*href=\"([^\"]+)\"", html)]
    findings = [h for h in hrefs if "vsort=" not in h.split("&")[0]]
    assert len(hrefs) == 14, "seven columns in each block"

    for href in hrefs:
        q = parse_qs(urlparse(href).query)
        assert q.get("range") == ["all"], f"lost the window: {href}"
        # The block that owns the link sets its own key; the other one rides
        # along unchanged.
        if href.startswith("?vsort="):
            assert q["sort"] == ["size"] and q["order"] == ["ASC"], href
        else:
            assert q["vsort"] == ["requests"] and q["vorder"] == ["DESC"], href
    assert findings, "and the findings block has headers at all"


def test_the_recounted_addresses_obey_the_window(tmp_db):
    """The recount binds two sets of parameters positionally, which is the shape
    _date_conditions warns about: get_exposures once bound its window onto the
    class list and every range came back empty while the tests passed.

    The benign count is deliberately not windowed — "ever" means ever — so this
    pins both halves at once.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store", ts="2026-08-01T00:00:00+00:00")
        _hit(conn, "203.0.113.2", "/%2eDS_Store", ts="2026-08-01T00:00:00+00:00")
        # Inside the window, and the only benign fetch anywhere.
        _hit(conn, "203.0.113.3", "/%2eDS_Store", cls=HUMAN, ts="2026-08-20T00:00:00+00:00")
    with get_conn(tmp_db) as conn:
        windowed = {r["path"]: r for r in get_exposures(conn, "2026-08-15", "2026-08-25", False)}
        every = {r["path"]: r for r in get_exposures(conn, findings_only=False)}

    assert every["/.DS_Store"]["ips"] == 3, "three addresses over all time"
    assert windowed["/.DS_Store"]["ips"] == 1, "one of them inside the window"
    assert windowed["/.DS_Store"]["benign_ips"] == 1, "the benign test ignores the window"


def test_an_address_not_yet_enriched_still_counts(tmp_db):
    """Intel arrives later than the visit — the enrichment worker is rate-limited.

    Every figure here used to inner-join ip_intel although only the benign test
    reads it, so a fresh burst of probers was invisible until enrichment caught
    up, and the row disagreed with its own side panel, which left-joins. An
    address with no verdict yet is not a benign one; it counts.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/.DS_Store", enriched=False)
        _hit(conn, "203.0.113.2", "/%2eDS_Store", enriched=False)
        _hit(conn, "203.0.113.3", "/?phpinfo=-1", enriched=False)
    with get_conn(tmp_db) as conn:
        (finding,) = get_exposures(conn)
        detail = get_exposure_detail(conn, finding["spellings"])
        echo = get_probe_echo(conn)

    assert finding["ips"] == 2, "the unenriched address is one of the two"
    assert finding["hits"] == 3
    assert (detail["ips"], detail["hits"]) == (finding["ips"], finding["hits"])
    assert echo == {"urls": 1, "ips": 1}
