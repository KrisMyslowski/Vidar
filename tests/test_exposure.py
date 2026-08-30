"""What the site gave away — the other reading of the same data.

Every other query in the codebase describes visitors. These describe what
visitors got, which is the operator's own attack surface as reported daily by
the people probing it.

The tests are mostly about *not* reporting things. A security surface that cries
wolf is read once and then ignored, so each case below is a false positive that
an earlier draft produced against a live log.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.db import get_conn
from src.queries import insert_visit, set_visitor_class, upsert_ip_intel
from src.queries.analysis import get_exposures, get_probe_echo

HUMAN = "humans/browser-direct"
PROBER = "bots/vulnerability-probers"


def _hit(conn, ip, path, status=200, cls=PROBER, bytes_sent=100):
    upsert_ip_intel(conn, {"ip": ip})
    set_visitor_class(conn, ip, cls)
    insert_visit(
        conn,
        ip=ip,
        timestamp="2026-08-20T10:00:00+00:00",
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


def test_a_finding_carries_its_explanation(client, tmp_db):
    """All four answers on the page, not a link to somewhere that has them."""
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store", bytes_sent=6148)
        _hit(conn, "203.0.113.2", "/.DS_Store", bytes_sent=6148)
    text = client.get("/exposure").text
    assert "Operating-system metadata" in text
    for question in (
        "What it is",
        "Why it was asked for",
        "Check it yourself",
        "How to stop serving it",
    ):
        assert question in text


def test_the_check_names_the_site_it_is_addressed_to(client, tmp_db):
    """A command the reader is invited to paste must not still say {host}."""
    from src.config import settings

    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/.DS_Store")
    with patch.object(settings, "site_base_url", "https://example.com"):
        text = client.get("/exposure").text
    assert "curl -sI https://example.com/.DS_Store" in text
    assert "{host}" not in text and "{path}" not in text


def test_a_blank_site_url_leaves_an_obvious_placeholder(client, tmp_db):
    """SITE_BASE_URL ships unset, and a wrong hostname is worse than none.

    The three site settings are blank by design so a verbatim .env.example
    cannot pass the deploy gate — which means this page has to render before
    anybody fills them in, and the command it prints must not look real.
    """
    from src.config import settings

    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/.DS_Store")
        _hit(conn, "203.0.113.2", "/.DS_Store")
    with patch.object(settings, "site_base_url", ""):
        text = client.get("/exposure").text
    assert "your-site.example" in text


def test_a_finding_with_no_family_renders_no_explanation(client, tmp_db):
    """None is a normal answer, and the page says nothing rather than filler.

    Inventing a family broad enough to cover everything would produce a
    paragraph that applies to any file and helps with none of them.
    """
    with get_conn(tmp_db) as conn:
        _hit(conn, "203.0.113.1", "/leftover-draft.html")
        _hit(conn, "203.0.113.2", "/leftover-draft.html")
    text = client.get("/exposure").text
    assert "/leftover-draft.html" in text
    assert "What it is" not in text
    # But it does get the one piece of advice that needs no knowledge of it.
    assert "curl -sI https://" in text and "/leftover-draft.html" in text


def test_one_family_covering_two_paths_is_explained_once(client, tmp_db):
    """Two rows, one thing to fix — so one explanation, naming both paths."""
    with get_conn(tmp_db) as conn:
        for path in ("/.git/config", "/.git/HEAD"):
            _hit(conn, "203.0.113.1", path)
            _hit(conn, "203.0.113.2", path)
    text = client.get("/exposure").text
    # Both rows are marked, so the reader can see which explanation is theirs;
    # the explanation itself is written once.
    assert text.count("Version control directory") == 3  # two row markers + the heading
    assert text.count("What it is") == 1
    assert "/.git/config" in text and "/.git/HEAD" in text
