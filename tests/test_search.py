"""Search-term parsing — the whole point of the field registry.

The defect these lock down: every term used to be a substring against eleven
columns at once, so `de` matched 3,617 of 11,564 production IPs (1,627 of them
via `path`, because "index" contains the letters) while the 961 IPs actually in
Germany drowned in the noise.
"""

import pytest

from src.search import (
    BROAD,
    COUNTRY,
    EXACT,
    MAX_TERMS,
    NUMBER,
    PREFIX,
    STATUS,
    SUBSTRING,
    parse,
    strip_term,
)


def _one(q):
    terms, unknown = parse(q)
    assert len(terms) == 1, terms
    assert unknown == []
    return terms[0]


# ── Shapes recognised without a field name ────────────────────────────────────


@pytest.mark.parametrize("token", ["DE", "de", "pl", "Us"])
def test_two_letters_mean_a_country(token):
    """The reported bug: DE is the country filter, not a substring hunt."""
    t = _one(token)
    assert t.field.name == "country"
    assert t.match == COUNTRY


@pytest.mark.parametrize("token", ["AS13335", "as9009"])
def test_as_number_means_an_asn(token):
    assert _one(token).field.name == "asn"


@pytest.mark.parametrize("token", ["/", "/.env", "/wp-admin/"])
def test_leading_slash_means_a_path(token):
    t = _one(token)
    assert t.field.name == "path"
    assert t.match == SUBSTRING


@pytest.mark.parametrize("token", ["404", "200", "503"])
def test_three_digit_code_means_a_status(token):
    t = _one(token)
    assert t.field.name == "status"
    assert t.match == STATUS


@pytest.mark.parametrize("token", ["192.0.2.96", "192.0.2.", "2001:db8", "2001:db8::1"])
def test_ip_shaped_tokens_mean_an_ip_prefix(token):
    t = _one(token)
    assert t.field.name == "ip"
    assert t.match == PREFIX


@pytest.mark.parametrize("token", ["hetzner", "22", "abc", "wget", "Chrome", "1.5"])
def test_everything_else_stays_broad(token):
    """A bare number or word must not be forced into a field — '22' is not an IP
    and not a status code, so it searches broadly."""
    t = _one(token)
    assert t.field is None
    assert t.match == BROAD


# ── Explicit field:value ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "token,field,match",
    [
        ("country:DE", "country", COUNTRY),
        ("cc:DE", "country", COUNTRY),
        ("city:Berlin", "city", SUBSTRING),
        ("ip:192.0.2.", "ip", PREFIX),
        ("path:de", "path", SUBSTRING),
        ("url:de", "path", SUBSTRING),
        ("ua:wget", "ua", SUBSTRING),
        ("agent:wget", "ua", SUBSTRING),
        ("device:Bot", "device", EXACT),
        ("class:threats", "class", "class"),
        ("signal:tor", "signal", "signal"),
        ("tag:scanner", "tag", EXACT),
        ("port:22", "port", NUMBER),
        ("serverport:80", "serverport", NUMBER),
        ("status:4xx", "status", STATUS),
        ("method:POST", "method", EXACT),
        ("http:2", "http", SUBSTRING),
        ("cve:CVE-2021", "vuln", SUBSTRING),
        ("host:googlebot", "rdns", SUBSTRING),
    ],
)
def test_field_prefixes_and_aliases(token, field, match):
    t = _one(token)
    assert t.field.name == field
    assert t.match == match


def test_field_name_is_case_insensitive():
    assert _one("Country:DE").field.name == "country"


def test_a_field_overrides_the_shape():
    """`path:de` must search paths again — the escape hatch from the inference."""
    t = _one("path:de")
    assert t.field.name == "path"
    assert t.value == "de"


def test_value_keeps_its_own_colons():
    """referer:https://x/y splits on the first colon only."""
    t = _one("referer:https://example.com/a")
    assert t.field.name == "referer"
    assert t.value == "https://example.com/a"


def test_url_without_a_field_is_not_read_as_one():
    terms, unknown = parse("https://example.com/a")
    assert unknown == []
    assert terms[0].field is None


def test_unknown_field_is_reported_not_swallowed():
    """Silently demoting foo:bar to a broad search would filter the page
    differently than the user believes."""
    terms, unknown = parse("foo:bar")
    assert unknown == ["foo"]
    assert terms == []


# ── Multiple terms, quoting, limits ───────────────────────────────────────────


def test_terms_are_separate():
    terms, _ = parse("country:DE ua:wget hetzner")
    assert [t.field.name if t.field else None for t in terms] == ["country", "ua", None]


def test_quoted_run_stays_one_term_and_stays_broad():
    """Quoting is how a phrase with spaces survives; it also opts out of the
    shape inference, so "DE" in quotes is a literal search."""
    t = _one('"Hetzner Online GmbH"')
    assert t.value == "Hetzner Online GmbH"
    assert t.field is None


def test_quoted_value_after_a_field_keeps_its_spaces():
    """Splitting on whitespace first would tear ua:"Mozilla 5.0" in half."""
    t = _one('ua:"Mozilla 5.0"')
    assert t.field.name == "ua"
    assert t.value == "Mozilla 5.0"


def test_term_count_is_capped():
    terms, _ = parse(" ".join(f"w{i}" for i in range(MAX_TERMS + 5)))
    assert len(terms) == MAX_TERMS


@pytest.mark.parametrize("q", ["", None, "   "])
def test_empty_input(q):
    assert parse(q) == ([], [])


# ── Removing a single term (the per-term pill) ────────────────────────────────


def test_strip_term_removes_only_that_term():
    assert strip_term("country:DE ua:wget hetzner", "ua:wget") == "country:DE hetzner"


def test_strip_term_requotes_phrases():
    assert strip_term('"a b" country:DE', "country:DE") == '"a b"'


def test_strip_term_of_the_only_term_empties_it():
    assert strip_term("country:DE", "country:DE") == ""


def test_client_is_an_alias_for_browser():
    """The grouping this filters is called Clients — the tab, the heading and
    the table all say so, and only the search said browser. The field keeps its
    name so every saved URL still works; `client:` is the second way in."""
    terms, unknown = parse("client:Chrome")
    assert not unknown
    assert terms[0].field.name == "browser"
    assert terms[0].value == "Chrome"

    assert parse("browser:Chrome")[0][0].field.name == "browser"
