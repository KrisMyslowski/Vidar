"""The explanation that turns a finding into something to do.

A path on its own is a fright. These tests are about the two ways that goes
wrong: an explanation that never appears, and one that appears where it does not
belong. The second is worse — a page that tells somebody their blog is a leaked
backup is a page nobody reads twice — so most of what follows asserts `None`.
"""

from __future__ import annotations

import pytest

from src.families import FAMILIES, explain_paths, family_for, unexplained_paths

# One representative path per family, in registry order. A family with no case
# here is a family nothing proves matches anything.
REPRESENTATIVES = {
    "os-metadata": "/.DS_Store",
    "vcs-directory": "/.git/config",
    "env-file": "/.env.production",
    "backup-file": "/config.php.bak",
    "config-file": "/docker-compose.yml",
    "credentials": "/.ssh/id_rsa",
    "tooling-leftover": "/.idea/workspace.xml",
    "log-file": "/error.log",
    "diagnostic-page": "/phpinfo.php",
}


@pytest.mark.parametrize("key,path", sorted(REPRESENTATIVES.items()))
def test_every_family_matches_something(key, path):
    family = family_for(path)
    assert family is not None, path
    assert family.key == key


def test_the_representatives_cover_the_registry():
    """Adding a family without a case here would pass the parametrised test."""
    assert {family.key for _, family in FAMILIES} == set(REPRESENTATIVES)


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/index.html",
        "/about/",
        "/robots.txt",
        "/assets/pages/cv.html",
        "/.well-known/security.txt",
    ],
)
def test_an_ordinary_path_has_no_family(path):
    """None is the normal answer, and the page renders nothing rather than filler."""
    assert family_for(path) is None


@pytest.mark.parametrize(
    "path",
    [
        # Each of these matched an earlier draft of the patterns. The words are
        # the trap: a page *about* backups is not a backup, and `log` is a
        # substring of half the English language.
        "/backup-policy.html",
        "/mybackup.html",
        "/login",
        "/blog/",
        "/blog/post.html",
        "/catalog/",
        "/dialogue.html",
        "/keyboard.png",
        "/testimonials.html",
        "/oldschool.html",
        "/en/config.html",
        "/info.html",
    ],
)
def test_a_word_that_merely_contains_a_pattern_is_not_a_finding(path):
    assert family_for(path) is None


@pytest.mark.parametrize(
    "path",
    ["/backups", "/backups/", "/backup/db.sql", "/dumps/", "/db.bak", "/config.php~"],
)
def test_the_narrower_pattern_still_catches_the_real_thing(path):
    """Tightening a pattern is only right if it still matches what it is for."""
    assert family_for(path) is not None


def test_matching_ignores_case():
    """nginx logs the path as requested, and a scanner may ask for /.ds_store."""
    assert family_for("/.DS_STORE") is not None
    assert family_for("/.ds_store") is not None


def test_explanations_group_by_family_in_first_appearance_order():
    """Three findings under /.git/ are one thing to fix and one thing to read."""
    grouped = explain_paths(
        ["/.DS_Store", "/.git/config", "/.git/HEAD", "/robots.txt"], "example.com"
    )
    assert [(family.key, paths) for family, paths in grouped] == [
        ("os-metadata", ["/.DS_Store"]),
        ("vcs-directory", ["/.git/config", "/.git/HEAD"]),
    ]


def test_the_check_is_a_command_and_not_a_template():
    """The reader is invited to paste it, so it must not still say {host}."""
    ((family, _),) = explain_paths(["/.DS_Store"], "example.com")
    assert family.check == "curl -sI https://example.com/.DS_Store"


def test_every_check_survives_being_addressed():
    """A stray brace in one family's check would raise only when it is found."""
    paths = [REPRESENTATIVES[family.key] for _, family in FAMILIES]
    grouped = explain_paths(paths, "example.com")
    assert len(grouped) == len(FAMILIES)
    for family, _ in grouped:
        assert "{" not in family.check and "}" not in family.check
        assert "example.com" in family.check


def test_every_family_answers_all_four_questions():
    """A family with a blank field renders an empty row and explains nothing."""
    for _, family in FAMILIES:
        assert all(
            getattr(family, field) for field in ("key", "title", "what", "why", "check", "fix")
        ), family.key


def test_family_keys_are_unique():
    keys = [family.key for _, family in FAMILIES]
    assert len(keys) == len(set(keys))


def test_a_path_with_no_family_still_gets_a_command():
    """Going and looking needs no knowledge of the file, so it never depends on one.

    Most findings will never match a family — the registry describes the
    accidents that recur, not every file anybody might leave in a web root.
    """
    assert unexplained_paths(["/.DS_Store", "/whatever-i-left-here.md"], "example.com") == [
        ("/whatever-i-left-here.md", "curl -sI https://example.com/whatever-i-left-here.md")
    ]


def test_the_generic_check_only_asks_for_headers():
    """A described family may pipe the body; the catch-all must not.

    -sI on an unknown path cannot dump a database export into the terminal of
    somebody who clicked a suggestion they did not read.
    """
    ((_, check),) = unexplained_paths(["/dump-of-something.xyz"], "example.com")
    assert check.startswith("curl -sI ")


def test_every_path_is_either_explained_or_given_a_command():
    """No finding falls between the two blocks and comes out with nothing."""
    paths = ["/.DS_Store", "/.git/config", "/notes.html", "/a", "/error.log"]
    explained = {p for _, covered in explain_paths(paths, "h") for p in covered}
    listed = {p for p, _ in unexplained_paths(paths, "h")}
    assert explained | listed == set(paths)
    assert explained & listed == set()
