"""The needles, as a file rather than as code.

What this has to get right is not the loading — it is the two ways a data file
makes a classifier worse. It can fail silently, leaving a dashboard where every
address is unknown and nothing looks broken. And it can change a verdict without
invalidating the verdicts already stored, so the database holds two vintages of
judgement with no way to tell them apart.

Both are covered here, and neither is covered by the loading working.
"""

from __future__ import annotations

import pytest

from src.classifier import pack

# A crawler added the complete way: its user-agent and the networks it runs from.
_HOUSEBOT = '[ai_uas]\nentries = ["housebot"]\n[crawler_origins]\nhousebot = ["housecloud"]\n'


def _write(tmp_path, body, name="extra.toml"):
    path = tmp_path / name
    path.write_text(f"schema = {pack.SCHEMA}\n{body}")
    return path


# ── What ships ───────────────────────────────────────────────────────────────


def test_the_shipped_pack_loads_and_is_complete():
    loaded, fingerprint = pack.load()
    assert set(loaded) == {"schema", *pack.LIST_TABLES, *pack.MAP_TABLES}
    assert len(fingerprint) == 8


def test_the_shipped_pack_is_what_the_classifier_reads():
    """The names in patterns.py did not move, only where their values come from."""
    from src.classifier import patterns

    loaded, _ = pack.load()
    assert patterns._SCANNER_PATH_PATTERNS == tuple(loaded["scanner_paths"]["entries"])
    assert patterns._AI_UAS == tuple(loaded["ai_uas"]["entries"])
    assert patterns._CRAWLER_ORIGINS["gptbot"] == tuple(loaded["crawler_origins"]["gptbot"])


def test_every_needle_reaches_a_rule():
    """A table nothing reads would look applied and never be.

    LIST_TABLES and MAP_TABLES are the contract between the file and the code;
    if the file grows a table the loader does not know, it is refused, and this
    is the other direction — the loader must not know a table the file lacks.
    """
    loaded, _ = pack.load()
    for name in (*pack.LIST_TABLES, *pack.MAP_TABLES):
        assert name in loaded, name


# ── The fingerprint ──────────────────────────────────────────────────────────


def test_the_fingerprint_is_stable():
    assert pack.load()[1] == pack.load()[1]


def test_a_changed_needle_changes_the_fingerprint(tmp_path):
    """This is what makes the pack safe to edit: the stored labels go stale."""
    before = pack.load()[1]
    after = pack.load(_write(tmp_path, '[seo_uas]\nentries = ["newseobot"]\n'))[1]
    assert before != after


def test_comments_and_formatting_do_not_change_it(tmp_path):
    """Otherwise reflowing a comment would reclassify a million visits."""
    plain = _write(tmp_path, '[seo_uas]\nentries = ["newbot"]\n', "a.toml")
    noisy = _write(
        tmp_path,
        '# a note\n[seo_uas]\n# another note\nentries = [\n  "newbot",\n]\n',
        "b.toml",
    )
    assert pack.load(plain)[1] == pack.load(noisy)[1]


def test_the_classifier_version_carries_both_halves():
    from src.classifier import patterns

    assert patterns.CLASSIFIER_VERSION == f"{patterns._RULES_VERSION}+{patterns.PACK_DIGEST}"


# ── The overlay ──────────────────────────────────────────────────────────────


def test_an_operator_pack_adds_to_a_table(tmp_path):
    shipped, _ = pack.load()
    merged, _ = pack.load(_write(tmp_path, _HOUSEBOT))
    assert merged["ai_uas"]["entries"] == shipped["ai_uas"]["entries"] + ["housebot"]


def test_shipped_needles_stay_first(tmp_path):
    """_hit() returns the first needle found, and that string is what an evidence
    line shows. An addition must not change how an existing match is described."""
    merged, _ = pack.load(_write(tmp_path, '[ai_uas]\nentries = ["gptbot"]\n'))
    assert merged["ai_uas"]["entries"].index("gptbot") == 0


def test_a_repeated_needle_is_not_added_twice(tmp_path):
    shipped, _ = pack.load()
    merged, _ = pack.load(_write(tmp_path, '[ai_uas]\nentries = ["gptbot"]\n'))
    assert merged["ai_uas"]["entries"] == shipped["ai_uas"]["entries"]


def test_an_overlay_touches_only_what_it_declares(tmp_path):
    shipped, _ = pack.load()
    merged, _ = pack.load(_write(tmp_path, _HOUSEBOT))
    assert merged["search_uas"] == shipped["search_uas"]


def test_an_overlay_cannot_remove_a_needle(tmp_path):
    """Additive by design. Removing one describes a rule change, and a rule
    change belongs in a rule rather than in a file that subtracts silently."""
    shipped, _ = pack.load()
    merged, _ = pack.load(_write(tmp_path, "[ai_uas]\nentries = []\n"))
    assert merged["ai_uas"]["entries"] == shipped["ai_uas"]["entries"]


def test_an_overlay_extends_a_crawler_origin(tmp_path):
    merged, _ = pack.load(_write(tmp_path, '[crawler_origins]\ngptbot = ["housecloud"]\n'))
    assert merged["crawler_origins"]["gptbot"] == ["openai", "microsoft", "housecloud"]


# ── When it is broken ────────────────────────────────────────────────────────


def test_a_missing_file_says_so(tmp_path):
    with pytest.raises(pack.PackError, match="no such file"):
        pack.load(tmp_path / "gone.toml")


def test_broken_toml_says_so(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("this is not [ toml")
    with pytest.raises(pack.PackError, match="not valid TOML"):
        pack.load(path)


def test_a_pack_with_no_schema_is_refused(tmp_path):
    path = tmp_path / "noschema.toml"
    path.write_text('[ai_uas]\nentries = ["x"]\n')
    with pytest.raises(pack.PackError, match="no `schema` key"):
        pack.load(path)


def test_a_pack_from_a_later_shape_is_refused(tmp_path):
    path = tmp_path / "future.toml"
    path.write_text(f"schema = {pack.SCHEMA + 1}\n")
    with pytest.raises(pack.PackError, match="this build reads schema"):
        pack.load(path)


def test_an_unknown_table_is_refused_and_named(tmp_path):
    """Silently ignoring it is worse than an error: it would look applied."""
    with pytest.raises(pack.PackError, match=r"unknown table \[ai_us\]"):
        pack.load(_write(tmp_path, '[ai_us]\nentries = ["typo"]\n'))


def test_a_table_without_entries_is_refused(tmp_path):
    with pytest.raises(pack.PackError, match=r"\[ai_uas\] must be a table"):
        pack.load(_write(tmp_path, '[ai_uas]\nnedles = ["typo"]\n'))


@pytest.mark.parametrize("value", ["1", '""', '"   "', "[]"])
def test_an_entry_that_is_not_a_needle_is_refused(tmp_path, value):
    with pytest.raises(pack.PackError, match="non-empty strings"):
        pack.load(_write(tmp_path, f"[ai_uas]\nentries = [{value}]\n"))


def test_a_crawler_origin_that_is_not_a_list_is_refused(tmp_path):
    with pytest.raises(pack.PackError, match="list of non-empty strings"):
        pack.load(_write(tmp_path, '[crawler_origins]\ngptbot = "openai"\n'))


def test_a_crawler_without_origins_is_refused_and_named(tmp_path):
    """The pack invites adding a new crawler as an edit rather than a code change.
    Added to [ai_uas] and not to [crawler_origins], the real crawler — on cloud
    hosting, publishing no PTR — was filed as an impersonator of itself, with no
    error anywhere. That is the mistake v6 was built to stop making."""
    with pytest.raises(pack.PackError, match=r"housebot.*\[crawler_origins\]"):
        pack.load(_write(tmp_path, '[ai_uas]\nentries = ["housebot"]\n'))


def test_a_crawler_declared_with_no_networks_is_allowed(tmp_path):
    """An empty list is a decision — verify by reverse DNS alone — and says so;
    a missing key is an omission."""
    merged, _ = pack.load(
        _write(tmp_path, '[search_uas]\nentries = ["ptrbot"]\n[crawler_origins]\nptrbot = []\n')
    )
    assert merged["crawler_origins"]["ptrbot"] == []


def test_the_shipped_pack_must_carry_every_table():
    """An overlay may be partial; the shipped one may not."""
    with pytest.raises(pack.PackError, match=r"missing table \["):
        pack._check(pack.SHIPPED_PACK, {"schema": pack.SCHEMA}, complete=True)


# ── The preflight ────────────────────────────────────────────────────────────


def test_preflight_reports_a_broken_pack_rather_than_the_service_finding_out(
    tmp_path, monkeypatch
):
    """The alternative is a crash at startup in a container whose logs somebody
    has to go and fetch."""
    from src import config, preflight

    bad = tmp_path / "bad.toml"
    bad.write_text("schema = 99\n")
    monkeypatch.setattr(config.settings, "patterns_path", str(bad))
    check = next(c for c in preflight.run_checks() if c.name == "pattern pack")
    assert check.status == preflight.FAIL
    assert "schema" in check.detail and str(bad) in check.detail


def test_preflight_names_the_fingerprint_when_the_pack_is_sound(monkeypatch):
    from src import config, preflight
    from src.classifier import patterns

    monkeypatch.setattr(config.settings, "patterns_path", "")
    check = next(c for c in preflight.run_checks() if c.name == "pattern pack")
    assert check.status == preflight.OK
    assert patterns.PACK_DIGEST in check.detail
