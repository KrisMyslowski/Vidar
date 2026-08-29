"""Settings had no test at all.

Two things worth pinning. Unknown keys in a .env are a hard error, which is why
`retention_days` still exists as a field even though nothing reads it: removing
it would stop every deployment whose .env still carries RETENTION_DAYS from
starting, production included. And the CSV validator on the provider lists —
the one path an operator actually uses to override them — was never exercised.
"""

import pytest
from pydantic import ValidationError

# From the package, not pydantic_settings.exceptions: that submodule path only
# exists from 2.9 on, and requirements/runtime.txt pins 2.8.*. The machine this
# was written on happened to have 2.11 installed.
from pydantic_settings import SettingsError

from src.config import Settings, settings


class TestADeprecatedKeyStillLoads:
    """`retention_days` purges nothing; the calendar window replaced it. The
    field stays so an existing .env is still a valid one."""

    def test_the_field_is_still_declared(self):
        assert "retention_days" in Settings.model_fields

    def test_an_env_that_still_sets_it_starts(self, monkeypatch):
        monkeypatch.setenv("RETENTION_DAYS", "120")
        assert Settings(_env_file=None).retention_days == 120

    def test_an_unknown_key_is_refused(self, monkeypatch):
        """Which is exactly why the field above cannot simply be deleted."""
        monkeypatch.setenv("VIDAR_NOT_A_SETTING", "1")
        Settings(_env_file=None)  # unprefixed env vars alone are fine

        with pytest.raises(ValidationError):
            Settings(_env_file=None, definitely_not_a_setting="x")

    def test_nothing_reads_it(self):
        """If this starts failing, the field is live again and the comment on it
        in config.py and .env.example needs to stop saying DEPRECATED.

        The status page's configuration list is the one allowed mention: it shows
        every field of Settings, this one included, and showing a value is not
        reading it. Any other appearance still fails.
        """
        from pathlib import Path

        src = Path(__file__).resolve().parent.parent / "src"
        users = [
            f"{p.relative_to(src)}:{n}"
            for p in src.rglob("*.py")
            for n, line in enumerate(p.read_text().splitlines(), 1)
            if "retention_days" in line and p.name != "config.py"
            # The read-only listing in _CONFIG_GROUPS, quoted as a bare name.
            and not (p.name == "settings.py" and '"retention_days"' in line)
        ]
        assert users == [], f"retention_days is read after all: {users}"


class TestTheProviderListsAcceptCsv:
    """The comma-separated form is how an operator overrides these from a .env,
    and the validator that supports it was never run."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("zen.spamhaus.org", ["zen.spamhaus.org"]),
            ("a.example,b.example", ["a.example", "b.example"]),
            (" a.example , b.example ", ["a.example", "b.example"]),
            ("a.example,,", ["a.example"]),
            ("", []),
        ],
        ids=["single", "two", "padded", "trailing-commas", "empty"],
    )
    def test_dnsbl_providers(self, monkeypatch, raw, expected):
        monkeypatch.setenv("DNSBL_PROVIDERS", raw)
        assert Settings(_env_file=None).dnsbl_providers == expected

    def test_json_is_not_accepted_for_these_two(self, monkeypatch):
        """A trap worth pinning. pydantic-settings parses a complex type from
        the environment as JSON, so the obvious guess is that a JSON list works
        — but the CSV validator runs on the raw string first and splits it on
        commas, leaving the brackets and quotes in the values. CSV is the only
        form these two accept. `static_extensions` has no such validator and is
        JSON-only, which is the opposite rule for a neighbouring setting."""
        monkeypatch.setenv("JS_ONLY_PATH_PREFIXES", '["/a/", "/b/"]')
        assert Settings(_env_file=None).js_only_path_prefixes == ['["/a/"', '"/b/"]']

    def test_static_extensions_is_json_not_csv(self, monkeypatch):
        monkeypatch.setenv("STATIC_EXTENSIONS", '[".css", ".js"]')
        assert Settings(_env_file=None).static_extensions == {".css", ".js"}

        monkeypatch.setenv("STATIC_EXTENSIONS", ".css,.js")
        with pytest.raises(SettingsError):
            Settings(_env_file=None)


class TestEverySettingIsDocumented:
    """.env.example is the canonical variable list. It listed 21 of 35, and the
    fourteen it left out included DB_CONNECTION_TIMEOUT, both export rate-limit
    knobs and every SERVER_* field — so an operator reading the file could not
    know they existed."""

    def _documented(self) -> set[str]:
        from pathlib import Path

        text = (Path(__file__).resolve().parent.parent / ".env.example").read_text()
        names = set()
        for line in text.splitlines():
            line = line.strip().lstrip("#").strip()
            if "=" in line and not line.startswith("─"):
                names.add(line.split("=", 1)[0].strip())
        return names

    def test_no_setting_is_missing(self):
        missing = sorted(
            name for name in Settings.model_fields if name.upper() not in self._documented()
        )
        assert missing == [], f".env.example does not mention: {', '.join(missing)}"

    def test_nothing_documented_has_been_removed(self):
        """The other direction: a variable in the file that no longer exists is
        worse than an undocumented one, because unknown keys are a hard error
        and an operator who copies the file gets a service that will not start."""
        known = {name.upper() for name in Settings.model_fields}
        stale = sorted(n for n in self._documented() if n not in known)
        assert stale == [], f".env.example names settings that do not exist: {stale}"


class TestTheExampleFileActuallyWorks:
    """Nothing ever loaded .env.example as a .env, and it did not survive it.

    STATIC_ASSET_PREFIXES aborted startup outright: the field lacked NoDecode,
    so pydantic-settings tried to JSON-decode "/assets/" before the CSV
    validator could see it — anyone who set that variable got a service that
    would not boot. And `SERVER_LAT=` with nothing after it, which is how a .env
    says "not applicable", failed float parsing.
    """

    def test_it_loads_as_a_real_env_file(self, tmp_path, monkeypatch):
        from pathlib import Path

        example = Path(__file__).resolve().parent.parent / ".env.example"
        env = tmp_path / ".env"
        env.write_text(example.read_text())
        # A .env must not be overridden by the ambient environment for this.
        for name in Settings.model_fields:
            monkeypatch.delenv(name.upper(), raising=False)

        loaded = Settings(_env_file=str(env))

        assert loaded.server_lat is None, "an empty value means unset, not zero"
        assert loaded.db_connection_timeout == 10
        assert loaded.export_rate_limit == 5
        # The three site settings ship blank, so copying the example verbatim
        # cannot satisfy the deploy gate with a wrong value.
        assert loaded.site_base_url == ""
        assert loaded.static_asset_prefixes == []
        assert loaded.js_only_path_prefixes == []

    def test_a_bare_path_prefix_still_parses(self, monkeypatch):
        """The regression the example file used to carry, now stated directly.

        STATIC_ASSET_PREFIXES once aborted startup because the field lacked
        NoDecode and pydantic-settings tried to JSON-decode a bare "/assets/"
        before the CSV validator saw it. The example no longer sets a value, so
        the guard has to live here.
        """
        monkeypatch.setenv("STATIC_ASSET_PREFIXES", "/assets/")
        assert Settings(_env_file=None).static_asset_prefixes == ["/assets/"]

        monkeypatch.setenv("STATIC_ASSET_PREFIXES", "/assets/,/static/")
        assert Settings(_env_file=None).static_asset_prefixes == ["/assets/", "/static/"]

    @pytest.mark.parametrize("raw", ["", "   "], ids=["empty", "whitespace"])
    def test_a_blank_coordinate_is_unset(self, monkeypatch, raw):
        monkeypatch.setenv("SERVER_LAT", raw)
        assert Settings(_env_file=None).server_lat is None

    def test_a_real_coordinate_still_arrives(self, monkeypatch):
        monkeypatch.setenv("SERVER_LAT", "52.52")
        assert Settings(_env_file=None).server_lat == 52.52


class TestTheDefaultsAreTheOnesDocumented:
    def test_the_tailer_does_not_read_a_backlog_by_default(self):
        """A database restored next to a surviving log would re-ingest it, and
        visits has no way to recognise the duplicates."""
        assert settings.ingest_existing_backlog is False

    def test_shodan_has_a_ceiling(self):
        assert settings.shodan_requests_per_minute > 0
        assert settings.shodan_cooldown_seconds > 0

    def test_dns_waits_are_bounded(self):
        assert settings.dns_timeout_seconds > 0
