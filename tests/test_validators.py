"""The layer between a URL and a query, which had one test.

Only valid_month() was covered, and only through the archive path. The other
eight were reached — if at all — through a route that happened to pass one bad
value. valid_order() is the sharpest of them: its return value is interpolated
straight into an ORDER BY, so what it does with input nobody planned for is the
whole question.
"""

import pytest

from src.validators import (
    valid_choice,
    valid_country,
    valid_date,
    valid_ip,
    valid_min_visits,
    valid_month,
    valid_order,
    valid_port,
    valid_search,
)


class TestOrderIsSafeForSql:
    """Interpolated into ORDER BY, so it may only ever be one of two words."""

    @pytest.mark.parametrize("raw", ["ASC", "asc", "AsC", " asc ".strip()])
    def test_ascending_is_recognised(self, raw):
        assert valid_order(raw) == "ASC"

    @pytest.mark.parametrize(
        "raw",
        [
            "DESC",
            "desc",
            "",
            "nonsense",
            "ASC; DROP TABLE visits",
            "ASC--",
            None,
            0,
            [],
        ],
        ids=[
            "desc",
            "lowercase",
            "empty",
            "junk",
            "injection",
            "comment",
            "none",
            "int",
            "list",
        ],
    )
    def test_everything_else_is_descending(self, raw):
        assert valid_order(raw) == "DESC"

    def test_it_only_ever_returns_two_values(self):
        seen = {valid_order(v) for v in ["ASC", "asc", "x", "", None, 1, "'", ";--"]}
        assert seen == {"ASC", "DESC"}


class TestIp:
    @pytest.mark.parametrize("raw", ["93.184.216.34", "::1", "2001:db8::1", "0.0.0.0"])
    def test_a_real_address_passes_through_unchanged(self, raw):
        assert valid_ip(raw) == raw

    @pytest.mark.parametrize(
        "raw",
        ["", None, "not-an-ip", "1.2.3", "999.1.1.1", "1.2.3.4/24", "1.2.3.4 ", "'; --"],
        ids=["empty", "none", "text", "short", "range", "cidr", "trailing-space", "sql"],
    )
    def test_anything_else_is_none(self, raw):
        assert valid_ip(raw) is None


class TestCountry:
    def test_it_uppercases(self):
        assert valid_country("de") == "DE"
        assert valid_country("DE") == "DE"

    @pytest.mark.parametrize(
        "raw",
        ["", None, "D", "DEU", "D1", "12", "  ", "d-"],
        ids=["empty", "none", "one", "three", "digit", "digits", "spaces", "punct"],
    )
    def test_anything_else_is_none(self, raw):
        assert valid_country(raw) is None


class TestDate:
    def test_a_well_formed_date_passes(self):
        assert valid_date("2026-08-13") == "2026-08-13"

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            None,
            "2026-8-13",
            "13-08-2026",
            "2026/08/13",
            "2026-08-13 ",
            "x2026-08-13",
            "2026-08-13\n",
        ],
        ids=[
            "empty",
            "none",
            "unpadded",
            "reversed",
            "slashes",
            "trailing",
            "prefixed",
            "newline",
        ],
    )
    def test_anything_else_is_none(self, raw):
        assert valid_date(raw) is None

    @pytest.mark.parametrize(
        "raw",
        ["2026-02-31", "2026-99-99", "2026-13-01", "2026-00-10", "2026-08-00", "2025-02-29"],
        ids=["feb-31", "impossible", "month-13", "month-00", "day-00", "non-leap-feb-29"],
    )
    def test_a_day_that_does_not_exist_is_none(self, raw):
        """It used to check the shape only, and SQLite resolves an impossible
        date to NULL — so the page answered "no visits" for a typo."""
        assert valid_date(raw) is None

    def test_a_real_leap_day_still_passes(self):
        assert valid_date("2024-02-29") == "2024-02-29"


class TestMonthGuardsTheFilesystem:
    """The only gate between a URL segment and <archive_dir>/<month>.zip."""

    def test_a_month_passes(self):
        assert valid_month("2026-04") == "2026-04"

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            None,
            "2026-6",
            "2026-13",
            "2026-00",
            "../secrets",
            "2026-04/../..",
            "2026-04.zip",
            "2026-04\n",
            "20264",
        ],
        ids=[
            "empty",
            "none",
            "unpadded",
            "month-13",
            "month-00",
            "traversal",
            "traversal-inside",
            "suffix",
            "newline",
            "no-separator",
        ],
    )
    def test_anything_else_is_none(self, raw):
        assert valid_month(raw) is None


class TestMinVisits:
    @pytest.mark.parametrize(
        "raw,expected",
        [("5", 5), (5, 5), ("0", 0), (0, 0), ("-3", 0), (-3, 0), ("", 0), (None, 0), ("x", 0)],
        ids=["str", "int", "zero-str", "zero", "neg-str", "neg", "empty", "none", "junk"],
    )
    def test_it_never_returns_below_zero(self, raw, expected):
        assert valid_min_visits(raw) == expected


class TestSearch:
    def test_it_trims(self):
        assert valid_search("  wp-admin  ") == "wp-admin"

    def test_it_caps_the_length(self):
        assert len(valid_search("x" * 500)) == 100
        assert len(valid_search("x" * 500, maxlen=10)) == 10

    @pytest.mark.parametrize("raw", ["", None, "   "], ids=["empty", "none", "spaces"])
    def test_nothing_to_search_for_is_none(self, raw):
        assert valid_search(raw) is None

    def test_wildcards_are_left_alone(self):
        """Escaping belongs to the query layer; changing it here would mean two
        places deciding what a LIKE pattern is."""
        assert valid_search("%_admin%") == "%_admin%"


class TestPort:
    @pytest.mark.parametrize("raw,expected", [("22", 22), (22, 22), ("65535", 65535), ("1", 1)])
    def test_a_port_in_range_passes(self, raw, expected):
        assert valid_port(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        ["", None, "0", "65536", "-1", "x", "22.5", "22; DROP"],
        ids=["empty", "none", "zero", "too-big", "negative", "junk", "float", "sql"],
    )
    def test_anything_else_is_none(self, raw):
        assert valid_port(raw) is None


class TestChoice:
    CHOICES = frozenset({"day", "hour", "week"})

    def test_a_known_choice_passes(self):
        assert valid_choice("hour", self.CHOICES, "day") == "hour"

    @pytest.mark.parametrize(
        "raw", ["", "month", "HOUR", " hour"], ids=["empty", "unknown", "case", "padded"]
    )
    def test_anything_else_falls_back(self, raw):
        assert valid_choice(raw, self.CHOICES, "day") == "day"
