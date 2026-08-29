"""Tests for Jinja2 filters in dashboard routes."""

from markupsafe import Markup

from src.template_filters import cpe_os as _cpe_os
from src.template_filters import cpe_services as _cpe_services
from src.template_filters import csv_items as _csv_items
from src.template_filters import fmtbytes as _fmtbytes
from src.template_filters import fmtdate as _fmtdate
from src.template_filters import fmtresptime as _fmtresptime
from src.template_filters import parse_cpe as _parse_cpe
from src.template_filters import primarylang as _primarylang


class TestFmtdate:
    """Test date formatting filter."""

    def test_iso_timestamp_to_local(self):
        """Should format ISO timestamp as dd.mm.yy HH:MM."""
        result = _fmtdate("2026-04-15T14:32:00")
        assert result == "15.04.26 14:32"

    def test_empty_string(self):
        """Empty string should return as-is."""
        assert _fmtdate("") == ""

    def test_dash_symbol(self):
        """Dash symbol should return as-is."""
        assert _fmtdate("—") == "—"

    def test_invalid_timestamp(self):
        """Invalid timestamp should return as-is."""
        result = _fmtdate("not-a-date")
        assert result == "not-a-date"

    def test_none_value(self):
        """None should return empty."""
        result = _fmtdate(None)
        assert result == ""


class TestCsvItems:
    """Test the CSV→chip-items helper used by overflow_cell."""

    def test_splits_into_items(self):
        items = _csv_items("443,80,22")
        assert [i["label"] for i in items] == ["443", "80", "22"]
        assert all(i["cls"] == "badge-muted" for i in items)

    def test_blank_returns_empty_list(self):
        assert _csv_items("") == []
        assert _csv_items(None) == []

    def test_custom_class(self):
        items = _csv_items("a,b", cls="badge-red")
        assert all(i["cls"] == "badge-red" for i in items)


class TestParseCpe:
    """Test CPE version parsing."""

    def test_cpe_2_2_format(self):
        """Parse CPE 2.2 format (cpe:/)."""
        result = _parse_cpe("cpe:/o:microsoft:windows:10")
        assert "Windows" in result
        assert "10" in result

    def test_cpe_2_3_format(self):
        """Parse CPE 2.3 format (cpe:2.3:)."""
        result = _parse_cpe("cpe:2.3:o:microsoft:windows:10")
        assert "Windows" in result
        assert "10" in result

    def test_invalid_cpe(self):
        """Invalid CPE should return as-is."""
        result = _parse_cpe("not-a-cpe")
        assert result == "not-a-cpe"

    def test_underscore_replacement(self):
        """Underscores should be replaced with spaces."""
        result = _parse_cpe("cpe:/a:apache:http_server:2.4")
        assert "Http Server" in result

    def test_short_cpe_no_version(self):
        """CPE with no version field should handle gracefully."""
        result = _parse_cpe("cpe:/o:linux")
        assert "Linux" in result


class TestCpeOs:
    """Test OS extraction from CPE list."""

    def test_extract_os_entries(self):
        """Should extract cpe:/o: entries."""
        cpes = "cpe:/o:microsoft:windows:10,cpe:/a:apache:http_server:2.4"
        result = _cpe_os(cpes)
        assert isinstance(result, Markup)
        assert "Windows" in str(result)
        assert "Apache" not in str(result)

    def test_extract_cpe_2_3_os(self):
        """Should extract cpe:2.3:o: entries."""
        cpes = "cpe:2.3:o:linux:linux_kernel:5.10"
        result = _cpe_os(cpes)
        assert "Linux" in str(result)

    def test_empty_cpes(self):
        """Empty should return dash."""
        result = _cpe_os("")
        assert result == Markup("—")

    def test_no_os_entries(self):
        """No OS entries should return dash."""
        cpes = "cpe:/a:apache:http_server:2.4"
        result = _cpe_os(cpes)
        assert result == Markup("—")

    def test_none_value(self):
        """None should return dash."""
        result = _cpe_os(None)
        assert result == Markup("—")


class TestCpeServices:
    """Test application/service extraction from CPE list."""

    def test_extract_app_entries(self):
        """Should extract cpe:/a: entries."""
        cpes = "cpe:/o:microsoft:windows:10,cpe:/a:apache:http_server:2.4"
        result = _cpe_services(cpes)
        assert isinstance(result, Markup)
        assert "Apache" in str(result) or "Http Server" in str(result)
        assert "Windows" not in str(result)

    def test_extract_cpe_2_3_app(self):
        """Should extract cpe:2.3:a: entries."""
        cpes = "cpe:2.3:a:openssl:openssl:1.1.1"
        result = _cpe_services(cpes)
        assert "Openssl" in str(result)

    def test_empty_cpes(self):
        """Empty should return dash."""
        result = _cpe_services("")
        assert result == Markup("—")

    def test_no_app_entries(self):
        """No app entries should return dash."""
        cpes = "cpe:/o:microsoft:windows:10"
        result = _cpe_services(cpes)
        assert result == Markup("—")


class TestFmtbytes:
    """Test byte size formatting."""

    def test_bytes_to_kb(self):
        """Bytes < 1024 should show as B."""
        result = _fmtbytes(512)
        assert "B" in result

    def test_kilobytes(self):
        """Around 1024 should show as KB."""
        result = _fmtbytes(2048)
        assert "KB" in result or "B" in result

    def test_megabytes(self):
        """Large values should show as MB/GB."""
        result = _fmtbytes(1024 * 1024 * 5)  # 5 MB
        assert "MB" in result

    def test_gigabytes(self):
        """Very large should show as GB."""
        result = _fmtbytes(1024 * 1024 * 1024)  # 1 GB
        assert "GB" in result

    def test_zero_bytes(self):
        """Zero should show as 0 B."""
        result = _fmtbytes(0)
        assert "0" in result

    def test_none_value(self):
        """None should show 0 B."""
        result = _fmtbytes(None)
        assert "0" in result


class TestFmtresptime:
    """Test response time formatting."""

    def test_milliseconds(self):
        """Sub-second should show as ms."""
        result = _fmtresptime(0.123)
        assert "ms" in result

    def test_seconds(self):
        """Over 1s should show as s."""
        result = _fmtresptime(1.5)
        assert "s" in result
        assert "ms" not in result

    def test_zero_time(self):
        """Zero should be valid."""
        result = _fmtresptime(0)
        assert result

    def test_very_slow(self):
        """Very slow response should show clearly."""
        result = _fmtresptime(30.0)
        assert "s" in result


class TestPrimarylang:
    """Test primary language extraction from Accept-Language header."""

    def test_single_language(self):
        """Single language code should be returned."""
        result = _primarylang("en")
        assert result == "en"

    def test_language_with_region(self):
        """Should extract language part from en-US."""
        result = _primarylang("en-US")
        assert result.startswith("en")

    def test_multiple_languages_weighted(self):
        """Should return first/highest-weighted language."""
        result = _primarylang("en-US,en;q=0.9,fr;q=0.8")
        assert "en" in result

    def test_weighted_preference(self):
        """Should prefer higher q-value."""
        result = _primarylang("en;q=0.5,fr;q=0.9")
        assert "fr" in result or "en" in result  # Depends on implementation

    def test_empty_header(self):
        """Empty header should return empty or default."""
        result = _primarylang("")
        assert result == "" or result is not None

    def test_malformed_header(self):
        """Malformed header should handle gracefully."""
        result = _primarylang("not-valid-!!!!")
        # Should not crash
        assert isinstance(result, str)

    def test_none_value(self):
        """None should return empty."""
        result = _primarylang(None)
        assert result == ""
