"""Extended tests for log processor edge cases."""

from src.log_processor import (
    _derive_server_port,
    _is_health_check,
    _is_internal_ip,
    _is_static_asset,
    parse_log_line,
    should_skip,
)
from src.models import LogEntry


class TestIsStaticAsset:
    """Test static asset detection."""

    def test_css_file(self):
        """CSS files should be static."""
        assert _is_static_asset("/style.css")

    def test_js_file(self):
        """JS files should be static."""
        assert _is_static_asset("/app.js")

    def test_image_files(self):
        """Images should be static."""
        assert _is_static_asset("/logo.png")
        assert _is_static_asset("/icon.svg")

    def test_css_with_query_string(self):
        """CSS with query string should be detected (cache buster)."""
        assert _is_static_asset("/style.css?v=1.2.3")

    def test_js_with_query_string(self):
        """JS with query string should be detected."""
        assert _is_static_asset("/app.js?v=2.0")

    def test_html_page(self):
        """HTML pages should NOT be static."""
        assert not _is_static_asset("/index.html")
        assert not _is_static_asset("/about")

    def test_api_endpoint(self):
        """API endpoints should NOT be static."""
        assert not _is_static_asset("/api/visits")

    def test_empty_path(self):
        """Root path should not be static."""
        assert not _is_static_asset("/")

    def test_case_insensitive(self):
        """Should be case-insensitive."""
        assert _is_static_asset("/Style.CSS")
        assert _is_static_asset("/APP.JS")


class TestIsInternalIp:
    """Test internal IP detection."""

    def test_ipv4_loopback(self):
        """127.0.0.1 should be internal."""
        assert _is_internal_ip("127.0.0.1")

    def test_ipv4_rfc1918_10(self):
        """10.x.x.x should be internal."""
        assert _is_internal_ip("10.0.0.1")
        assert _is_internal_ip("10.255.255.255")

    def test_ipv4_rfc1918_172(self):
        """172.16.x.x - 172.31.x.x should be internal."""
        assert _is_internal_ip("172.16.0.1")
        assert _is_internal_ip("172.31.255.255")

    def test_ipv4_rfc1918_192(self):
        """192.168.x.x should be internal."""
        assert _is_internal_ip("192.168.1.1")

    def test_ipv6_loopback(self):
        """::1 should be internal."""
        assert _is_internal_ip("::1")

    def test_public_ipv4(self):
        """Public IPs should NOT be internal."""
        assert not _is_internal_ip("8.8.8.8")
        assert not _is_internal_ip("1.1.1.1")

    def test_invalid_ip(self):
        """An address that will not parse is not internal — it is its own case.

        Answering True here filed a broken log field under the wrong reason and
        hung it on filter_internal_ips, a switch it has nothing to do with, so
        turning that off would have started inserting the garbage. skip_reason()
        handles it; see tests/test_filters_that_cost_data.py.
        """
        assert _is_internal_ip("not-an-ip") is False
        assert _is_internal_ip("999.999.999.999") is False


class TestIsHealthCheck:
    """Test health check bot detection."""

    def test_health_check_ua(self):
        """Health check UAs should be detected."""
        assert _is_health_check("Health-Check")
        assert _is_health_check("UptimeRobot/2.0")

    def test_kuma_uptime(self):
        """Kuma uptime monitoring."""
        assert _is_health_check("kuma/1.0")

    def test_pingdom(self):
        """Pingdom should be detected."""
        assert _is_health_check("Pingdom.com_bot_version_1.4")

    def test_normal_browser(self):
        """Normal browsers should NOT be health checks."""
        assert not _is_health_check("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

    def test_case_insensitive(self):
        """Should be case-insensitive."""
        assert _is_health_check("HEALTH-CHECK")
        assert _is_health_check("UptimE")


class TestDeriveServerPort:
    """Test server port detection."""

    def test_http_default_port(self):
        """HTTP should default to 80."""
        entry = LogEntry(
            time="2026-04-06T12:00:00+00:00",
            remote_addr="1.2.3.4",
            request="GET / HTTP/1.1",
            status=200,
            body_bytes_sent=100,
            ssl_protocol="",  # No SSL
        )
        port = _derive_server_port(entry)
        assert port == 80

    def test_https_default_port(self):
        """HTTPS should default to 443."""
        entry = LogEntry(
            time="2026-04-06T12:00:00+00:00",
            remote_addr="1.2.3.4",
            request="GET / HTTP/1.1",
            status=200,
            body_bytes_sent=100,
            ssl_protocol="TLSv1.3",  # SSL present
        )
        port = _derive_server_port(entry)
        assert port == 443


class TestParseLogLine:
    """Test JSON log line parsing."""

    def test_valid_log_line(self, sample_json_line):
        """Valid log line should parse."""
        entry = parse_log_line(sample_json_line)
        assert entry is not None
        assert entry.remote_addr == "93.184.216.34"
        assert entry.request_method == "GET"

    def test_malformed_json(self):
        """Malformed JSON should return None."""
        entry = parse_log_line("not valid json")
        assert entry is None

    def test_missing_required_field(self):
        """Missing required fields should return None."""
        incomplete_json = '{"time":"2026-04-06T13:05:27+00:00","remote_addr":"1.2.3.4"}'
        entry = parse_log_line(incomplete_json)
        assert entry is None

    def test_empty_line(self):
        """Empty line should return None."""
        assert parse_log_line("") is None
        assert parse_log_line("   ") is None


class TestShouldSkip:
    """Test visit filtering."""

    def test_skip_internal_ip(self, sample_internal_line):
        """Internal IPs should be skipped."""
        entry = parse_log_line(sample_internal_line)
        assert entry is not None
        assert should_skip(entry) is True

    def test_skip_static_asset(self, sample_static_line):
        """Static assets should be skipped."""
        entry = parse_log_line(sample_static_line)
        assert entry is not None
        assert should_skip(entry) is True

    def test_skip_health_check_ua(self):
        """Health check UAs should be skipped."""
        log_line = (
            '{"time":"2026-04-06T13:05:27+00:00","remote_addr":"93.184.216.34",'
            '"request":"GET / HTTP/1.1","status":200,"body_bytes_sent":100,'
            '"http_referer":"","http_user_agent":"UptimeRobot/2.0","request_time":0.001,'
            '"ssl_protocol":"","request_method":"GET","request_uri":"/"}'
        )
        entry = parse_log_line(log_line)
        assert entry is not None
        assert should_skip(entry) is True

    def test_do_not_skip_normal_request(self, sample_json_line):
        """Normal requests should NOT be skipped."""
        entry = parse_log_line(sample_json_line)
        assert entry is not None
        assert should_skip(entry) is False
