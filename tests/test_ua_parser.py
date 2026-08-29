"""Tests for User-Agent parser."""

import pytest

from src.ua_parser import parse_user_agent


class TestParseUserAgent:
    """Test UA string parsing with fallback heuristics."""

    def test_known_chrome_browser(self):
        """Standard Chrome browser UA should parse correctly."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        result = parse_user_agent(ua)
        assert "Chrome" in result["browser"]
        assert "Windows" in result["os"]
        assert result["device"] == "Desktop"

    def test_firefox_browser(self):
        """Firefox UA should be recognized."""
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
        result = parse_user_agent(ua)
        assert "Firefox" in result["browser"]
        assert "Linux" in result["os"]
        assert result["device"] == "Desktop"

    def test_mobile_ua(self):
        """Mobile UA should be detected as Mobile device."""
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
        result = parse_user_agent(ua)
        assert result["device"] == "Mobile"
        assert "iOS" in result["os"]

    def test_tablet_ua(self):
        """Tablet UA should be detected."""
        ua = "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
        result = parse_user_agent(ua)
        assert result["device"] == "Tablet"

    def test_curl_bot(self):
        """curl user-agent should be detected as bot."""
        ua = "curl/8.14.1"
        result = parse_user_agent(ua)
        assert result["device"] == "Bot"
        assert "curl" in result["browser"].lower()

    def test_wget_bot(self):
        """wget user-agent should be detected."""
        ua = "Wget/1.21.2"
        result = parse_user_agent(ua)
        assert result["device"] == "Bot"
        assert "wget" in result["browser"].lower()

    def test_zgrab_scanner(self):
        """zgrab scanner should be recognized."""
        ua = "Zgrab/0.12.1"
        result = parse_user_agent(ua)
        assert result["device"] == "Bot"

    def test_censys_inspector(self):
        """CensysInspect UA should be recognized."""
        ua = "Mozilla/5.0 (compatible; CensysInspect/1.1; +http://censys.io)"
        result = parse_user_agent(ua)
        assert result["device"] == "Bot"

    def test_empty_ua(self):
        """Empty UA string should have sensible defaults."""
        result = parse_user_agent("")
        assert result["browser"] == "No User-Agent"
        assert result["os"] == "No User-Agent"
        assert result["device"] == "Unknown"

    def test_dash_ua(self):
        """Dash-only UA should be treated as empty."""
        result = parse_user_agent("-")
        assert result["browser"] == "No User-Agent"
        assert result["os"] == "No User-Agent"

    def test_unknown_ua(self):
        """Unknown/malformed UA should fallback gracefully."""
        ua = "SomeRandomBot/2.0"
        result = parse_user_agent(ua)
        assert result["browser"] != ""
        assert result["device"] in ("Bot", "Unknown", "Other")

    def test_android_mobile(self):
        """Android UA should detect mobile."""
        ua = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        result = parse_user_agent(ua)
        assert result["device"] == "Mobile"
        assert "Android" in result["os"]

    def test_lru_cache(self):
        """Repeated UA parses should use cache."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        result1 = parse_user_agent(ua)
        result2 = parse_user_agent(ua)
        # Same object from cache
        assert result1 is result2

    def test_cache_info(self):
        """Cache should track hits."""
        parse_user_agent.cache_clear()
        ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        ua2 = "Mozilla/5.0 (X11; Linux x86_64)"

        parse_user_agent(ua1)
        parse_user_agent(ua2)
        parse_user_agent(ua1)  # Hit

        info = parse_user_agent.cache_info()
        assert info.hits >= 1
        assert info.misses >= 2

    def test_result_is_immutable(self):
        """Result should be immutable (MappingProxyType)."""
        ua = "Mozilla/5.0"
        result = parse_user_agent(ua)
        with pytest.raises(TypeError):
            result["browser"] = "Hacked"  # type: ignore

    def test_whitespace_ua(self):
        """Whitespace-only UA should be treated as empty."""
        result = parse_user_agent("   ")
        assert result["browser"] == "No User-Agent"

    def test_python_requests_bot(self):
        """python-requests should be detected as bot."""
        ua = "python-requests/2.31.0"
        result = parse_user_agent(ua)
        assert result["device"] == "Bot"

    def test_go_http_client_bot(self):
        """go-http-client should be detected as bot."""
        ua = "Go-http-client/2.0"
        result = parse_user_agent(ua)
        assert result["device"] == "Bot"


def test_bot_ua_with_a_desktop_platform_token_is_a_bot():
    """The library sets is_pc alongside is_bot for crawlers whose UA carries a
    desktop platform. Testing is_pc first meant those never came out as "Bot",
    so they never reached the classifier's generic-bot rule."""
    result = parse_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AhrefsBot/7.0")
    assert result["device"] == "Bot"
