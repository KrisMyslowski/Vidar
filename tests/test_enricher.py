from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.enricher import _init_async_globals, _parse_api_result, enrich_batch


def test_parse_success():
    item = {
        "status": "success",
        "query": "93.184.216.34",
        "country": "United States",
        "countryCode": "US",
        "city": "Norwell",
        "lat": 42.1596,
        "lon": -70.8217,
        "isp": "Edgecast Inc.",
        "org": "Verizon Digital Media Services",
        "as": "AS15133 Edgecast Inc.",
        "proxy": False,
        "hosting": True,
        "mobile": False,
    }
    result = _parse_api_result(item)
    assert result is not None
    assert result["ip"] == "93.184.216.34"
    assert result["country_code"] == "US"
    assert result["is_hosting"] is True
    assert result["is_proxy"] is False
    # fetched_at is stamped in enrich_batch() after all enrichment steps complete, not here
    assert "fetched_at" not in result


def test_parse_failure():
    item = {"status": "fail", "message": "private range", "query": "192.168.1.1"}
    assert _parse_api_result(item) is None


def test_error_backoff_progression():
    """Backoff doubles per consecutive error: 10s, 20s, 40s, ... capped at 300s."""
    from src.enricher import _error_backoff_s

    assert _error_backoff_s(1) == 10
    assert _error_backoff_s(2) == 20
    assert _error_backoff_s(3) == 40
    assert _error_backoff_s(6) == 300  # 10 * 2^5 = 320 -> capped
    assert _error_backoff_s(20) == 300


def test_reverse_ipv6_known_vector():
    """Nibble-reversal per RFC 5782."""
    from src.enricher import _reverse_ipv6

    assert (
        _reverse_ipv6("2001:db8::1")
        == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
    )
    # 32 nibbles -> 32 dot-separated parts
    assert len(_reverse_ipv6("2001:db8::1").split(".")) == 32


def test_reverse_ipv6_invalid_returns_none():
    from src.enricher import _reverse_ipv6

    assert _reverse_ipv6("not-an-ip") is None
    assert _reverse_ipv6("1.2.3.4") is None  # IPv4 is not IPv6
    assert _reverse_ipv6("2001:zzzz::1") is None


@patch("src.enricher._bounded_dnsbl_lookup", new_callable=AsyncMock)
async def test_check_dnsbl_ipv6_builds_nibble_query(mock_lookup):
    """IPv6 addresses are queried with the nibble-reversed name, not skipped."""
    from src.config import settings
    from src.enricher import _check_dnsbl

    mock_lookup.return_value = False
    listed, sources = await _check_dnsbl("2001:db8::1")

    assert listed is False
    assert sources == ""
    assert mock_lookup.call_count == len(settings.dnsbl_providers)
    reversed_args = {call.args[0] for call in mock_lookup.call_args_list}
    assert reversed_args == {"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"}


@patch("src.enricher._bounded_dnsbl_lookup", new_callable=AsyncMock)
async def test_check_dnsbl_ipv4_dotted_quad_reversed(mock_lookup):
    from src.enricher import _check_dnsbl

    mock_lookup.return_value = False
    await _check_dnsbl("1.2.3.4")

    reversed_args = {call.args[0] for call in mock_lookup.call_args_list}
    assert reversed_args == {"4.3.2.1"}


@patch("src.enricher._bounded_dnsbl_lookup", new_callable=AsyncMock)
async def test_check_dnsbl_invalid_ipv6_asks_nobody(mock_lookup):
    """An address we cannot build a query name for yields no verdict at all —
    not a clean one. See test_enrichment_is_not_destructive.py."""
    from src.enricher import _check_dnsbl

    assert await _check_dnsbl("2001:zzzz::1") is None
    mock_lookup.assert_not_called()


# ── Negative cache for permanent ip-api failures ─────────────────────────────


def _api_item(ip: str) -> dict:
    return {
        "status": "success",
        "query": ip,
        "country": "Germany",
        "countryCode": "DE",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.40,
        "isp": "ISP",
        "org": "Org",
        "as": "AS1 Org",
        "proxy": False,
        "hosting": False,
        "mobile": False,
    }


def _mock_batch_response(items: list[dict]) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"X-Rl": "10", "X-Ttl": "60"}
    resp.json.return_value = items
    resp.raise_for_status.return_value = None
    return resp


@patch("src.enricher._check_dnsbl", new_callable=AsyncMock)
@patch("src.enricher._load_tor_exits", new_callable=AsyncMock)
@patch("src.enricher._fetch_shodan", new_callable=AsyncMock)
async def test_enrich_batch_returns_failed_ips(mock_shodan, mock_tor, mock_dnsbl):
    """status=fail items come back as failed_ips; success items are enriched normally."""
    _init_async_globals()
    mock_shodan.return_value = {
        "reverse_dns": "",
        "open_ports": "",
        "tags": "",
        "hostnames": "",
        "cpes": "",
        "vulns": "",
    }
    mock_tor.return_value = set()
    mock_dnsbl.return_value = (False, "")

    client = MagicMock()
    client.post = AsyncMock(
        return_value=_mock_batch_response(
            [
                _api_item("93.184.216.34"),
                {"status": "fail", "message": "private range", "query": "100.64.0.1"},
            ]
        )
    )

    enriched, failed = await enrich_batch(["93.184.216.34", "100.64.0.1"], client)

    assert [e["ip"] for e in enriched] == ["93.184.216.34"]
    assert failed == ["100.64.0.1"]
    # No Shodan lookup wasted on the failed IP
    assert mock_shodan.call_count == 1


async def test_enrich_batch_transient_error_marks_nothing_failed():
    """A whole-batch failure (network error) must not report IPs as permanently
    failed — and must not read as "nothing to do" either, or the worker's
    backoff never engages. See tests/test_enricher_backs_off.py."""
    _init_async_globals()
    client = MagicMock()
    client.post = AsyncMock(side_effect=RuntimeError("connection reset"))

    assert await enrich_batch(["93.184.216.34"], client) is None


def test_mark_enrichment_failed_creates_stub_and_stops_requeue(tmp_db):
    """A failure stub keeps the IP out of get_unenriched_ips (no retry storm)."""
    from src.db import get_conn
    from src.queries import get_unenriched_ips, insert_visit, mark_enrichment_failed

    with get_conn() as conn:
        insert_visit(conn, ip="100.64.0.1", timestamp="2026-07-06T10:00:00+00:00")
        assert get_unenriched_ips(conn) == ["100.64.0.1"]

        mark_enrichment_failed(conn, "100.64.0.1", "2026-07-06T10:00:01+00:00")

        assert get_unenriched_ips(conn) == []
        row = conn.execute("SELECT fetched_at FROM ip_intel WHERE ip = '100.64.0.1'").fetchone()
        assert row["fetched_at"] == "2026-07-06T10:00:01+00:00"


def test_mark_enrichment_failed_preserves_existing_data(tmp_db):
    """Failing a re-enrichment only bumps fetched_at — earlier data is not wiped."""
    from src.db import get_conn
    from src.queries import get_ip_intel, mark_enrichment_failed, upsert_ip_intel

    with get_conn() as conn:
        upsert_ip_intel(
            conn,
            {
                "ip": "93.184.216.34",
                "country": "Germany",
                "country_code": "DE",
                "is_hosting": True,
                "fetched_at": "2026-06-01T00:00:00+00:00",
            },
        )

        mark_enrichment_failed(conn, "93.184.216.34", "2026-07-06T10:00:00+00:00")

        intel = get_ip_intel(conn, "93.184.216.34")
        assert intel["country"] == "Germany"
        assert intel["is_hosting"] == 1
        assert intel["fetched_at"] == "2026-07-06T10:00:00+00:00"


# ── DNSBL response codes ──────────────────────────────────────────────────────
# A DNSBL answers in 127.0.0.0/8 and the *value* is the answer. Treating "it
# resolved" as "it is listed" marked 11,372 of 11,527 production IPs (98.7%) as
# blocklisted — including Googlebot ranges — because Spamhaus answers
# 127.255.255.254 ("you queried via a public resolver") to every lookup.


def _addrinfo(*addrs):
    """Shape of socket.getaddrinfo's return value, with only the address filled in."""
    return [(2, 1, 6, "", (a, 0)) for a in addrs]


@pytest.mark.parametrize(
    "addr,expected",
    [
        ("127.0.0.2", True),  # SBL
        ("127.0.0.3", True),  # CSS
        ("127.0.0.4", True),  # XBL
        ("127.0.0.11", True),  # PBL
        ("127.255.255.252", None),  # error: wrong zone name
        ("127.255.255.254", None),  # error: open resolver — the production case
        ("127.255.255.255", None),  # error: over quota
    ],
)
def test_dnsbl_lookup_reads_the_return_code(addr, expected):
    from src.enricher import _dnsbl_lookup

    with patch("src.enricher.socket.getaddrinfo", return_value=_addrinfo(addr)):
        assert _dnsbl_lookup("4.3.2.1", "zen.spamhaus.org") is expected


def test_dnsbl_lookup_nxdomain_is_not_listed():
    import socket as _socket

    from src.enricher import _dnsbl_lookup

    with patch("src.enricher.socket.getaddrinfo", side_effect=_socket.gaierror):
        assert _dnsbl_lookup("4.3.2.1", "zen.spamhaus.org") is False


@patch("src.enricher._bounded_dnsbl_lookup", new_callable=AsyncMock)
async def test_dnsbl_error_code_does_not_count_as_a_source(mock_lookup):
    """The whole point: a refused query must not become a listing.

    Nor a clearance. When every provider refuses there is no answer to record,
    and the caller leaves dnsbl_listed as it found it.
    """
    from src.enricher import _check_dnsbl

    mock_lookup.return_value = None
    assert await _check_dnsbl("1.2.3.4") is None

    # One provider answering is enough to record what it said.
    mock_lookup.side_effect = [True, None]
    assert await _check_dnsbl("1.2.3.4") == (True, "zen.spamhaus.org")


def test_dqs_key_rewrites_the_spamhaus_zone():
    from src.config import settings
    from src.enricher import _dnsbl_host

    original = settings.dnsbl_dqs_key
    try:
        settings.dnsbl_dqs_key = "abc123"
        assert _dnsbl_host("zen.spamhaus.org") == "abc123.zen.dq.spamhaus.net"
        assert _dnsbl_host("bl.spamcop.net") == "bl.spamcop.net"
        settings.dnsbl_dqs_key = ""
        assert _dnsbl_host("zen.spamhaus.org") == "zen.spamhaus.org"
    finally:
        settings.dnsbl_dqs_key = original


# ── Reverse DNS ───────────────────────────────────────────────────────────────


def test_reverse_dns_requires_forward_confirmation():
    """A PTR record is published by whoever owns the IP block, so it can claim any
    name. Only a forward lookup back to the same IP proves it."""
    from src.enricher import _reverse_dns_lookup

    with patch("src.enricher.socket.gethostbyaddr", return_value=("crawl.googlebot.com", [], [])):
        with patch("src.enricher.socket.getaddrinfo", return_value=_addrinfo("66.249.66.1")):
            assert _reverse_dns_lookup("66.249.66.1") == "crawl.googlebot.com"
        # Same claimed name, forward lookup points somewhere else — discard it.
        with patch("src.enricher.socket.getaddrinfo", return_value=_addrinfo("5.6.7.8")):
            assert _reverse_dns_lookup("66.249.66.1") == ""


async def test_reverse_dns_backfill_stamps_ips_without_a_ptr_record(tmp_db):
    """An IP with no PTR must be marked as checked, or it is retried forever."""
    from src.db import get_conn
    from src.enricher import reverse_dns_backfill
    from src.queries import get_ips_without_rdns, upsert_ip_intel

    with get_conn(tmp_db) as conn:
        upsert_ip_intel(conn, {"ip": "9.9.9.9"})
        upsert_ip_intel(conn, {"ip": "8.8.4.4"})

    _init_async_globals()
    with patch("src.enricher.get_conn", lambda *a, **k: get_conn(tmp_db)):
        with patch("src.enricher._reverse_dns_lookup", side_effect=["dns.example.net", ""]):
            resolved = await reverse_dns_backfill()

    assert resolved == 1
    with get_conn(tmp_db) as conn:
        assert get_ips_without_rdns(conn) == []
        rows = dict(conn.execute("SELECT ip, reverse_dns FROM ip_intel").fetchall())
    assert rows["9.9.9.9"] == "dns.example.net"
    assert rows["8.8.4.4"] == ""
