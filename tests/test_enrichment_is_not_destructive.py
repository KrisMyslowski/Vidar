"""A provider that does not answer must not overwrite what we already know.

Five sources fail independently, and four of them used to report failure as an
empty result: Shodan returned the same empty dict for "404, no record" and for a
timeout, the Tor loader returned an empty set either way, _check_dnsbl folded a
refusing zone into (False, ""), and upsert_ip_intel filled every missing key
with its default and wrote it. Together that meant one Shodan hiccup during a
re-enrichment deleted an IP's ports, CVEs, CPEs, tags and hostnames, a failed
Tor download recorded a batch of exit nodes as not-Tor, and a dead resolver
recorded every IP as clean.

The rule these hold: a column is written when a provider answered about it, and
absence is not a negative.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.db import get_conn
from src.enricher import _check_dnsbl, _fetch_shodan, _init_async_globals, _load_tor_exits
from src.queries import get_ip_intel, upsert_ip_intel

KNOWN = {
    "ip": "93.184.216.34",
    "country": "Germany",
    "country_code": "DE",
    "city": "Berlin",
    "lat": 52.52,
    "lon": 13.40,
    "isp": "Example ISP",
    "org": "Example Org",
    "asn": "AS1 Example",
    "is_proxy": False,
    "is_hosting": True,
    "is_mobile": False,
    "reverse_dns": "host.example.com",
    "is_tor": True,
    "dnsbl_listed": True,
    "dnsbl_sources": "zen.spamhaus.org",
    "open_ports": "22,443",
    "tags": "cloud",
    "vulns": "CVE-2021-44228",
    "cpes": "cpe:/a:nginx:nginx",
    "hostnames": "host.example.com",
    "fetched_at": "2026-01-01T00:00:00+00:00",
}

CHILD_TABLES = {
    "ip_intel_ports": "port",
    "ip_intel_tags": "tag",
    "ip_intel_vulns": "vuln",
    "ip_intel_cpes": "cpe",
    "ip_intel_hostnames": "hostname",
}


def _children(conn, ip: str) -> dict[str, list]:
    return {
        table: [r[0] for r in conn.execute(f"SELECT {col} FROM {table} WHERE ip = ?", (ip,))]
        for table, col in CHILD_TABLES.items()
    }


def _seed(conn) -> None:
    upsert_ip_intel(conn, dict(KNOWN))


class TestTheWriteLayerOnlyTouchesWhatItWasGiven:
    """upsert_ip_intel is where absence used to become a default."""

    def test_a_key_that_is_absent_leaves_the_column_alone(self, tmp_db):
        with get_conn() as conn:
            _seed(conn)
            # ip-api answered; nothing else did.
            upsert_ip_intel(
                conn,
                {
                    "ip": KNOWN["ip"],
                    "country": "France",
                    "country_code": "FR",
                    "fetched_at": "2026-02-02T00:00:00+00:00",
                },
            )
            row = get_ip_intel(conn, KNOWN["ip"])

        assert row["country"] == "France", "the answer we got should land"
        assert row["fetched_at"] == "2026-02-02T00:00:00+00:00"
        assert row["is_tor"] == 1, "no Tor answer — the stored verdict stands"
        assert row["dnsbl_listed"] == 1
        assert row["dnsbl_sources"] == "zen.spamhaus.org"
        assert row["reverse_dns"] == "host.example.com"
        assert row["city"] == "Berlin"
        assert row["is_hosting"] == 1

    def test_a_child_table_is_untouched_when_its_key_is_absent(self, tmp_db):
        with get_conn() as conn:
            _seed(conn)
            before = _children(conn, KNOWN["ip"])
            upsert_ip_intel(conn, {"ip": KNOWN["ip"], "fetched_at": "2026-02-02T00:00:00+00:00"})
            assert _children(conn, KNOWN["ip"]) == before

    def test_an_empty_answer_still_clears(self, tmp_db):
        """The keys are present and empty: Shodan answered, and what it knows now
        is nothing. That is what delete-then-insert is for."""
        with get_conn() as conn:
            _seed(conn)
            upsert_ip_intel(
                conn,
                {
                    "ip": KNOWN["ip"],
                    "open_ports": "",
                    "tags": "",
                    "vulns": "",
                    "cpes": "",
                    "hostnames": "",
                    "is_tor": False,
                },
            )
            row = get_ip_intel(conn, KNOWN["ip"])
            assert _children(conn, KNOWN["ip"]) == {t: [] for t in CHILD_TABLES}
        assert row["is_tor"] == 0

    def test_a_new_row_still_gets_the_defaults(self, tmp_db):
        with get_conn() as conn:
            upsert_ip_intel(conn, {"ip": "198.51.100.7", "country": "Spain"})
            row = get_ip_intel(conn, "198.51.100.7")
        assert row["country"] == "Spain"
        assert row["is_tor"] == 0 and row["dnsbl_listed"] == 0
        assert row["reverse_dns"] == "" and row["city"] == ""
        assert row["fetched_at"], "a row that was looked at carries a timestamp"


class TestShodanSaysWhetherItAnswered:
    async def _fetch(self, **response):
        client = MagicMock()
        if "exc" in response:
            client.get = AsyncMock(side_effect=response["exc"])
        else:
            resp = MagicMock()
            resp.status_code = response.get("status", 200)
            resp.json.return_value = response.get("body", {})
            if response.get("status", 200) >= 400 and response.get("status") != 404:
                resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                    "boom", request=MagicMock(), response=MagicMock()
                )
            else:
                resp.raise_for_status.return_value = None
            client.get = AsyncMock(return_value=resp)
        return await _fetch_shodan("93.184.216.34", client)

    async def test_404_is_an_answer(self):
        result = await self._fetch(status=404)
        assert result == {"open_ports": "", "tags": "", "hostnames": "", "cpes": "", "vulns": ""}

    @pytest.mark.parametrize(
        "case",
        [
            {"exc": httpx.TimeoutException("timed out")},
            {"exc": httpx.ConnectError("refused")},
            {"status": 429},
            {"status": 500},
            {"body": "not a dict"},
        ],
        ids=["timeout", "connect-error", "rate-limited", "server-error", "junk-body"],
    )
    async def test_no_answer_is_none(self, case):
        assert await self._fetch(**case) is None

    async def test_a_real_answer_carries_the_ports(self):
        result = await self._fetch(body={"ports": [22, 443], "tags": ["cloud"], "vulns": []})
        assert result["open_ports"] == "22,443"
        assert result["tags"] == "cloud"

    async def test_an_answer_without_hostnames_does_not_claim_reverse_dns(self):
        """reverse_dns holds forward-confirmed PTR data. Shodan contributes to it
        only when it actually has a name."""
        assert "reverse_dns" not in await self._fetch(body={"ports": [22]})
        assert "reverse_dns" not in await self._fetch(status=404)
        withname = await self._fetch(body={"hostnames": ["host.example.com"]})
        assert withname["reverse_dns"] == "host.example.com"


class TestTorAndDnsblSayWhetherTheyAnswered:
    async def test_a_failed_download_with_no_cache_is_none(self):
        _init_async_globals()
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("no route"))
        assert await _load_tor_exits(client) is None

    async def test_a_stale_list_beats_no_list(self):
        """An exit list from yesterday is evidence; an empty set is not."""
        import src.enricher as enricher

        _init_async_globals()
        enricher._tor_exits = {"1.2.3.4"}
        enricher._tor_exits_loaded_at = 0  # long expired
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("no route"))
        try:
            assert await _load_tor_exits(client) == {"1.2.3.4"}
        finally:
            enricher._tor_exits = set()
            enricher._tor_exits_loaded_at = 0

    @patch("src.enricher._bounded_dnsbl_lookup", new_callable=AsyncMock)
    async def test_every_provider_erroring_is_none(self, mock_lookup):
        _init_async_globals()
        mock_lookup.return_value = None  # 127.255.255.x — the zone refused us
        assert await _check_dnsbl("93.184.216.34") is None

    @patch("src.enricher._bounded_dnsbl_lookup", new_callable=AsyncMock)
    async def test_one_provider_answering_is_a_verdict(self, mock_lookup):
        _init_async_globals()
        mock_lookup.side_effect = [False, None]
        assert await _check_dnsbl("93.184.216.34") == (False, "")

    async def test_an_unqueryable_address_is_none(self):
        _init_async_globals()
        assert await _check_dnsbl("not-an-ip") is None
        assert await _check_dnsbl("1.2.3") is None


class TestAFullOutageChangesNothingButTheTimestamp:
    """The test the whole block exists for.

    ip-api answers, every other source is down, and the IP already has a
    complete record. Before, this call deleted five child tables and rewrote
    three columns with defaults.
    """

    @patch("src.enricher._check_dnsbl", new_callable=AsyncMock)
    @patch("src.enricher._load_tor_exits", new_callable=AsyncMock)
    @patch("src.enricher._bounded_reverse_dns", new_callable=AsyncMock)
    @patch("src.enricher._fetch_shodan", new_callable=AsyncMock)
    async def test_the_record_survives(self, mock_shodan, mock_rdns, mock_tor, mock_dnsbl, tmp_db):
        from src.enricher import enrich_batch

        _init_async_globals()
        mock_shodan.return_value = None  # timed out
        mock_rdns.return_value = ""  # no PTR
        mock_tor.return_value = None  # list unreachable
        mock_dnsbl.return_value = None  # every zone refused

        with get_conn() as conn:
            _seed(conn)
            before_children = _children(conn, KNOWN["ip"])

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"X-Rl": "10", "X-Ttl": "60"}
        resp.raise_for_status.return_value = None
        resp.json.return_value = [
            {
                "status": "success",
                "query": KNOWN["ip"],
                "country": "Germany",
                "countryCode": "DE",
                "city": "Berlin",
                "lat": 52.52,
                "lon": 13.40,
                "isp": "Example ISP",
                "org": "Example Org",
                "as": "AS1 Example",
                "proxy": False,
                "hosting": True,
                "mobile": False,
            }
        ]
        client = MagicMock()
        client.post = AsyncMock(return_value=resp)

        enriched, failed = await enrich_batch([KNOWN["ip"]], client)
        assert failed == []

        with get_conn() as conn:
            upsert_ip_intel(conn, enriched[0])
            row = get_ip_intel(conn, KNOWN["ip"])
            assert _children(conn, KNOWN["ip"]) == before_children

        assert row["is_tor"] == 1, "a failed Tor download is not a verdict"
        assert row["dnsbl_listed"] == 1, "a refusing blocklist is not a clean record"
        assert row["dnsbl_sources"] == "zen.spamhaus.org"
        assert row["reverse_dns"] == "host.example.com", "a failed PTR erases nothing"
        assert row["fetched_at"] != KNOWN["fetched_at"], "the IP was looked at"
