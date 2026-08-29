"""When a provider pushes back, the enricher has to slow down.

It could not. enrich_batch swallowed every exception and returned ([], []) —
the same value it returns when there is nothing to do — so the worker counted
a sustained network fault as a successful round and reset consecutive_errors
to zero. The 10s→300s backoff existed and could never fire on the failure it
was written for: the same hundred IPs, every 4.5 s, indefinitely, one full
traceback per attempt.

Three more of the same shape: Shodan had a concurrency limit and no rate limit
at all, and swallowed 429; the Tor list stamped its cache only on success, so a
failed download was retried every batch; and the wait after ip-api's 429 came
straight from an unvalidated X-Ttl header.

The whole error path was also unreachable from the suite — _mock_batch_response
hardcodes status_code 200 — so none of it had ever been exercised.
"""

import asyncio
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import src.enricher as enricher
from src.enricher import (
    _error_backoff_s,
    _init_async_globals,
    _load_tor_exits,
    _rate_limit_pause,
    _RateGate,
    enrich_batch,
)


def _response(status=200, headers=None, body=None):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {"X-Rl": "10", "X-Ttl": "60"}
    resp.json.return_value = body if body is not None else []
    if status >= 400 and status != 404:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "boom", request=MagicMock(), response=MagicMock()
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


class TestABatchFailureIsNotAnEmptyBatch:
    """The distinction the backoff hangs on."""

    @pytest.mark.parametrize(
        "failure",
        [
            httpx.TimeoutException("timed out"),
            httpx.ConnectError("connection refused"),
            RuntimeError("connection reset"),
        ],
        ids=["timeout", "connect-error", "reset"],
    )
    async def test_a_failed_batch_is_none(self, failure):
        _init_async_globals()
        client = MagicMock()
        client.post = AsyncMock(side_effect=failure)
        assert await enrich_batch(["93.184.216.34"], client) is None

    async def test_a_server_error_is_none(self):
        _init_async_globals()
        client = MagicMock()
        client.post = AsyncMock(return_value=_response(status=500))
        assert await enrich_batch(["93.184.216.34"], client) is None

    async def test_an_unparseable_body_is_none(self):
        _init_async_globals()
        client = MagicMock()
        client.post = AsyncMock(return_value=_response(body="not a list"))
        assert await enrich_batch(["93.184.216.34"], client) is None

    async def test_an_empty_batch_is_not_a_failure(self):
        _init_async_globals()
        assert await enrich_batch([], MagicMock()) == ([], [])

    async def test_being_told_to_wait_is_not_a_failure(self):
        """A 429 is an instruction, not a fault: we waited as asked, so the
        backoff has nothing to add."""
        _init_async_globals()
        client = MagicMock()
        client.post = AsyncMock(return_value=_response(status=429, headers={"X-Ttl": "0"}))
        assert await enrich_batch(["93.184.216.34"], client) == ([], [])


class TestTheWorkerActuallyBacksOff:
    """Driving the loop itself, which had no test at all."""

    async def _run_with_failures(self, monkeypatch):
        slept: list[float] = []

        async def fake_sleep(seconds):
            slept.append(seconds)
            if len(slept) >= 4:
                raise asyncio.CancelledError()

        monkeypatch.setattr(enricher.asyncio, "sleep", fake_sleep)
        monkeypatch.setattr(enricher, "enrich_batch", AsyncMock(return_value=None))
        monkeypatch.setattr(enricher, "get_unenriched_ips", lambda conn, limit: ["93.184.216.34"])
        monkeypatch.setattr(enricher, "get_stale_ips", lambda *a: [])
        monkeypatch.setattr(enricher, "get_ip_intel_bulk", lambda conn, ips: {ips[0]: None})

        with pytest.raises(asyncio.CancelledError):
            await enricher.enrichment_worker(asyncio.Queue())
        return slept

    async def test_the_wait_grows_with_each_failed_batch(self, tmp_db, monkeypatch):
        slept = await self._run_with_failures(monkeypatch)
        assert slept == [10, 20, 40, 80], f"expected a doubling backoff, got {slept}"

    def test_the_backoff_curve_is_bounded(self):
        assert _error_backoff_s(1) == 10
        assert _error_backoff_s(6) == 300
        assert _error_backoff_s(99) == 300


class TestTheRateLimitHeaderIsNotTakenOnTrust:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("60", 61),
            (None, 61),
            ("nonsense", 61),
            ("-5", 1),
            ("0", 1),
            ("999999", 900),
        ],
        ids=["ordinary", "missing", "junk", "negative", "zero", "absurd"],
    )
    def test_it_is_clamped(self, header, expected):
        """A negative value made the wait a no-op and kept the worker hammering;
        a large one parked it for as long as the number said."""
        assert _rate_limit_pause(header) == expected


class TestShodanHasACeilingAndHonoursPushback:
    async def test_requests_are_spaced(self):
        gate = _RateGate(per_minute=600)  # one every 100 ms
        gate.reset()
        started = time.monotonic()
        await asyncio.gather(*[gate.wait() for _ in range(4)])
        elapsed = time.monotonic() - started
        assert elapsed >= 0.25, f"four requests should span three intervals, took {elapsed:.3f}s"

    async def test_no_ceiling_configured_means_no_wait(self):
        gate = _RateGate(per_minute=0)
        gate.reset()
        started = time.monotonic()
        await gate.wait()
        assert time.monotonic() - started < 0.05

    async def test_a_429_stops_the_calls_entirely(self):
        """Swallowed at DEBUG before, while the batch carried on at full rate."""
        _init_async_globals()
        resp = _response(status=429)
        client = MagicMock()
        client.get = AsyncMock(return_value=resp)

        assert await enricher._fetch_shodan("1.2.3.4", client) is None
        assert enricher._shodan_gate.in_cooldown()

        # The next lookup does not even reach the network.
        client.get.reset_mock()
        assert await enricher._fetch_shodan("5.6.7.8", client) is None
        client.get.assert_not_called()

    def test_the_cooldown_expires(self):
        gate = _RateGate(per_minute=600)
        gate.reset()
        gate.back_off(-1)
        assert not gate.in_cooldown()


class TestTheTorListIsNotRetriedEveryBatch:
    async def test_a_failed_download_is_not_retried_every_batch(self, caplog, monkeypatch):
        """_tor_exits_loaded_at was stamped only on success, so a failing
        download was attempted once per batch — about thirteen times a minute
        at torproject.org, for as long as the outage lasted.

        One call is three attempts now: a single ConnectError is usually a blip,
        and treating it as an outage cost five minutes of no Tor data. What must
        not happen is the *next* batch trying again, which is the whole point of
        the pause."""
        monkeypatch.setattr(enricher, "_TOR_RETRY_BACKOFF_S", 0)
        _init_async_globals()
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("no route"))

        with caplog.at_level(logging.WARNING, logger="vidar.enricher"):
            assert await _load_tor_exits(client) is None
        assert client.get.call_count == enricher._TOR_DOWNLOAD_ATTEMPTS
        assert "not retrying" in caplog.text
        assert "no list has ever loaded" in caplog.text, "say what the signal does meanwhile"

        for _ in range(5):
            assert await _load_tor_exits(client) is None
        assert client.get.call_count == enricher._TOR_DOWNLOAD_ATTEMPTS, "one round, not six"

    async def test_it_tries_again_once_the_pause_is_over(self, monkeypatch):
        monkeypatch.setattr(enricher, "_TOR_RETRY_BACKOFF_S", 0)
        _init_async_globals()
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("no route"))
        await _load_tor_exits(client)

        monkeypatch.setattr(enricher, "_tor_exits_failed_at", time.time() - 10_000)
        await _load_tor_exits(client)
        assert client.get.call_count == 2 * enricher._TOR_DOWNLOAD_ATTEMPTS

    async def test_a_blip_inside_one_call_still_loads(self, monkeypatch):
        """The reason the retry exists: one refused connection followed by a
        working one must produce a list, not a five-minute gap."""
        monkeypatch.setattr(enricher, "_TOR_RETRY_BACKOFF_S", 0)
        _init_async_globals()
        ok = MagicMock()
        ok.text = "1.2.3.4\n5.6.7.8\n"
        ok.raise_for_status = MagicMock()
        client = MagicMock()
        client.get = AsyncMock(side_effect=[httpx.ConnectError("blip"), ok])

        assert await _load_tor_exits(client) == {"1.2.3.4", "5.6.7.8"}
        assert client.get.call_count == 2
        assert enricher._tor_exits_failed_at == 0, "a recovered call is not a failure"

    async def test_the_last_list_survives_a_later_outage(self, monkeypatch, caplog):
        """What the operator actually cares about: Tor detection keeps working
        on yesterday's list rather than going blank."""
        monkeypatch.setattr(enricher, "_TOR_RETRY_BACKOFF_S", 0)
        _init_async_globals()
        ok = MagicMock()
        ok.text = "1.2.3.4\n"
        ok.raise_for_status = MagicMock()
        client = MagicMock()
        client.get = AsyncMock(return_value=ok)
        assert await _load_tor_exits(client) == {"1.2.3.4"}

        # The cache goes stale, and every attempt from now on fails.
        monkeypatch.setattr(enricher, "_tor_exits_loaded_at", time.time() - 10_000_000)
        client.get = AsyncMock(side_effect=httpx.ConnectError("no route"))
        with caplog.at_level(logging.WARNING, logger="vidar.enricher"):
            assert await _load_tor_exits(client) == {"1.2.3.4"}
        assert "keeping the 1 exits" in caplog.text


class TestQueuedIpsRespectTheCache:
    """seen_ips in the tailer is per-process, so every restart re-queues every
    active IP. Queue arrivals skipped the staleness check entirely: up to 50,000
    IPs re-enriched against ip-api and Shodan minutes after the last time, past
    a 30-day cache that already held the answers."""

    async def test_a_freshly_enriched_queued_ip_is_not_re_enriched(self, tmp_db, monkeypatch):
        from datetime import datetime, timezone

        from src.db import get_conn
        from src.queries import upsert_ip_intel

        with get_conn() as conn:
            upsert_ip_intel(
                conn,
                {
                    "ip": "93.184.216.34",
                    "country": "Germany",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                },
            )

        batch = AsyncMock(return_value=([], []))
        monkeypatch.setattr(enricher, "enrich_batch", batch)
        monkeypatch.setattr(enricher, "get_unenriched_ips", lambda conn, limit: [])
        monkeypatch.setattr(enricher, "get_stale_ips", lambda *a: [])

        async def fake_sleep(_seconds):
            raise asyncio.CancelledError()

        monkeypatch.setattr(enricher.asyncio, "sleep", fake_sleep)

        queue: asyncio.Queue = asyncio.Queue()
        queue.put_nowait("93.184.216.34")
        with pytest.raises(asyncio.CancelledError):
            await enricher.enrichment_worker(queue)

        batch.assert_not_called()

    async def test_a_stale_queued_ip_still_is(self, tmp_db, monkeypatch):
        from src.db import get_conn
        from src.queries import upsert_ip_intel

        with get_conn() as conn:
            upsert_ip_intel(
                conn,
                {
                    "ip": "93.184.216.34",
                    "country": "Germany",
                    "fetched_at": "2020-01-01T00:00:00+00:00",
                },
            )

        batch = AsyncMock(return_value=([], []))
        monkeypatch.setattr(enricher, "enrich_batch", batch)
        monkeypatch.setattr(enricher, "get_unenriched_ips", lambda conn, limit: [])
        monkeypatch.setattr(enricher, "get_stale_ips", lambda *a: [])

        async def fake_sleep(_seconds):
            raise asyncio.CancelledError()

        monkeypatch.setattr(enricher.asyncio, "sleep", fake_sleep)

        queue: asyncio.Queue = asyncio.Queue()
        queue.put_nowait("93.184.216.34")
        with pytest.raises(asyncio.CancelledError):
            await enricher.enrichment_worker(queue)

        batch.assert_called_once()
        assert batch.call_args[0][0] == ["93.184.216.34"]


class TestADnsLookupCannotParkTheWorker:
    async def test_the_wait_is_bounded(self, monkeypatch):
        """The resolver's own timeout governs the thread, which cannot be
        cancelled. What is bounded is how long the worker waits on it."""
        monkeypatch.setattr(enricher.settings, "dns_timeout_seconds", 0.05)

        async def never():
            await asyncio.sleep(30)

        started = time.monotonic()
        assert await enricher._with_dns_timeout(never(), "fallback") == "fallback"
        assert time.monotonic() - started < 1.0

    @patch("src.enricher._dnsbl_lookup")
    async def test_a_hanging_blocklist_yields_no_verdict(self, mock_lookup, monkeypatch):
        _init_async_globals()
        monkeypatch.setattr(enricher.settings, "dns_timeout_seconds", 0.05)
        mock_lookup.side_effect = lambda *a: time.sleep(5)
        assert await enricher._bounded_dnsbl_lookup("4.3.2.1", "zen.spamhaus.org") is None
