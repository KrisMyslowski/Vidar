"""Failures that leave no trace are the reason the rest went unnoticed.

Three of them, all of the same kind — the code handles the error correctly and
then says nothing an operator would ever see:

  * a log line that will not parse is dropped at DEBUG under an INFO root
    logger, and the offset moves past it. A changed nginx log_format drops
    every line, forever, and the dashboard simply looks quiet.
  * a Shodan lookup that times out is a DEBUG line per IP. Now that silence no
    longer erases stored data (see test_enrichment_is_not_destructive.py),
    nothing else would reveal a day-long outage either.
  * a background task that dies has its exception retrieved by
    gather(return_exceptions=True) at shutdown and thrown away.
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src import log_processor as lp
from src.db import get_conn
from src.log_processor import _report_unparseable
from src.queries import get_state


async def _drive(seconds: float = 0.4) -> None:
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    task = asyncio.create_task(lp.tail_log(queue))
    await asyncio.sleep(seconds)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


class TestABatchWeCannotReadSaysSo:
    def test_a_readable_batch_is_quiet(self):
        assert _report_unparseable(100, 3, False) is False

    def test_a_mostly_unreadable_batch_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            assert _report_unparseable(10, 9, False) is True
        assert "9 of 10 log lines could not be parsed" in caplog.text
        assert "nginx-log-format.conf" in caplog.text, "name the file to compare against"

    def test_it_warns_once_per_run_not_once_per_poll(self, caplog):
        """A one-second poll would otherwise turn a format mismatch into a line
        of log per second, which is its own kind of invisible."""
        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            warned = _report_unparseable(10, 10, False)
            for _ in range(5):
                warned = _report_unparseable(10, 10, warned)
        assert caplog.text.count("could not be parsed") == 1

    def test_a_good_batch_rearms_the_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            warned = _report_unparseable(10, 10, False)
            warned = _report_unparseable(10, 0, warned)  # recovered
            _report_unparseable(10, 10, warned)  # broke again
        assert caplog.text.count("could not be parsed") == 2


class TestAChangedLogFormatIsNotSilent:
    """The scenario: nginx emits `"status":,` — unquoted and empty, which is
    what deploy/nginx-log-format.conf produces when $status is unset.
    Every line is invalid JSON. Before, the tailer drained the file, advanced
    the offset and logged nothing at all."""

    async def test_it_warns_and_still_advances(self, fast_log, caplog):
        broken = '{"time":"2026-06-13T10:00:00+00:00","remote_addr":"1.2.3.4","status":,}\n'
        fast_log.write_text(broken * 20)

        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            await _drive()

        assert "could not be parsed" in caplog.text, "a format change must be visible"
        with get_conn() as conn:
            assert conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0] == 0
            # Still advances: unreadable bytes are consumed, not retried forever.
            assert int(get_state(conn, "file_offset")) == len(broken) * 20

    async def test_a_readable_log_says_nothing(self, fast_log, caplog):
        good = (
            json.dumps(
                {
                    "time": "2026-06-13T10:00:00+00:00",
                    "remote_addr": "93.184.216.34",
                    "request": "GET /p HTTP/1.1",
                    "status": 200,
                    "body_bytes_sent": 10,
                    "http_user_agent": "Mozilla/5.0",
                    "request_method": "GET",
                    "request_uri": "/p",
                }
            )
            + "\n"
        )
        fast_log.write_text(good * 5)

        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            await _drive()

        assert "could not be parsed" not in caplog.text
        with get_conn() as conn:
            assert conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0] == 5


class TestAShortenedLogFormatIsNotSilent:
    """The other way a log_format goes wrong. Dropping a required field breaks
    every line, which the class above catches; dropping one of the nineteen
    optional ones breaks nothing visible — the lines parse and a feature is
    gone, deduplication without $connection being the expensive case."""

    def test_the_full_format_says_nothing(self):
        assert lp._missing_field_report(frozenset(lp.LogEntry.model_fields)) is None

    def test_a_missing_field_is_named_with_its_cost(self):
        keys = frozenset(lp.LogEntry.model_fields) - {"connection", "connection_requests"}
        report = lp._missing_field_report(keys)
        assert "connection" in report and "connection_requests" in report
        assert "deduplication is inactive" in report
        assert "nginx-log-format.conf" in report

    def test_each_group_names_its_own_consequence(self):
        for fields, note in lp._FIELD_CONSEQUENCES:
            keys = frozenset(lp.LogEntry.model_fields) - {fields[0]}
            assert note in lp._missing_field_report(keys)

    async def test_the_tailer_reports_it_once(self, fast_log, caplog):
        line = (
            json.dumps(
                {
                    "time": "2026-06-13T10:00:00+00:00",
                    "remote_addr": "93.184.216.34",
                    "request": "GET /p HTTP/1.1",
                    "status": 200,
                    "body_bytes_sent": 10,
                }
            )
            + "\n"
        )
        fast_log.write_text(line * 5)

        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            await _drive()

        assert caplog.text.count("Log lines are missing") == 1
        assert "connection" in caplog.text
        with get_conn() as conn:
            assert conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0] == 5


class TestALogItCannotOpenSaysSo:
    """A bad mount, a typo in LOG_PATH and a file UID 1000 cannot read are
    indistinguishable from a half-second rotation, so the tailer swallowed all
    four and span once a second, forever, saying nothing."""

    async def test_a_brief_absence_stays_quiet(self, fast_log, caplog, monkeypatch):
        monkeypatch.setattr(lp, "_OPEN_FAILURE_QUIET_S", 30.0)
        monkeypatch.setattr(lp.settings, "log_path", fast_log.parent / "not-here.log")

        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            await _drive(0.2)

        assert "Cannot read" not in caplog.text

    async def test_a_lasting_one_is_named(self, fast_log, caplog, monkeypatch):
        missing = fast_log.parent / "not-here.log"
        monkeypatch.setattr(lp, "_OPEN_FAILURE_QUIET_S", 0.05)
        monkeypatch.setattr(lp.settings, "log_path", missing)

        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            await _drive(0.4)

        assert caplog.text.count("Cannot read") == 1, "once per run of failures, not per poll"
        assert str(missing) in caplog.text
        assert "UID 1000" in caplog.text


class TestShodanSilenceIsCounted:
    def test_a_full_outage_warns(self, caplog):
        from src.enricher import _report_shodan_silence

        with caplog.at_level(logging.INFO, logger="vidar.enricher"):
            _report_shodan_silence(50, 50)
        assert "Shodan did not answer 50 of 50" in caplog.text
        assert caplog.records[-1].levelno == logging.WARNING

    def test_a_few_timeouts_are_only_noted(self, caplog):
        from src.enricher import _report_shodan_silence

        with caplog.at_level(logging.INFO, logger="vidar.enricher"):
            _report_shodan_silence(2, 50)
        assert caplog.records[-1].levelno == logging.INFO

    def test_nothing_silent_says_nothing(self, caplog):
        from src.enricher import _report_shodan_silence

        with caplog.at_level(logging.INFO, logger="vidar.enricher"):
            _report_shodan_silence(0, 50)
        assert caplog.text == ""

    async def test_rate_limiting_is_named(self, caplog):
        """A 429 is the one Shodan failure we cause ourselves, so the summary
        distinguishes it from a timeout."""
        import src.enricher as enricher

        resp = MagicMock()
        resp.status_code = 429
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "too many", request=MagicMock(), response=MagicMock()
        )
        client = MagicMock()
        client.get = AsyncMock(return_value=resp)

        enricher._shodan_rate_limited = False
        try:
            assert await enricher._fetch_shodan("1.2.3.4", client) is None
            with caplog.at_level(logging.INFO, logger="vidar.enricher"):
                enricher._report_shodan_silence(1, 1)
            assert "rate-limited" in caplog.text
        finally:
            enricher._shodan_rate_limited = False


class TestABackgroundTaskThatDiesIsReported:
    async def test_the_backfill_logs_its_own_failure(self, caplog):
        """It was the one task with no handler at all."""
        from src.main import _backfill_task

        with patch("src.main._backfill", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("database is locked")
            with caplog.at_level(logging.ERROR, logger="vidar.main"):
                await _backfill_task()

        assert "Classifier backfill failed" in caplog.text
        assert "database is locked" in caplog.text

    async def test_cancellation_is_not_an_error(self, caplog):
        from src.main import _backfill_task

        with patch("src.main._backfill", new_callable=AsyncMock) as mock:
            mock.side_effect = asyncio.CancelledError()
            with pytest.raises(asyncio.CancelledError):
                await _backfill_task()
        assert caplog.text == ""

    async def test_shutdown_names_the_task_that_ended_badly(self, caplog):
        """gather(return_exceptions=True) retrieves the exception, and that is
        the last moment anything can say it happened. Drives the same function
        the lifespan calls, on what gather really hands back — including a
        cancellation, which must stay quiet."""
        from src.main import _report_task_exits

        async def dies():
            raise RuntimeError("disk full")

        async def sleeps():
            await asyncio.sleep(3600)

        doomed = asyncio.create_task(dies())
        sleeper = asyncio.create_task(sleeps())
        await asyncio.sleep(0)
        sleeper.cancel()
        results = await asyncio.gather(doomed, sleeper, return_exceptions=True)

        with caplog.at_level(logging.ERROR, logger="vidar.main"):
            _report_task_exits(["log tailer", "retention"], results)

        assert "log tailer" in caplog.text and "disk full" in caplog.text
        assert "retention" not in caplog.text, "an ordinary cancellation is not an error"


class TestANonUtcHostIsReported:
    """Visit timestamps are stored exactly as nginx wrote them and compared as
    text against bounds derived from UTC. On a host that is not UTC every window
    on the dashboard and every retention boundary is off by the offset —
    silently. nginx-log-format.conf says the host must run UTC; saying it in a
    file the service cannot read is not the same as knowing."""

    @pytest.mark.parametrize(
        "stamp",
        ["2026-06-13T10:00:00+00:00", "2026-06-13T10:00:00-00:00", "2026-06-13T10:00:00Z"],
        ids=["plus-zero", "minus-zero", "zulu"],
    )
    def test_utc_is_recognised(self, stamp):
        assert lp._is_utc(stamp) is True

    @pytest.mark.parametrize(
        "stamp",
        ["2026-06-13T10:00:00+02:00", "2026-06-13T10:00:00-05:00", "2026-06-13T10:00:00+05:30"],
        ids=["berlin", "new-york", "kolkata"],
    )
    def test_an_offset_is_not(self, stamp):
        assert lp._is_utc(stamp) is False

    def test_a_batch_of_them_warns_once(self, caplog):
        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            warned = lp._report_local_time(10, 10, False)
            for _ in range(4):
                warned = lp._report_local_time(10, 10, warned)
        assert caplog.text.count("non-UTC timestamp") == 1
        assert "nginx-log-format.conf" in caplog.text

    def test_a_utc_host_says_nothing(self, caplog):
        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            assert lp._report_local_time(10, 0, False) is False
        assert caplog.text == ""

    async def test_the_tailer_reports_it(self, fast_log, caplog):
        line = json.dumps(
            {
                "time": "2026-06-13T10:00:00+02:00",
                "remote_addr": "93.184.216.34",
                "request": "GET / HTTP/1.1",
                "status": 200,
                "body_bytes_sent": 10,
                "http_user_agent": "Mozilla/5.0",
                "request_method": "GET",
                "request_uri": "/",
            }
        )
        fast_log.write_text((line + "\n") * 5)

        with caplog.at_level(logging.WARNING, logger="vidar.log_processor"):
            await _drive()

        assert "non-UTC timestamp" in caplog.text
        with get_conn() as conn:
            assert (
                conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0] == 5
            ), "the visits are still ingested — this is a warning, not a filter"
