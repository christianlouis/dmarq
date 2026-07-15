import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_cancel_background_task_cancels_pending_task():
    from app.main import _cancel_background_task

    task = asyncio.create_task(asyncio.Event().wait())

    await _cancel_background_task(task, "test")

    assert task.cancelled()


@pytest.mark.asyncio
async def test_cancel_background_task_ignores_completed_task():
    from app.main import _cancel_background_task

    async def done():
        return "finished"

    task = asyncio.create_task(done())
    result = await task

    await _cancel_background_task(task, "test")

    assert task.done()
    assert result == "finished"
    assert task.result() == result


class TestNextSleepSeconds:
    def test_uses_shortest_enabled_source_interval_without_db_query(self):
        from app.main import _next_sleep_seconds

        slow = SimpleNamespace(polling_interval=30)
        fast = SimpleNamespace(polling_interval=5)

        with patch("app.main.SessionLocal") as mock_session:
            result = _next_sleep_seconds(enabled_sources=[slow, fast])

        assert result == 300
        mock_session.assert_not_called()

    def test_respects_min_sleep(self):
        from app.main import _next_sleep_seconds

        source = SimpleNamespace(polling_interval=1)

        assert _next_sleep_seconds(min_sleep=120, enabled_sources=[source]) == 120

    def test_queries_database_when_sources_not_supplied(self):
        from app.main import _next_sleep_seconds

        source = SimpleNamespace(polling_interval=2)
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [source]

        with patch("app.main.SessionLocal", return_value=mock_db):
            result = _next_sleep_seconds()

        assert result == 120
        mock_db.close.assert_called_once()

    def test_database_exception_falls_back_to_one_hour(self):
        from app.main import _next_sleep_seconds

        with patch("app.main.SessionLocal", side_effect=RuntimeError("db unavailable")):
            assert _next_sleep_seconds() == 3600


def test_poll_single_imap_source_passes_configured_folder():
    from app.main import _poll_single_imap_source

    source = SimpleNamespace(
        id=1,
        server="imap.example.com",
        port=993,
        username="u",
        password="p",
        folder="Junk Mail",
    )
    db = MagicMock()
    db.query.return_value.get.return_value = source
    results = {
        "success": True,
        "processed": 0,
        "reports_found": 0,
        "new_domains": [],
    }

    with (
        patch("app.main.SessionLocal", return_value=db),
        patch("app.main.IMAPClient") as mock_client_cls,
        patch("app.main.record_import_attempt"),
    ):
        mock_client_cls.return_value.fetch_reports.return_value = results

        _poll_single_imap_source(source)

    mock_client_cls.assert_called_once_with(
        server="imap.example.com",
        port=993,
        username="u",
        password="p",
        folder="Junk Mail",
        db=db,
        workspace_id=None,
    )
    db.commit.assert_called_once()
    db.close.assert_called_once()


def test_poll_single_m365_source_persists_import_state():
    from app.main import _poll_single_m365_source

    source = SimpleNamespace(
        id=2,
        m365_access_token="tok",
        m365_tenant_id="organizations",
        m365_client_id="cid",
        m365_client_secret="csec",
        m365_refresh_token="ref",
        m365_mailbox="shared@example.com",
        m365_ingested_ids="[]",
        folder="INBOX",
    )
    db_source = SimpleNamespace(**source.__dict__)
    db = MagicMock()
    db.query.return_value.get.return_value = db_source
    results = {
        "success": True,
        "processed": 1,
        "reports_found": 1,
        "new_domains": ["example.com"],
        "new_ingested_ids": ["message-1"],
    }

    with (
        patch("app.main.SessionLocal", return_value=db),
        patch("app.main.MicrosoftGraphClient") as mock_client_cls,
        patch("app.main.MicrosoftGraphClient.load_ingested_ids", return_value=[]),
        patch(
            "app.main.MicrosoftGraphClient.dump_ingested_ids",
            return_value='["message-1"]',
        ),
        patch("app.main.record_import_attempt"),
    ):
        mock_client = mock_client_cls.return_value
        mock_client.fetch_reports.return_value = results
        mock_client.get_refreshed_tokens.return_value = {
            "access_token": "new-tok",
            "refresh_token": "new-ref",
        }

        _poll_single_m365_source(source)

    assert db_source.m365_ingested_ids == '["message-1"]'
    assert db_source.m365_access_token == "new-tok"
    assert db_source.m365_refresh_token == "new-ref"
    mock_client.fetch_reports.assert_called_once_with(days=7)
    db.commit.assert_called_once()
    db.close.assert_called_once()


def test_poll_single_m365_source_skips_without_token():
    from app.main import _poll_single_m365_source

    source = SimpleNamespace(id=3, m365_access_token=None)

    with patch("app.main.SessionLocal") as mock_session:
        _poll_single_m365_source(source)

    mock_session.assert_not_called()


def test_run_due_mail_source_backfills_logs_processed_count():
    from app.main import _run_due_mail_source_backfills

    db = MagicMock()
    with (
        patch("app.main.SessionLocal", return_value=db),
        patch("app.main.run_due_mail_source_backfill_jobs", return_value=2) as run_due,
        patch("app.main.logger") as logger,
    ):
        assert _run_due_mail_source_backfills() == 2

    run_due.assert_called_once_with(db)
    logger.info.assert_called_once_with("Processed %d queued mail-source backfill job(s)", 2)
    db.close.assert_called_once()


def test_mailbox_scheduler_cycle_runs_blocking_work_in_order():
    from app.main import _run_mailbox_scheduler_cycle

    with (
        patch("app.main._poll_all_enabled_sources", return_value=["source"]) as poll,
        patch("app.main._run_due_mail_source_backfills", return_value=0) as backfills,
        patch("app.main._send_due_summary_notifications") as summaries,
        patch("app.main._deliver_due_webhook_events") as webhooks,
    ):
        assert _run_mailbox_scheduler_cycle() == ["source"]

    poll.assert_called_once_with()
    backfills.assert_called_once_with()
    summaries.assert_called_once_with()
    webhooks.assert_called_once_with()


@pytest.mark.asyncio
async def test_scheduled_imap_polling_sleep_exception_falls_back_then_cancels():
    from app.main import scheduled_imap_polling

    with (
        patch("app.main._poll_all_enabled_sources", return_value=[]),
        patch("app.main._run_due_mail_source_backfills", return_value=0),
        patch("app.main._next_sleep_seconds", return_value=60),
        patch(
            "app.main.asyncio.sleep",
            side_effect=[RuntimeError("sleep failed"), asyncio.CancelledError()],
        ),
    ):
        await scheduled_imap_polling()


@pytest.mark.asyncio
async def test_scheduled_polling_waits_until_http_startup_can_finish():
    from app.main import _scheduled_imap_polling_after_startup

    with (
        patch("app.main.asyncio.sleep") as sleep,
        patch("app.main.scheduled_imap_polling") as polling,
    ):
        await _scheduled_imap_polling_after_startup(0.25)

    sleep.assert_awaited_once_with(0.25)
    polling.assert_awaited_once_with()
