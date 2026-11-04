import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import app.main as main_module
import app.services.alert_rules as alert_rules
from app.models.alert import AlertHistory
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.report import DMARCReport, ReportRecord
from app.models.setting import Setting
from app.models.webhook import WebhookDelivery, WebhookEndpoint
from app.models.workspace import Workspace
from app.services.notifications import NotificationResult


def _seed_scheduled_alert(db_session):
    domain = Domain(name="scheduled-alert.example")
    db_session.add(domain)
    db_session.flush()
    now = int(datetime.now(timezone.utc).timestamp())
    report = DMARCReport(
        domain_id=domain.id,
        report_id="scheduled-alert-report",
        org_name="receiver.example",
        begin_date=now,
        end_date=now + 3600,
        policy="none",
    )
    db_session.add(report)
    db_session.flush()
    db_session.add(
        ReportRecord(
            report_id=report.id,
            source_ip="203.0.113.99",
            count=1,
            disposition="none",
            dkim="pass",
            spf="pass",
            header_from=domain.name,
        )
    )
    db_session.add_all(
        [
            Setting(key="notifications.apprise_enabled", value="true", category="notifications"),
            Setting(
                key="notifications.apprise_urls", value="fake://target", category="notifications"
            ),
            Setting(
                key="notifications.min_send_interval_minutes", value="5", category="notifications"
            ),
            Setting(
                key="notifications.alert_new_sources_enabled",
                value="true",
                category="notifications",
            ),
            Setting(
                key="notifications.alert_failure_threshold_enabled",
                value="false",
                category="notifications",
            ),
            Setting(
                key="notifications.alert_missing_reports_enabled",
                value="false",
                category="notifications",
            ),
            Setting(
                key="notifications.alert_compliance_drop_enabled",
                value="false",
                category="notifications",
            ),
        ]
    )
    db_session.commit()


def test_scheduler_delivers_alerts_and_retries_failed_apprise_send(db_session, monkeypatch):
    """Scheduled active alerts use Apprise and retry delivery failures."""
    _seed_scheduled_alert(db_session)
    outcomes = iter([True, False, True])
    notifications = []

    class FakeApprise:
        def add(self, url):
            assert url == "fake://target"
            return True

        def notify(self, *, title, body):
            notifications.append((title, body))
            return next(outcomes)

    monkeypatch.setattr(main_module, "SessionLocal", lambda: db_session)
    monkeypatch.setattr("app.services.notifications.apprise.Apprise", FakeApprise)
    with (
        patch.object(main_module, "_poll_all_enabled_sources", return_value=[]),
        patch.object(main_module, "_run_due_mail_source_backfills", return_value=0),
        patch.object(
            main_module,
            "_run_calm_watch_cycle",
            return_value={"sent": [], "suppressed": [], "resolved": []},
        ),
        patch.object(main_module, "_send_due_summary_notifications"),
        patch.object(main_module, "_deliver_due_webhook_events"),
    ):
        main_module._run_mailbox_scheduler_cycle()
        assert len(notifications) == 1

        main_module._run_mailbox_scheduler_cycle()
        assert len(notifications) == 1

        last_sent = db_session.query(Setting).filter_by(key="notifications.last_sent_at").one()
        old_value = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
        last_sent.value = old_value
        db_session.commit()
        main_module._run_mailbox_scheduler_cycle()
        assert len(notifications) == 2
        assert (
            db_session.query(Setting).filter_by(key="notifications.last_sent_at").one().value
            == old_value
        )

        main_module._run_mailbox_scheduler_cycle()

    assert len(notifications) == 3


def test_scheduler_scopes_alert_webhooks_per_workspace(db_session, monkeypatch):
    """Scheduled alerts retain owner routing while preserving legacy domains."""
    default = Workspace(slug="default", name="Default")
    first = Workspace(slug="first", name="First")
    second = Workspace(slug="second", name="Second")
    db_session.add_all([default, first, second])
    db_session.flush()
    db_session.add_all(
        [
            Domain(name="legacy.example"),
            Domain(name="first.example", workspace_id=first.id),
            Domain(name="second.example", workspace_id=second.id),
            Setting(key="notifications.apprise_enabled", value="true", category="notifications"),
            Setting(
                key="notifications.apprise_urls", value="fake://target", category="notifications"
            ),
            Setting(
                key="notifications.alert_new_sources_enabled",
                value="false",
                category="notifications",
            ),
            Setting(
                key="notifications.alert_failure_threshold_enabled",
                value="false",
                category="notifications",
            ),
            Setting(
                key="notifications.alert_missing_reports_enabled",
                value="true",
                category="notifications",
            ),
            Setting(
                key="notifications.alert_missing_reports_days", value="2", category="notifications"
            ),
            Setting(
                key="notifications.alert_compliance_drop_enabled",
                value="false",
                category="notifications",
            ),
        ]
    )
    db_session.add_all(
        [
            WebhookEndpoint(
                workspace_id=default.id,
                name="default endpoint",
                url="https://default.example/hook",
                secret="default-secret",
                event_types="dmarq.reports.missing",
                enabled=True,
            ),
            WebhookEndpoint(
                workspace_id=first.id,
                name="first endpoint",
                url="https://first.example/hook",
                secret="first-secret",
                event_types="dmarq.reports.missing",
                enabled=True,
            ),
            WebhookEndpoint(
                workspace_id=second.id,
                name="second endpoint",
                url="https://second.example/hook",
                secret="second-secret",
                event_types="dmarq.reports.missing",
                enabled=True,
            ),
        ]
    )
    db_session.commit()
    default_id, first_id, second_id = default.id, first.id, second.id

    # This mirrors history recorded before workspace ownership was added to
    # alert payloads. It must be updated, not resolved and recreated.
    from app.services.alert_history import record_alert_evaluation

    record_alert_evaluation(
        db_session,
        [
            {
                "rule": "missing_reports",
                "severity": "warning",
                "domain": "legacy.example",
                "title": "DMARC reports missing",
                "detail": "No DMARC aggregate report for legacy.example in the last 2 day(s).",
            }
        ],
    )

    notifications = []

    class FakeApprise:
        def add(self, url):
            assert url == "fake://target"
            return True

        def notify(self, *, title, body):
            notifications.append((title, body))
            return True

    monkeypatch.setattr(main_module, "SessionLocal", lambda: db_session)
    monkeypatch.setattr("app.services.notifications.apprise.Apprise", FakeApprise)
    main_module._send_current_alert_notifications()

    deliveries = db_session.query(WebhookDelivery).all()
    assert len(deliveries) == 3
    assert len(notifications) == 1
    assert "legacy.example" in notifications[0][1]
    assert "first.example" in notifications[0][1]
    assert "second.example" in notifications[0][1]
    assert db_session.query(AlertHistory).filter(AlertHistory.is_active.is_(True)).count() == 3
    payloads = {delivery.endpoint_id: json.loads(delivery.payload) for delivery in deliveries}
    endpoints = {endpoint.id: endpoint for endpoint in db_session.query(WebhookEndpoint).all()}
    assert {
        (
            endpoints[endpoint_id].workspace_id,
            payload["data"]["domain"],
            payload["data"]["workspace_id"],
        )
        for endpoint_id, payload in payloads.items()
    } == {
        (default_id, "legacy.example", None),
        (first_id, "first.example", first_id),
        (second_id, "second.example", second_id),
    }

    main_module._send_current_alert_notifications()
    assert len(db_session.query(WebhookDelivery).all()) == 3
    assert len(notifications) == 1
    assert db_session.query(AlertHistory).filter(AlertHistory.is_active.is_(True)).count() == 3
    legacy_history = (
        db_session.query(AlertHistory).filter(AlertHistory.domain == "legacy.example").one()
    )
    assert legacy_history.observed_count == 3


def test_alert_webhook_keys_preserve_legacy_dedupe_and_bound_long_details(db_session):
    """Legacy short keys remain stable while new keys fit delivery storage."""
    workspace = Workspace(slug="default", name="Default")
    db_session.add(workspace)
    db_session.flush()
    db_session.add(
        WebhookEndpoint(
            workspace_id=workspace.id,
            name="default endpoint",
            url="https://default.example/hook",
            secret="default-secret",
            event_types="dmarq.alert.created",
            enabled=True,
        )
    )
    db_session.commit()

    alert = {
        "rule": "custom",
        "domain": "legacy.example",
        "detail": "stable",
        "workspace_id": None,
    }
    alert_rules.enqueue_alert_webhook_events(db_session, [alert])
    alert_rules.enqueue_alert_webhook_events(db_session, [alert])
    deliveries = db_session.query(WebhookDelivery).all()
    assert len(deliveries) == 1
    assert deliveries[0].idempotency_key == "dmarq.alert.created:legacy.example:custom:stable"
    alert["workspace_id"] = workspace.id
    alert_rules.enqueue_alert_webhook_events(db_session, [alert])
    assert db_session.query(WebhookDelivery).count() == 1

    long_alert = {
        "rule": "custom",
        "domain": "legacy.example",
        "detail": "x" * 500,
        "workspace_id": None,
    }
    alert_rules.enqueue_alert_webhook_events(db_session, [long_alert])
    long_delivery = db_session.query(WebhookDelivery).order_by(WebhookDelivery.id.desc()).first()
    assert long_delivery is not None
    assert len(long_delivery.idempotency_key) == 160
    alert_rules.enqueue_alert_webhook_events(db_session, [long_alert])
    assert db_session.query(WebhookDelivery).count() == 2
    assert (
        db_session.query(WebhookDelivery)
        .order_by(WebhookDelivery.id.desc())
        .first()
        .idempotency_key
        == long_delivery.idempotency_key
    )


def test_alert_webhook_failure_rolls_back_before_next_alert_cycle(db_session, monkeypatch):
    """A failed enqueue does not poison the session or block the next alert send."""
    workspace = Workspace(slug="default", name="Default")
    db_session.add(workspace)
    db_session.flush()
    endpoint = WebhookEndpoint(
        workspace_id=workspace.id,
        name="default endpoint",
        url="https://default.example/hook",
        secret="default-secret",
        event_types="dmarq.alert.created",
        enabled=True,
    )
    db_session.add(endpoint)
    db_session.commit()
    alert = {
        "rule": "custom",
        "domain": "recover.example",
        "detail": "recover",
        "title": "Recovery alert",
        "workspace_id": None,
    }
    monkeypatch.setattr(alert_rules, "evaluate_alert_rules", lambda db: [alert])
    monkeypatch.setattr(
        alert_rules,
        "send_notification",
        lambda *args, **kwargs: NotificationResult(success=True, message="sent"),
    )
    original_enqueue = alert_rules.enqueue_webhook_event
    failed = {"value": True}

    def flaky_enqueue(*args, **kwargs):
        if failed["value"]:
            failed["value"] = False
            db_session.add(
                WebhookDelivery(
                    endpoint_id=None,
                    event_type="dmarq.alert.created",
                    payload="{}",
                    idempotency_key="poisoned-before-rollback",
                    status="pending",
                    max_attempts=5,
                )
            )
            db_session.flush()
        return original_enqueue(*args, **kwargs)

    monkeypatch.setattr(alert_rules, "enqueue_webhook_event", flaky_enqueue)
    first = alert_rules.send_current_alerts(db_session)
    history = db_session.query(AlertHistory).filter(AlertHistory.domain == "recover.example").one()
    assert history.is_active is True
    second = alert_rules.send_current_alerts(db_session)

    assert first["notification"]["success"] is True
    assert second["notification"]["success"] is True
    assert db_session.query(WebhookDelivery).count() == 1


def test_migrate_imap_env_uses_configured_folder_and_is_idempotent(db_session, monkeypatch):
    monkeypatch.setattr(main_module.settings, "IMAP_SERVER", "imap.example.com")
    monkeypatch.setattr(main_module.settings, "IMAP_USERNAME", "reports@example.com")
    monkeypatch.setattr(main_module.settings, "IMAP_PASSWORD", "secret")
    monkeypatch.setattr(main_module.settings, "IMAP_FOLDER", "Archive / DMARC")
    monkeypatch.setattr(main_module, "SessionLocal", lambda: db_session)

    main_module._migrate_imap_env_vars_to_db()
    source = db_session.query(MailSource).one()
    assert source.folder == "Archive / DMARC"

    main_module._migrate_imap_env_vars_to_db()
    assert db_session.query(MailSource).count() == 1
    assert db_session.query(MailSource).one().folder == "Archive / DMARC"


def test_migrate_imap_env_missing_folder_falls_back_to_inbox(db_session, monkeypatch):
    monkeypatch.setattr(main_module.settings, "IMAP_SERVER", "imap.example.com")
    monkeypatch.setattr(main_module.settings, "IMAP_USERNAME", "reports@example.com")
    monkeypatch.setattr(main_module.settings, "IMAP_PASSWORD", "secret")
    monkeypatch.setattr(main_module.settings, "IMAP_FOLDER", None)
    monkeypatch.setattr(main_module, "SessionLocal", lambda: db_session)

    main_module._migrate_imap_env_vars_to_db()

    assert db_session.query(MailSource).one().folder == "INBOX"


@pytest.mark.asyncio
async def test_cancel_background_task_cancels_pending_task():
    _cancel_background_task = main_module._cancel_background_task

    task = asyncio.create_task(asyncio.Event().wait())

    await _cancel_background_task(task, "test")

    assert task.cancelled()


@pytest.mark.asyncio
async def test_cancel_background_task_ignores_completed_task():
    _cancel_background_task = main_module._cancel_background_task

    async def done():
        return "finished"

    task = asyncio.create_task(done())
    result = await task

    await _cancel_background_task(task, "test")

    assert task.done()
    assert result == "finished"
    assert task.result() == result


class TestNextSleepSeconds:
    @pytest.mark.parametrize("min_sleep, expected", [(60, 3600), (7200, 7200)])
    def test_empty_sources_default_to_one_hour(self, min_sleep, expected):
        _next_sleep_seconds = main_module._next_sleep_seconds

        with patch("app.main.SessionLocal") as mock_session:
            result = _next_sleep_seconds(min_sleep=min_sleep, enabled_sources=[])

        assert result == expected
        mock_session.assert_not_called()

    def test_empty_database_defaults_to_one_hour(self):
        _next_sleep_seconds = main_module._next_sleep_seconds

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = []

        with patch("app.main.SessionLocal", return_value=mock_db):
            result = _next_sleep_seconds()

        assert result == 3600
        mock_db.close.assert_called_once()

    @pytest.mark.parametrize("interval", [None, 0, 60])
    def test_source_default_interval_is_one_hour(self, interval):
        _next_sleep_seconds = main_module._next_sleep_seconds

        source = SimpleNamespace(polling_interval=interval)

        assert _next_sleep_seconds(enabled_sources=[source]) == 3600

    def test_uses_shortest_enabled_source_interval_without_db_query(self):
        _next_sleep_seconds = main_module._next_sleep_seconds

        slow = SimpleNamespace(polling_interval=30)
        fast = SimpleNamespace(polling_interval=5)

        with patch("app.main.SessionLocal") as mock_session:
            result = _next_sleep_seconds(enabled_sources=[slow, fast])

        assert result == 300
        mock_session.assert_not_called()

    def test_respects_min_sleep(self):
        _next_sleep_seconds = main_module._next_sleep_seconds

        source = SimpleNamespace(polling_interval=1)

        assert _next_sleep_seconds(min_sleep=120, enabled_sources=[source]) == 120

    def test_queries_database_when_sources_not_supplied(self):
        _next_sleep_seconds = main_module._next_sleep_seconds

        source = SimpleNamespace(polling_interval=2)
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [source]

        with patch("app.main.SessionLocal", return_value=mock_db):
            result = _next_sleep_seconds()

        assert result == 120
        mock_db.close.assert_called_once()

    def test_database_exception_falls_back_to_one_hour(self):
        _next_sleep_seconds = main_module._next_sleep_seconds

        with patch("app.main.SessionLocal", side_effect=RuntimeError("db unavailable")):
            assert _next_sleep_seconds() == 3600


def test_poll_single_imap_source_passes_configured_folder():
    _poll_single_imap_source = main_module._poll_single_imap_source

    source = SimpleNamespace(
        id=1,
        server="imap.example.com",
        port=993,
        username="u",
        password="p",
        use_ssl=True,
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
        use_ssl=True,
        folder="Junk Mail",
        db=db,
        workspace_id=None,
        incremental=True,
        last_uid=None,
        uid_validity=None,
        uid_account=None,
        uid_folder=None,
        uid_server=None,
        uid_port=None,
        uid_use_ssl=None,
    )
    db.commit.assert_called_once()
    db.close.assert_called_once()


def test_poll_single_imap_source_persists_uid_cursor():
    """A scheduled poll resumes from, and then advances, the stored UID cursor."""
    _poll_single_imap_source = main_module._poll_single_imap_source

    source = SimpleNamespace(
        id=1,
        server="imap.example.com",
        port=993,
        username="u",
        password="p",
        use_ssl=True,
        folder="INBOX",
        last_uid=11,
        uid_validity=42,
        uid_account="u",
        uid_folder="INBOX",
        uid_server="imap.example.com",
        uid_port=993,
        uid_use_ssl=True,
    )
    db = MagicMock()
    db.query.return_value.get.return_value = source
    results = {
        "success": True,
        "processed": 1,
        "reports_found": 1,
        "new_domains": [],
        "last_uid": 12,
        "uid_validity": 42,
        "uid_account": "u",
        "uid_folder": "INBOX",
        "uid_server": "imap.example.com",
        "uid_port": 993,
        "uid_use_ssl": True,
    }

    with (
        patch("app.main.SessionLocal", return_value=db),
        patch("app.main.IMAPClient") as mock_client_cls,
        patch("app.main.record_import_attempt"),
    ):
        mock_client_cls.return_value.fetch_reports.return_value = results

        _poll_single_imap_source(source)

    assert mock_client_cls.call_args.kwargs["last_uid"] == 11
    assert mock_client_cls.call_args.kwargs["uid_validity"] == 42
    assert source.last_uid == 12
    assert source.uid_validity == 42
    assert source.uid_server == "imap.example.com"


def test_poll_single_imap_source_keeps_cursor_when_poll_fails():
    """A failed poll must not clear the cursor and force a full rescan later."""
    _poll_single_imap_source = main_module._poll_single_imap_source

    source = SimpleNamespace(
        id=1,
        server="imap.example.com",
        port=993,
        username="u",
        password="p",
        use_ssl=True,
        folder="INBOX",
        last_uid=11,
        uid_validity=42,
    )
    db = MagicMock()
    db.query.return_value.get.return_value = source

    with (
        patch("app.main.SessionLocal", return_value=db),
        patch("app.main.IMAPClient") as mock_client_cls,
        patch("app.main.record_import_attempt"),
    ):
        mock_client_cls.return_value.fetch_reports.return_value = {
            "success": False,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "error": "boom",
        }

        _poll_single_imap_source(source)

    assert source.last_uid == 11
    assert source.uid_validity == 42


def test_poll_single_m365_source_persists_import_state():
    _poll_single_m365_source = main_module._poll_single_m365_source

    source = SimpleNamespace(
        id=2,
        method="M365_GRAPH",
        workspace_id=1,
        m365_access_token="tok",
        m365_tenant_id="organizations",
        m365_client_id="cid",
        m365_client_secret="csec",
        m365_refresh_token="ref",
        m365_mailbox="shared@example.com",
        m365_auth_mode="delegated",
        m365_folder_id="",
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
    _poll_single_m365_source = main_module._poll_single_m365_source

    source = SimpleNamespace(id=3, m365_access_token=None)

    with patch("app.main.SessionLocal") as mock_session:
        _poll_single_m365_source(source)

    mock_session.assert_not_called()


def test_poll_single_m365_application_source_runs_without_stored_token():
    _poll_single_m365_source = main_module._poll_single_m365_source

    source = SimpleNamespace(
        id=4,
        method="M365_GRAPH",
        workspace_id=1,
        m365_auth_mode="application",
        m365_access_token=None,
        m365_tenant_id="tenant-id",
        m365_client_id="client-id",
        m365_client_secret="client-secret",
        m365_refresh_token=None,
        m365_mailbox="dmarc-reports@example.com",
        m365_folder_id="",
        m365_ingested_ids="[]",
        folder="INBOX",
    )
    db_source = SimpleNamespace(**source.__dict__)
    db = MagicMock()
    db.query.return_value.get.return_value = db_source

    with (
        patch("app.main.SessionLocal", return_value=db),
        patch("app.main.MicrosoftGraphClient") as client_cls,
        patch("app.main.MicrosoftGraphClient.load_ingested_ids", return_value=[]),
        patch("app.main.record_import_attempt"),
    ):
        client_cls.return_value.fetch_reports.return_value = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "new_ingested_ids": [],
        }
        client_cls.return_value.get_refreshed_tokens.return_value = {
            "access_token": "new-application-token"
        }

        _poll_single_m365_source(source)

    _, kwargs = client_cls.call_args
    assert kwargs["auth_mode"] == "application"
    assert kwargs["access_token"] is None
    assert kwargs["mailbox"] == "dmarc-reports@example.com"
    assert db_source.m365_access_token == "new-application-token"
    db.commit.assert_called_once()
    db.close.assert_called_once()


def test_run_due_mail_source_backfills_logs_processed_count():
    _run_due_mail_source_backfills = main_module._run_due_mail_source_backfills

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
    _run_mailbox_scheduler_cycle = main_module._run_mailbox_scheduler_cycle

    with (
        patch("app.main._poll_all_enabled_sources", return_value=["source"]) as poll,
        patch("app.main._run_due_mail_source_backfills", return_value=0) as backfills,
        patch(
            "app.main._run_calm_watch_cycle",
            return_value={"sent": [], "suppressed": [], "resolved": []},
        ) as calm_watch,
        patch("app.main._send_due_summary_notifications") as summaries,
        patch("app.main._send_current_alert_notifications") as alerts,
        patch("app.main._deliver_due_webhook_events") as webhooks,
    ):
        assert _run_mailbox_scheduler_cycle() == ["source"]

    poll.assert_called_once_with()
    backfills.assert_called_once_with()
    calm_watch.assert_called_once_with()
    summaries.assert_called_once_with()
    alerts.assert_called_once_with()
    webhooks.assert_called_once_with()


@pytest.mark.asyncio
async def test_scheduled_polling_without_sources_sleeps_for_one_hour():
    scheduled_imap_polling = main_module.scheduled_imap_polling

    with (
        patch("app.main._run_mailbox_scheduler_cycle", return_value=[]) as cycle,
        patch("app.main.asyncio.sleep", side_effect=asyncio.CancelledError()) as sleep,
        patch("app.main.mark_scheduler_cycle_started"),
        patch("app.main.mark_scheduler_success"),
        patch("app.main.mark_scheduler_stopped"),
    ):
        await scheduled_imap_polling()

    cycle.assert_called_once_with()
    sleep.assert_awaited_once_with(3600)


@pytest.mark.asyncio
async def test_scheduled_imap_polling_sleep_exception_falls_back_then_cancels():
    scheduled_imap_polling = main_module.scheduled_imap_polling

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
    _scheduled_imap_polling_after_startup = main_module._scheduled_imap_polling_after_startup

    with (
        patch("app.main.asyncio.sleep") as sleep,
        patch("app.main.scheduled_imap_polling") as polling,
    ):
        await _scheduled_imap_polling_after_startup(0.25)

    sleep.assert_awaited_once_with(0.25)
    polling.assert_awaited_once_with()
