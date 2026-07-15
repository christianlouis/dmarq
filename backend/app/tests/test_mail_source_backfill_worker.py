import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from app.models.mail_source import MailSource
from app.models.mail_source_backfill import MailSourceBackfillJob
from app.models.mail_source_import import MailSourceImport
from app.services.mail_source_backfill_worker import (
    _backfill_window_days,
    _mark_failure,
    _retry_delay,
    run_due_imap_backfill_jobs,
    run_due_mail_source_backfill_jobs,
    run_gmail_backfill_job,
    run_imap_backfill_job,
    run_m365_backfill_job,
    run_mail_source_backfill_job,
    run_mail_source_backfill_job_by_id,
)
from app.services.workspaces import get_or_create_default_workspace


def _source(db_session, *, method="IMAP", enabled=True):
    workspace = get_or_create_default_workspace(db_session)
    source = MailSource(
        workspace_id=workspace.id,
        name=f"{method} Backfill",
        method=method,
        server="imap.example.com",
        port=993,
        username="reports@example.com",
        password="secret",
        folder="INBOX/DMARC",
        enabled=enabled,
        gmail_client_id="gmail-client",
        gmail_client_secret="gmail-secret",
        gmail_access_token="gmail-token" if method == "GMAIL_API" else None,
        gmail_refresh_token="gmail-refresh" if method == "GMAIL_API" else None,
        gmail_ingested_ids='["old-id"]' if method == "GMAIL_API" else None,
        m365_tenant_id="organizations",
        m365_client_id="m365-client",
        m365_client_secret="m365-secret",
        m365_access_token="m365-token" if method == "M365_GRAPH" else None,
        m365_refresh_token="m365-refresh" if method == "M365_GRAPH" else None,
        m365_mailbox="shared@example.com",
        m365_ingested_ids='["old-m365-id"]' if method == "M365_GRAPH" else None,
    )
    db_session.add(source)
    db_session.commit()
    return workspace, source


def _job(db_session, workspace, source, **overrides):
    values = {
        "workspace_id": workspace.id,
        "mail_source_id": source.id,
        "status": "queued",
        "requested_start": datetime(2026, 1, 1),
        "requested_end": datetime(2026, 1, 11),
        "max_attempts": 3,
    }
    values.update(overrides)
    row = MailSourceBackfillJob(**values)
    db_session.add(row)
    db_session.commit()
    return row


def test_run_due_imap_backfill_completes_job_and_records_import(db_session, monkeypatch):
    workspace, source = _source(db_session)
    row = _job(db_session, workspace, source)
    results = {
        "success": True,
        "processed": 12,
        "reports_found": 4,
        "duplicate_reports": 1,
        "new_domains": ["example.com"],
        "errors": [],
        "details": [{"status": "imported", "domain": "example.com"}],
    }

    class FakeIMAPClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def fetch_reports(self, days, progress_callback=None):
            assert days == 10
            if progress_callback:
                progress_callback({**results, "processed": 5, "total_messages": 12})
            return results

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.IMAPClient",
        FakeIMAPClient,
    )

    assert run_due_imap_backfill_jobs(db_session, limit=1) == 1

    db_session.refresh(row)
    db_session.refresh(source)
    attempt = db_session.query(MailSourceImport).filter_by(mail_source_id=source.id).one()

    assert row.status == "completed"
    assert row.attempt_count == 1
    assert row.processed == 12
    assert row.reports_found == 4
    assert row.duplicate_reports == 1
    cursor = json.loads(row.cursor)
    assert cursor["connector"] == "imap"
    assert cursor["state"] == "completed"
    assert cursor["window_days"] == 10
    assert cursor["processed"] == 12
    assert row.finished_at is not None
    assert row.next_retry_at is None
    assert source.last_checked is not None
    assert attempt.trigger == "backfill"
    assert attempt.status == "success"


def test_run_imap_backfill_moves_failed_attempt_to_backoff(db_session, monkeypatch):
    workspace, source = _source(db_session)
    row = _job(db_session, workspace, source, max_attempts=3)

    class FakeIMAPClient:
        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days, **_kwargs):
            return {
                "success": False,
                "processed": 2,
                "reports_found": 0,
                "duplicate_reports": 0,
                "new_domains": [],
                "errors": ["temporary provider failure"],
            }

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.IMAPClient",
        FakeIMAPClient,
    )

    assert run_imap_backfill_job(db_session, row) is True

    db_session.refresh(row)
    assert row.status == "backoff"
    assert row.attempt_count == 1
    assert row.error_count == 1
    assert json.loads(row.cursor)["state"] == "backoff"
    assert row.next_retry_at is not None
    assert row.finished_at is None


def test_run_imap_backfill_marks_exhausted_attempt_failed(db_session, monkeypatch):
    workspace, source = _source(db_session)
    row = _job(db_session, workspace, source, attempt_count=1, max_attempts=2)

    class FakeIMAPClient:
        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days, **_kwargs):
            raise RuntimeError("login failed for token=secret-value")

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.IMAPClient",
        FakeIMAPClient,
    )

    assert run_imap_backfill_job(db_session, row) is True

    db_session.refresh(row)
    attempt = db_session.query(MailSourceImport).filter_by(mail_source_id=source.id).one()

    assert row.status == "failed"
    assert row.attempt_count == 2
    assert row.finished_at is not None
    assert row.next_retry_at is None
    assert "secret-value" not in row.errors
    assert attempt.trigger == "backfill"
    assert attempt.status == "failed"
    assert "secret-value" not in attempt.errors


def test_run_due_imap_backfill_skips_unsupported_or_disabled_sources(db_session):
    workspace, gmail_source = _source(db_session, method="GMAIL_API")
    disabled_workspace, disabled_source = _source(db_session, enabled=False)
    _job(db_session, workspace, gmail_source)
    _job(db_session, disabled_workspace, disabled_source)

    assert run_due_imap_backfill_jobs(db_session) == 0


def test_run_due_mail_source_backfill_executes_gmail_job(db_session, monkeypatch):
    workspace, source = _source(db_session, method="GMAIL_API")
    row = _job(db_session, workspace, source)
    results = {
        "success": True,
        "processed": 5,
        "reports_found": 3,
        "duplicate_reports": 1,
        "new_domains": ["example.com"],
        "new_ingested_ids": ["new-id", "old-id"],
        "errors": [],
        "details": [{"status": "imported", "domain": "example.com"}],
        "search_window_days": 10,
    }

    class FakeGmailClient:
        def __init__(self, **kwargs):
            assert kwargs["already_ingested_ids"] == ["old-id"]
            assert kwargs["workspace_id"] == workspace.id

        def fetch_reports(self, days, **kwargs):
            assert days == 10
            assert kwargs["page_cursor"] is None
            assert kwargs["max_pages"] == 5
            return results

        def get_refreshed_tokens(self):
            return {"access_token": "new-access", "refresh_token": "new-refresh"}

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.GmailClient",
        FakeGmailClient,
    )
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.GmailClient.load_ingested_ids",
        lambda value: ["old-id"],
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.GmailClient.dump_ingested_ids",
        lambda values: ",".join(values),
        raising=False,
    )

    assert run_due_mail_source_backfill_jobs(db_session, limit=1) == 1

    db_session.refresh(row)
    db_session.refresh(source)
    attempt = db_session.query(MailSourceImport).filter_by(mail_source_id=source.id).one()

    assert row.status == "completed"
    cursor = json.loads(row.cursor)
    assert cursor["connector"] == "gmail"
    assert cursor["state"] == "completed"
    assert cursor["window_days"] == 10
    assert cursor["processed"] == 5
    assert cursor["search_window_days"] == 10
    assert row.processed == 5
    assert row.reports_found == 3
    assert source.gmail_ingested_ids == "old-id,new-id"
    assert source.gmail_access_token == "new-access"
    assert source.gmail_refresh_token == "new-refresh"
    assert source.last_checked is not None
    assert attempt.trigger == "backfill"
    assert attempt.status == "success"


def test_run_gmail_backfill_without_token_moves_to_backoff(db_session):
    workspace, source = _source(db_session, method="GMAIL_API")
    source.gmail_access_token = None
    db_session.commit()
    row = _job(db_session, workspace, source, max_attempts=3)

    assert run_gmail_backfill_job(db_session, row) is True

    db_session.refresh(row)
    attempt = db_session.query(MailSourceImport).filter_by(mail_source_id=source.id).one()

    assert row.status == "backoff"
    assert row.attempt_count == 1
    assert row.next_retry_at is not None
    assert "not yet authorised" in row.errors
    assert attempt.trigger == "backfill"
    assert attempt.status == "failed"


def test_run_gmail_backfill_without_refresh_token_moves_to_backoff(db_session):
    workspace, source = _source(db_session, method="GMAIL_API")
    source.gmail_refresh_token = None
    db_session.commit()
    row = _job(db_session, workspace, source, max_attempts=3)

    assert run_gmail_backfill_job(db_session, row) is True

    db_session.refresh(row)
    attempt = db_session.query(MailSourceImport).filter_by(mail_source_id=source.id).one()

    assert row.status == "backoff"
    assert row.attempt_count == 1
    assert row.next_retry_at is not None
    assert "Reconnect Gmail" in row.errors
    assert attempt.trigger == "backfill"
    assert attempt.status == "failed"


def test_run_gmail_backfill_provider_failure_moves_to_backoff(db_session, monkeypatch):
    workspace, source = _source(db_session, method="GMAIL_API")
    row = _job(db_session, workspace, source, max_attempts=3)

    class FakeGmailClient:
        load_ingested_ids = staticmethod(lambda _value: [])
        dump_ingested_ids = staticmethod(lambda values: ",".join(values))

        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days, **_kwargs):
            return {
                "success": False,
                "processed": 2,
                "reports_found": 0,
                "duplicate_reports": 0,
                "new_domains": [],
                "errors": ["temporary Gmail API failure"],
            }

        def get_refreshed_tokens(self):
            return None

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.GmailClient",
        FakeGmailClient,
    )

    assert run_gmail_backfill_job(db_session, row) is True

    db_session.refresh(row)
    assert row.status == "backoff"
    assert row.processed == 2
    assert row.error_count == 1
    assert json.loads(row.cursor)["connector"] == "gmail"
    assert row.next_retry_at is not None


def test_run_due_mail_source_backfill_executes_m365_job(db_session, monkeypatch):
    workspace, source = _source(db_session, method="M365_GRAPH")
    row = _job(db_session, workspace, source)
    results = {
        "success": True,
        "processed": 4,
        "reports_found": 2,
        "duplicate_reports": 1,
        "new_domains": ["example.net"],
        "new_ingested_ids": ["new-m365-id", "old-m365-id"],
        "errors": [],
        "details": [{"status": "imported", "domain": "example.net"}],
        "search_window_days": 10,
    }

    class FakeMicrosoftGraphClient:
        def __init__(self, **kwargs):
            assert kwargs["already_ingested_ids"] == ["old-m365-id"]
            assert kwargs["workspace_id"] == workspace.id
            assert kwargs["folder"] == "INBOX/DMARC"

        def fetch_reports(self, days, **kwargs):
            assert days == 10
            assert kwargs["page_cursor"] is None
            assert kwargs["max_pages"] == 5
            return results

        def get_refreshed_tokens(self):
            return {"access_token": "new-m365-access", "refresh_token": "new-m365-refresh"}

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.MicrosoftGraphClient",
        FakeMicrosoftGraphClient,
    )
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.MicrosoftGraphClient.load_ingested_ids",
        lambda value: ["old-m365-id"],
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.MicrosoftGraphClient.dump_ingested_ids",
        lambda values: ",".join(values),
        raising=False,
    )

    assert run_due_mail_source_backfill_jobs(db_session, limit=1) == 1

    db_session.refresh(row)
    db_session.refresh(source)
    attempt = db_session.query(MailSourceImport).filter_by(mail_source_id=source.id).one()

    assert row.status == "completed"
    cursor = json.loads(row.cursor)
    assert cursor["connector"] == "m365"
    assert cursor["state"] == "completed"
    assert cursor["window_days"] == 10
    assert cursor["processed"] == 4
    assert row.processed == 4
    assert row.reports_found == 2
    assert source.m365_ingested_ids == "old-m365-id,new-m365-id"
    assert source.m365_access_token == "new-m365-access"
    assert source.m365_refresh_token == "new-m365-refresh"
    assert source.last_checked is not None
    assert attempt.trigger == "backfill"
    assert attempt.status == "success"


def test_run_m365_backfill_without_token_moves_to_backoff(db_session):
    workspace, source = _source(db_session, method="M365_GRAPH")
    source.m365_access_token = None
    db_session.commit()
    row = _job(db_session, workspace, source, max_attempts=3)

    assert run_m365_backfill_job(db_session, row) is True

    db_session.refresh(row)
    attempt = db_session.query(MailSourceImport).filter_by(mail_source_id=source.id).one()

    assert row.status == "backoff"
    assert row.attempt_count == 1
    assert row.next_retry_at is not None
    assert "not yet authorised" in row.errors
    assert attempt.trigger == "backfill"
    assert attempt.status == "failed"


def test_run_m365_backfill_provider_failure_moves_to_backoff(db_session, monkeypatch):
    workspace, source = _source(db_session, method="M365_GRAPH")
    row = _job(db_session, workspace, source, max_attempts=3)

    class FakeMicrosoftGraphClient:
        load_ingested_ids = staticmethod(lambda _value: [])
        dump_ingested_ids = staticmethod(lambda values: ",".join(values))

        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days, **_kwargs):
            return {
                "success": False,
                "processed": 2,
                "reports_found": 0,
                "duplicate_reports": 0,
                "new_domains": [],
                "errors": ["temporary Microsoft Graph failure"],
            }

        def get_refreshed_tokens(self):
            return None

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.MicrosoftGraphClient",
        FakeMicrosoftGraphClient,
    )

    assert run_m365_backfill_job(db_session, row) is True

    db_session.refresh(row)
    assert row.status == "backoff"
    assert row.processed == 2
    assert row.error_count == 1
    assert json.loads(row.cursor)["connector"] == "m365"
    assert row.next_retry_at is not None


def test_gmail_backfill_queues_next_page_cursor(db_session, monkeypatch):
    workspace, source = _source(db_session, method="GMAIL_API")
    row = _job(db_session, workspace, source)

    class FakeGmailClient:
        load_ingested_ids = staticmethod(lambda _value: ["old-id"])
        dump_ingested_ids = staticmethod(lambda values: ",".join(values))

        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days, **kwargs):
            assert days == 10
            assert kwargs["page_cursor"] is None
            assert kwargs["max_pages"] == 5
            return {
                "success": True,
                "processed": 2,
                "reports_found": 1,
                "duplicate_reports": 0,
                "new_domains": [],
                "new_ingested_ids": ["gmail-id-1"],
                "errors": [],
                "page_cursor": "gmail-next-page",
            }

        def get_refreshed_tokens(self):
            return None

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.GmailClient",
        FakeGmailClient,
    )

    assert run_gmail_backfill_job(db_session, row) is True

    db_session.refresh(row)
    db_session.refresh(source)
    cursor = json.loads(row.cursor)
    assert row.status == "queued"
    assert row.finished_at is None
    assert row.next_retry_at is None
    assert row.processed == 2
    assert cursor["state"] == "queued"
    assert cursor["page_cursor"] == "gmail-next-page"
    assert source.gmail_ingested_ids == "old-id,gmail-id-1"


def test_gmail_backfill_resumes_from_stored_page_cursor(db_session, monkeypatch):
    workspace, source = _source(db_session, method="GMAIL_API")
    row = _job(db_session, workspace, source)
    row.processed = 2
    row.reports_found = 1
    row.cursor = json.dumps(
        {
            "version": 1,
            "connector": "gmail",
            "state": "queued",
            "window_days": 10,
            "processed": 2,
            "reports_found": 1,
            "duplicate_reports": 0,
            "error_count": 0,
            "page_cursor": "gmail-next-page",
        }
    )
    db_session.commit()

    class FakeGmailClient:
        load_ingested_ids = staticmethod(lambda _value: ["old-id"])
        dump_ingested_ids = staticmethod(lambda values: ",".join(values))

        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days, **kwargs):
            assert days == 10
            assert kwargs["page_cursor"] == "gmail-next-page"
            assert kwargs["max_pages"] == 5
            return {
                "success": True,
                "processed": 1,
                "reports_found": 1,
                "duplicate_reports": 0,
                "new_domains": [],
                "new_ingested_ids": ["gmail-id-2"],
                "errors": [],
            }

        def get_refreshed_tokens(self):
            return None

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.GmailClient",
        FakeGmailClient,
    )

    assert run_gmail_backfill_job(db_session, row) is True

    db_session.refresh(row)
    cursor = json.loads(row.cursor)
    assert row.status == "completed"
    assert row.processed == 3
    assert row.reports_found == 2
    assert cursor["state"] == "completed"
    assert "page_cursor" not in cursor


def test_m365_backfill_queues_next_link_cursor(db_session, monkeypatch):
    workspace, source = _source(db_session, method="M365_GRAPH")
    row = _job(db_session, workspace, source)

    class FakeMicrosoftGraphClient:
        load_ingested_ids = staticmethod(lambda _value: ["old-m365-id"])
        dump_ingested_ids = staticmethod(lambda values: ",".join(values))

        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days, **kwargs):
            assert days == 10
            assert kwargs["page_cursor"] is None
            assert kwargs["max_pages"] == 5
            return {
                "success": True,
                "processed": 3,
                "reports_found": 2,
                "duplicate_reports": 0,
                "new_domains": [],
                "new_ingested_ids": ["m365-id-1"],
                "errors": [],
                "page_cursor": "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc",
            }

        def get_refreshed_tokens(self):
            return None

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.MicrosoftGraphClient",
        FakeMicrosoftGraphClient,
    )

    assert run_m365_backfill_job(db_session, row) is True

    db_session.refresh(row)
    cursor = json.loads(row.cursor)
    assert row.status == "queued"
    assert row.processed == 3
    assert cursor["connector"] == "m365"
    assert cursor["state"] == "queued"
    assert cursor["page_cursor"].startswith("https://graph.microsoft.com/")


def test_run_mail_source_backfill_dispatches_or_skips(db_session, monkeypatch):
    workspace, imap_source = _source(db_session)
    imap_job = _job(db_session, workspace, imap_source)
    workspace, gmail_source = _source(db_session, method="GMAIL_API")
    gmail_job = _job(db_session, workspace, gmail_source)
    workspace, m365_source = _source(db_session, method="M365_GRAPH")
    m365_job = _job(db_session, workspace, m365_source)

    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.run_imap_backfill_job",
        lambda _db, job: job.id == imap_job.id,
    )
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.run_gmail_backfill_job",
        lambda _db, job: job.id == gmail_job.id,
    )
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.run_m365_backfill_job",
        lambda _db, job: job.id == m365_job.id,
    )

    assert run_mail_source_backfill_job(db_session, imap_job) is True
    assert run_mail_source_backfill_job(db_session, gmail_job) is True
    assert run_mail_source_backfill_job(db_session, m365_job) is True


def test_run_mail_source_backfill_job_by_id_uses_standalone_session(db_session, monkeypatch):
    workspace, source = _source(db_session)
    job = _job(db_session, workspace, source)
    standalone = MagicMock(wraps=db_session)
    dispatched = MagicMock(return_value=True)
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.SessionLocal",
        lambda: standalone,
    )
    monkeypatch.setattr(
        "app.services.mail_source_backfill_worker.run_mail_source_backfill_job",
        dispatched,
    )

    assert run_mail_source_backfill_job_by_id(job.id) is True
    dispatched.assert_called_once()
    assert dispatched.call_args.args[1].id == job.id
    standalone.close.assert_called_once()


def test_run_imap_backfill_skips_unsupported_status_or_future_retry(db_session):
    workspace, gmail_source = _source(db_session, method="GMAIL_API")
    gmail_job = _job(db_session, workspace, gmail_source)
    assert run_imap_backfill_job(db_session, gmail_job) is False

    workspace, imap_source = _source(db_session)
    running_job = _job(db_session, workspace, imap_source, status="running")
    assert run_imap_backfill_job(db_session, running_job) is False

    future_retry_job = _job(
        db_session,
        workspace,
        imap_source,
        status="backoff",
        next_retry_at=datetime.utcnow() + timedelta(minutes=5),
    )
    assert run_imap_backfill_job(db_session, future_retry_job) is False


def test_backfill_window_and_failure_helpers_cover_edge_cases(db_session):
    workspace, source = _source(db_session)
    default_window = _job(
        db_session,
        workspace,
        source,
        requested_start=None,
        requested_end=None,
    )
    assert _backfill_window_days(default_window) == 30

    now = datetime(2026, 1, 11, tzinfo=timezone.utc)
    future_end = _job(
        db_session,
        workspace,
        source,
        requested_start=datetime(2026, 1, 10, tzinfo=timezone.utc),
        requested_end=datetime(2026, 1, 12, tzinfo=timezone.utc),
    )
    assert _backfill_window_days(future_end, now=now) == 1
    assert _retry_delay(20) == timedelta(minutes=60)

    _mark_failure(
        future_end,
        "provider returned token=secret-value",
        now=datetime.utcnow(),
    )
    assert future_end.error_count == 1
    assert "secret-value" not in future_end.errors
