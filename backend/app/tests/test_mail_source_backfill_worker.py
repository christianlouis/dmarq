from datetime import datetime, timedelta, timezone

from app.models.mail_source import MailSource
from app.models.mail_source_backfill import MailSourceBackfillJob
from app.models.mail_source_import import MailSourceImport
from app.services.mail_source_backfill_worker import (
    _backfill_window_days,
    _mark_failure,
    _retry_delay,
    run_due_imap_backfill_jobs,
    run_imap_backfill_job,
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

        def fetch_reports(self, days):
            assert days == 10
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
    assert row.cursor == "imap:days=10;processed=12"
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

        def fetch_reports(self, days):
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
    assert row.next_retry_at is not None
    assert row.finished_at is None


def test_run_imap_backfill_marks_exhausted_attempt_failed(db_session, monkeypatch):
    workspace, source = _source(db_session)
    row = _job(db_session, workspace, source, attempt_count=1, max_attempts=2)

    class FakeIMAPClient:
        def __init__(self, **_kwargs):
            pass

        def fetch_reports(self, days):
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
