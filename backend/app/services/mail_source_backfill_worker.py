"""Worker helpers for resumable mail-source backfill jobs."""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.redaction import redact_sensitive_text
from app.models.mail_source import MailSource
from app.models.mail_source_backfill import MailSourceBackfillJob
from app.services.gmail_client import GmailClient
from app.services.imap_client import IMAPClient
from app.services.import_history import record_import_attempt
from app.services.microsoft_graph_client import MicrosoftGraphClient

logger = logging.getLogger(__name__)

RUNNABLE_BACKFILL_STATUSES = ("queued", "backoff")
SUPPORTED_WORKER_METHODS = ("IMAP", "GMAIL_API", "M365_GRAPH")
MAX_BACKFILL_DAYS = 365


def _json_error_list(values: Iterable[object]) -> str:
    return json.dumps([redact_sensitive_text(value) for value in values])


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _backfill_window_days(job: MailSourceBackfillJob, now: Optional[datetime] = None) -> int:
    """Return the IMAP day window needed for a queued backfill job."""
    if not job.requested_start:
        return 30

    anchor = _naive_utc(now or datetime.utcnow())
    requested_start = _naive_utc(job.requested_start)
    requested_end = _naive_utc(job.requested_end) if job.requested_end else anchor
    if requested_end > anchor:
        requested_end = anchor
    seconds = max((requested_end - requested_start).total_seconds(), 1)
    days = int(math.ceil(seconds / 86400))
    return min(MAX_BACKFILL_DAYS, max(1, days))


def _retry_delay(attempt_count: int) -> timedelta:
    minutes = min(60, max(5, 5 * (2 ** max(attempt_count - 1, 0))))
    return timedelta(minutes=minutes)


def _copy_result_counts(job: MailSourceBackfillJob, results: Dict[str, Any]) -> None:
    job.processed = int(results.get("processed", 0) or 0)
    job.reports_found = int(results.get("reports_found", 0) or 0)
    job.duplicate_reports = int(results.get("duplicate_reports", 0) or 0)
    job.error_count = len(results.get("errors") or [])


def _claim_job(job: MailSourceBackfillJob, now: datetime) -> None:
    job.status = "running"
    job.started_at = now
    job.finished_at = None
    job.cancelled_at = None
    job.next_retry_at = None
    job.attempt_count = int(job.attempt_count or 0) + 1
    job.updated_at = now


def _job_is_runnable(job: MailSourceBackfillJob, method: str) -> bool:
    source = job.mail_source
    if source is None or source.method != method:
        return False
    if job.status not in RUNNABLE_BACKFILL_STATUSES:
        return False
    if job.next_retry_at and job.next_retry_at > datetime.utcnow():
        return False
    return True


def _mark_success(
    job: MailSourceBackfillJob,
    results: Dict[str, Any],
    *,
    days: int,
    cursor_prefix: str,
    now: datetime,
    errors: str,
    details: str,
) -> None:
    _copy_result_counts(job, results)
    job.status = "completed"
    job.cursor = f"{cursor_prefix}:days={days};processed={job.processed}"
    job.errors = errors
    job.details = details
    job.finished_at = now
    job.next_retry_at = None
    job.updated_at = now


def _mark_failure(
    job: MailSourceBackfillJob,
    message: object,
    *,
    now: datetime,
    results: Optional[Dict[str, Any]] = None,
    errors: Optional[str] = None,
    details: Optional[str] = None,
) -> None:
    if results:
        _copy_result_counts(job, results)
    else:
        job.error_count = max(1, int(job.error_count or 0))

    job.errors = errors or _json_error_list([message])
    job.details = details or json.dumps([])
    if int(job.attempt_count or 0) >= int(job.max_attempts or 1):
        job.status = "failed"
        job.finished_at = now
        job.next_retry_at = None
    else:
        job.status = "backoff"
        job.finished_at = None
        job.next_retry_at = now + _retry_delay(int(job.attempt_count or 1))
    job.updated_at = now


def run_imap_backfill_job(db: Session, job: MailSourceBackfillJob) -> bool:
    """Execute one IMAP backfill job and update its persisted lifecycle state."""
    source = job.mail_source
    if not _job_is_runnable(job, "IMAP"):
        return False

    started_at = datetime.utcnow()
    days = _backfill_window_days(job, started_at)
    _claim_job(job, started_at)
    db.commit()

    try:
        client = IMAPClient(
            server=source.server,
            port=source.port or 993,
            username=source.username,
            password=source.password,
            folder=source.folder,
            db=db,
            workspace_id=source.workspace_id,
        )
        results = client.fetch_reports(days=days)
        source.last_checked = datetime.utcnow()
        attempt = record_import_attempt(
            db,
            source,
            results,
            started_at=started_at,
            trigger="backfill",
        )
        db.flush()

        finished_at = datetime.utcnow()
        if results.get("success"):
            _mark_success(
                job,
                results,
                days=days,
                cursor_prefix="imap",
                now=finished_at,
                errors=attempt.errors,
                details=attempt.details,
            )
        else:
            _mark_failure(
                job,
                results.get("error") or "Backfill failed",
                now=finished_at,
                results=results,
                errors=attempt.errors,
                details=attempt.details,
            )
        db.commit()
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception("IMAP backfill job id=%s failed", job.id)
        results = {
            "success": False,
            "processed": 0,
            "reports_found": 0,
            "duplicate_reports": 0,
            "new_domains": [],
            "errors": [redact_sensitive_text(exc)],
            "details": [],
        }
        attempt = record_import_attempt(
            db,
            source,
            results,
            started_at=started_at,
            trigger="backfill",
        )
        db.flush()
        _mark_failure(
            job,
            exc,
            now=datetime.utcnow(),
            results=results,
            errors=attempt.errors,
            details=attempt.details,
        )
        db.commit()
        return True


def _fetch_gmail_backfill_results(
    db: Session,
    source: MailSource,
    *,
    started_at: datetime,
    days: int,
) -> tuple[Dict[str, Any], Any]:
    if not source.gmail_access_token:
        raise ValueError("Gmail account not yet authorised. Complete OAuth2 flow first.")

    already = GmailClient.load_ingested_ids(source.gmail_ingested_ids)
    client = GmailClient(
        client_id=source.gmail_client_id or "",
        client_secret=source.gmail_client_secret or "",
        access_token=source.gmail_access_token,
        refresh_token=source.gmail_refresh_token or "",
        already_ingested_ids=already,
        db=db,
        workspace_id=source.workspace_id,
    )
    results = client.fetch_reports(days=days)
    _sync_gmail_backfill_state(source, client, already, results)
    source.last_checked = datetime.utcnow()
    attempt = record_import_attempt(
        db,
        source,
        results,
        started_at=started_at,
        trigger="backfill",
    )
    db.flush()
    return results, attempt


def _sync_gmail_backfill_state(
    source: MailSource,
    client: GmailClient,
    already_ingested: List[str],
    results: Dict[str, Any],
) -> None:
    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already_ingested + results["new_ingested_ids"]))
        source.gmail_ingested_ids = GmailClient.dump_ingested_ids(all_ids)

    refreshed = client.get_refreshed_tokens()
    if refreshed:
        source.gmail_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.gmail_refresh_token = refreshed["refresh_token"]


def _fetch_m365_backfill_results(
    db: Session,
    source: MailSource,
    *,
    started_at: datetime,
    days: int,
) -> tuple[Dict[str, Any], Any]:
    if not source.m365_access_token:
        raise ValueError("Microsoft 365 account not yet authorised. Complete OAuth2 flow first.")

    already = MicrosoftGraphClient.load_ingested_ids(source.m365_ingested_ids)
    client = MicrosoftGraphClient(
        tenant_id=source.m365_tenant_id or "common",
        client_id=source.m365_client_id or "",
        client_secret=source.m365_client_secret or "",
        access_token=source.m365_access_token,
        refresh_token=source.m365_refresh_token or "",
        mailbox=source.m365_mailbox,
        folder=source.folder or "INBOX",
        folder_id=getattr(source, "m365_folder_id", None),
        already_ingested_ids=already,
        db=db,
        workspace_id=source.workspace_id,
    )
    results = client.fetch_reports(days=days)
    _sync_m365_backfill_state(source, client, already, results)
    source.last_checked = datetime.utcnow()
    attempt = record_import_attempt(
        db,
        source,
        results,
        started_at=started_at,
        trigger="backfill",
    )
    db.flush()
    return results, attempt


def _sync_m365_backfill_state(
    source: MailSource,
    client: MicrosoftGraphClient,
    already_ingested: List[str],
    results: Dict[str, Any],
) -> None:
    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already_ingested + results["new_ingested_ids"]))
        source.m365_ingested_ids = MicrosoftGraphClient.dump_ingested_ids(all_ids)

    refreshed = client.get_refreshed_tokens()
    if refreshed:
        source.m365_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.m365_refresh_token = refreshed["refresh_token"]


def _finish_backfill_from_results(
    job: MailSourceBackfillJob,
    results: Dict[str, Any],
    *,
    days: int,
    cursor_prefix: str,
    errors: str,
    details: str,
) -> None:
    finished_at = datetime.utcnow()
    if results.get("success"):
        _mark_success(
            job,
            results,
            days=days,
            cursor_prefix=cursor_prefix,
            now=finished_at,
            errors=errors,
            details=details,
        )
    else:
        _mark_failure(
            job,
            results.get("error") or "Backfill failed",
            now=finished_at,
            results=results,
            errors=errors,
            details=details,
        )


def _backfill_exception_results(exc: Exception) -> Dict[str, Any]:
    return {
        "success": False,
        "processed": 0,
        "reports_found": 0,
        "duplicate_reports": 0,
        "new_domains": [],
        "errors": [redact_sensitive_text(exc)],
        "details": [],
    }


def run_gmail_backfill_job(db: Session, job: MailSourceBackfillJob) -> bool:
    """Execute one Gmail API backfill job and update its persisted lifecycle state."""
    source = job.mail_source
    if not _job_is_runnable(job, "GMAIL_API"):
        return False

    started_at = datetime.utcnow()
    days = _backfill_window_days(job, started_at)
    _claim_job(job, started_at)
    db.commit()

    try:
        results, attempt = _fetch_gmail_backfill_results(
            db,
            source,
            started_at=started_at,
            days=days,
        )
        _finish_backfill_from_results(
            job,
            results,
            days=days,
            cursor_prefix="gmail",
            errors=attempt.errors,
            details=attempt.details,
        )
        db.commit()
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception("Gmail backfill job id=%s failed", job.id)
        results = _backfill_exception_results(exc)
        attempt = record_import_attempt(
            db,
            source,
            results,
            started_at=started_at,
            trigger="backfill",
        )
        db.flush()
        _mark_failure(
            job,
            exc,
            now=datetime.utcnow(),
            results=results,
            errors=attempt.errors,
            details=attempt.details,
        )
        db.commit()
        return True


def run_m365_backfill_job(db: Session, job: MailSourceBackfillJob) -> bool:
    """Execute one Microsoft 365 Graph backfill job and update persisted state."""
    source = job.mail_source
    if not _job_is_runnable(job, "M365_GRAPH"):
        return False

    started_at = datetime.utcnow()
    days = _backfill_window_days(job, started_at)
    _claim_job(job, started_at)
    db.commit()

    try:
        results, attempt = _fetch_m365_backfill_results(
            db,
            source,
            started_at=started_at,
            days=days,
        )
        _finish_backfill_from_results(
            job,
            results,
            days=days,
            cursor_prefix="m365",
            errors=attempt.errors,
            details=attempt.details,
        )
        db.commit()
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception("Microsoft 365 backfill job id=%s failed", job.id)
        results = _backfill_exception_results(exc)
        attempt = record_import_attempt(
            db,
            source,
            results,
            started_at=started_at,
            trigger="backfill",
        )
        db.flush()
        _mark_failure(
            job,
            exc,
            now=datetime.utcnow(),
            results=results,
            errors=attempt.errors,
            details=attempt.details,
        )
        db.commit()
        return True


def due_mail_source_backfill_jobs(
    db: Session,
    limit: int = 1,
    *,
    methods: Iterable[str] = SUPPORTED_WORKER_METHODS,
) -> List[MailSourceBackfillJob]:
    """Return due queued/backoff mail-source jobs for supported methods, oldest first."""
    now = datetime.utcnow()
    safe_limit = max(1, min(limit, 20))
    method_list = tuple(methods)
    return (
        db.query(MailSourceBackfillJob)
        .join(MailSource, MailSource.id == MailSourceBackfillJob.mail_source_id)
        .filter(
            MailSourceBackfillJob.status.in_(RUNNABLE_BACKFILL_STATUSES),
            or_(
                MailSourceBackfillJob.next_retry_at.is_(None),
                MailSourceBackfillJob.next_retry_at <= now,
            ),
            MailSource.method.in_(method_list),
            MailSource.enabled.is_(True),
        )
        .order_by(MailSourceBackfillJob.created_at.asc(), MailSourceBackfillJob.id.asc())
        .with_for_update(skip_locked=True)
        .limit(safe_limit)
        .all()
    )


def due_imap_backfill_jobs(db: Session, limit: int = 1) -> List[MailSourceBackfillJob]:
    """Return due queued/backoff IMAP jobs, oldest first."""
    return due_mail_source_backfill_jobs(db, limit=limit, methods=("IMAP",))


def run_mail_source_backfill_job(db: Session, job: MailSourceBackfillJob) -> bool:
    """Execute one supported mail-source backfill job."""
    source = job.mail_source
    if source is None:
        return False
    if source.method == "IMAP":
        return run_imap_backfill_job(db, job)
    if source.method == "GMAIL_API":
        return run_gmail_backfill_job(db, job)
    if source.method == "M365_GRAPH":
        return run_m365_backfill_job(db, job)
    return False


def run_due_imap_backfill_jobs(db: Session, limit: int = 1) -> int:
    """Execute a bounded batch of due IMAP backfill jobs."""
    count = 0
    for job in due_imap_backfill_jobs(db, limit=limit):
        if run_imap_backfill_job(db, job):
            count += 1
    return count


def run_due_mail_source_backfill_jobs(db: Session, limit: int = 1) -> int:
    """Execute a bounded batch of due supported mail-source backfill jobs."""
    count = 0
    for job in due_mail_source_backfill_jobs(db, limit=limit):
        if run_mail_source_backfill_job(db, job):
            count += 1
    return count
