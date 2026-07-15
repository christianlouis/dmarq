"""Worker helpers for resumable mail-source backfill jobs."""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
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
PROVIDER_BACKFILL_PAGE_BATCH_LIMIT = 5


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
    job.error_count = int(results.get("error_count", len(results.get("errors") or [])) or 0)


def _persist_imap_progress(
    db: Session,
    job: MailSourceBackfillJob,
    results: Dict[str, Any],
    *,
    days: int,
) -> None:
    """Persist bounded IMAP progress so UI polling is useful during large scans."""
    processed = int(results.get("processed", 0) or 0)
    total = int(results.get("total_messages", 0) or 0)
    if processed % 5 and processed != total:
        return
    _copy_result_counts(job, results)
    job.cursor = _cursor_checkpoint(
        connector="imap",
        state="running",
        days=days,
        results=results,
    )
    job.updated_at = datetime.utcnow()
    db.commit()


def _combined_result_counts(
    job: MailSourceBackfillJob,
    results: Dict[str, Any],
) -> Dict[str, Any]:
    combined = dict(results)
    combined["processed"] = int(job.processed or 0) + int(results.get("processed", 0) or 0)
    combined["reports_found"] = int(job.reports_found or 0) + int(
        results.get("reports_found", 0) or 0
    )
    combined["duplicate_reports"] = int(job.duplicate_reports or 0) + int(
        results.get("duplicate_reports", 0) or 0
    )
    combined["error_count"] = int(job.error_count or 0) + len(results.get("errors") or [])
    combined["skipped_attachments"] = _stored_skipped_attachments(job) + int(
        results.get("skipped_attachments", 0) or 0
    )
    return combined


def _stored_skipped_attachments(job: MailSourceBackfillJob) -> int:
    if not job.cursor:
        return 0
    try:
        payload = json.loads(job.cursor)
    except (TypeError, ValueError):
        return 0
    if not isinstance(payload, dict):
        return 0
    try:
        return max(0, int(payload.get("skipped_attachments", 0) or 0))
    except (TypeError, ValueError):
        return 0


def _stored_page_cursor(job: MailSourceBackfillJob, connector: str) -> Optional[str]:
    if not job.cursor:
        return None
    try:
        payload = json.loads(job.cursor)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("version") != 1 or payload.get("connector") != connector:
        return None
    cursor = payload.get("page_cursor")
    return cursor if isinstance(cursor, str) and cursor else None


def _cursor_checkpoint(
    *,
    connector: str,
    state: str,
    days: int,
    results: Optional[Dict[str, Any]] = None,
    page_cursor: Optional[str] = None,
) -> str:
    """Return a stable, provider-agnostic cursor checkpoint for one backfill job."""
    stats = results or {}
    checkpoint: Dict[str, Any] = {
        "version": 1,
        "connector": connector,
        "state": state,
        "window_days": days,
        "processed": int(stats.get("processed", 0) or 0),
        "reports_found": int(stats.get("reports_found", 0) or 0),
        "duplicate_reports": int(stats.get("duplicate_reports", 0) or 0),
        "skipped_attachments": int(stats.get("skipped_attachments", 0) or 0),
        "error_count": int(stats.get("error_count", len(stats.get("errors") or [])) or 0),
    }
    search_window_days = stats.get("search_window_days")
    if search_window_days is not None:
        checkpoint["search_window_days"] = int(search_window_days)
    if page_cursor:
        checkpoint["page_cursor"] = page_cursor
    return json.dumps(checkpoint, sort_keys=True, separators=(",", ":"))


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
    job.cursor = _cursor_checkpoint(
        connector=cursor_prefix,
        state="completed",
        days=days,
        results=results,
        page_cursor=results.get("page_cursor"),
    )
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
    days: Optional[int] = None,
    cursor_prefix: Optional[str] = None,
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
    if cursor_prefix and days is not None:
        job.cursor = _cursor_checkpoint(
            connector=cursor_prefix,
            state=job.status,
            days=days,
            results=results,
            page_cursor=results.get("page_cursor") if results else None,
        )
    job.updated_at = now


def _mark_queued_for_next_page(
    job: MailSourceBackfillJob,
    results: Dict[str, Any],
    *,
    days: int,
    cursor_prefix: str,
    now: datetime,
    errors: str,
    details: str,
    page_cursor: str,
) -> None:
    _copy_result_counts(job, results)
    job.status = "queued"
    job.cursor = _cursor_checkpoint(
        connector=cursor_prefix,
        state="queued",
        days=days,
        results=results,
        page_cursor=page_cursor,
    )
    job.errors = errors
    job.details = details
    job.finished_at = None
    job.next_retry_at = None
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
        results = client.fetch_reports(
            days=days,
            progress_callback=lambda progress: _persist_imap_progress(
                db,
                job,
                progress,
                days=days,
            ),
        )
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
                days=days,
                cursor_prefix="imap",
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
            days=days,
            cursor_prefix="imap",
        )
        db.commit()
        return True


def _fetch_gmail_backfill_results(
    db: Session,
    source: MailSource,
    *,
    started_at: datetime,
    days: int,
    page_cursor: Optional[str] = None,
) -> tuple[Dict[str, Any], Any]:
    if not source.gmail_access_token:
        raise ValueError("Gmail account not yet authorised. Complete OAuth2 flow first.")
    if not source.gmail_refresh_token:
        raise ValueError("Gmail authorization cannot be refreshed. Reconnect Gmail first.")

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
    results = client.fetch_reports(
        days=days,
        page_cursor=page_cursor,
        max_pages=PROVIDER_BACKFILL_PAGE_BATCH_LIMIT,
    )
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
    page_cursor: Optional[str] = None,
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
    results = client.fetch_reports(
        days=days,
        page_cursor=page_cursor,
        max_pages=PROVIDER_BACKFILL_PAGE_BATCH_LIMIT,
    )
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
    combined_results = _combined_result_counts(job, results)
    if results.get("success"):
        page_cursor = results.get("page_cursor")
        if isinstance(page_cursor, str) and page_cursor:
            _mark_queued_for_next_page(
                job,
                combined_results,
                days=days,
                cursor_prefix=cursor_prefix,
                now=finished_at,
                errors=errors,
                details=details,
                page_cursor=page_cursor,
            )
            return
        _mark_success(
            job,
            combined_results,
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
            results=combined_results,
            errors=errors,
            details=details,
            days=days,
            cursor_prefix=cursor_prefix,
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
        page_cursor = _stored_page_cursor(job, "gmail")
        results, attempt = _fetch_gmail_backfill_results(
            db,
            source,
            started_at=started_at,
            days=days,
            page_cursor=page_cursor,
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
            days=days,
            cursor_prefix="gmail",
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
        page_cursor = _stored_page_cursor(job, "m365")
        results, attempt = _fetch_m365_backfill_results(
            db,
            source,
            started_at=started_at,
            days=days,
            page_cursor=page_cursor,
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
            days=days,
            cursor_prefix="m365",
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


def run_mail_source_backfill_job_by_id(job_id: int) -> bool:
    """Run one queued backfill in a standalone session for API background tasks."""
    db = SessionLocal()
    try:
        job = (
            db.query(MailSourceBackfillJob)
            .filter(MailSourceBackfillJob.id == job_id)
            .with_for_update(skip_locked=True)
            .first()
        )
        if job is None:
            return False
        return run_mail_source_backfill_job(db, job)
    except Exception:  # pylint: disable=broad-exception-caught
        db.rollback()
        logger.exception("Background backfill job id=%s could not start", job_id)
        return False
    finally:
        db.close()


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
