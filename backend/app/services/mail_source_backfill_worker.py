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
from app.services.imap_client import IMAPClient
from app.services.import_history import record_import_attempt

logger = logging.getLogger(__name__)

RUNNABLE_BACKFILL_STATUSES = ("queued", "backoff")
SUPPORTED_WORKER_METHODS = ("IMAP",)
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


def _mark_success(
    job: MailSourceBackfillJob,
    results: Dict[str, Any],
    *,
    days: int,
    now: datetime,
    errors: str,
    details: str,
) -> None:
    _copy_result_counts(job, results)
    job.status = "completed"
    job.cursor = f"imap:days={days};processed={job.processed}"
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
    if source is None or source.method != "IMAP":
        return False
    if job.status not in RUNNABLE_BACKFILL_STATUSES:
        return False
    if job.next_retry_at and job.next_retry_at > datetime.utcnow():
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


def due_imap_backfill_jobs(db: Session, limit: int = 1) -> List[MailSourceBackfillJob]:
    """Return due queued/backoff IMAP jobs, oldest first."""
    now = datetime.utcnow()
    safe_limit = max(1, min(limit, 20))
    return (
        db.query(MailSourceBackfillJob)
        .join(MailSource, MailSource.id == MailSourceBackfillJob.mail_source_id)
        .filter(
            MailSourceBackfillJob.status.in_(RUNNABLE_BACKFILL_STATUSES),
            or_(
                MailSourceBackfillJob.next_retry_at.is_(None),
                MailSourceBackfillJob.next_retry_at <= now,
            ),
            MailSource.method.in_(SUPPORTED_WORKER_METHODS),
            MailSource.enabled.is_(True),
        )
        .order_by(MailSourceBackfillJob.created_at.asc(), MailSourceBackfillJob.id.asc())
        .with_for_update(skip_locked=True)
        .limit(safe_limit)
        .all()
    )


def run_due_imap_backfill_jobs(db: Session, limit: int = 1) -> int:
    """Execute a bounded batch of due IMAP backfill jobs."""
    count = 0
    for job in due_imap_backfill_jobs(db, limit=limit):
        if run_imap_backfill_job(db, job):
            count += 1
    return count
