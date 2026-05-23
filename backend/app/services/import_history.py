import json
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from sqlalchemy.orm import Session

from app.core.redaction import redact_sensitive_text
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport

MAX_STORED_ERRORS = 10
MAX_ERROR_LENGTH = 500
MAX_STORED_DETAILS = 50
MAX_DETAIL_VALUE_LENGTH = 300
DETAIL_FIELDS = {
    "status",
    "reason",
    "message_id",
    "filename",
    "domain",
    "report_id",
    "mailbox",
    "folder",
    "error",
}


def _sanitize_error(value: object) -> str:
    """Return a compact, log-safe error string for storage and UI display."""
    text = redact_sensitive_text(value).strip()
    if len(text) > MAX_ERROR_LENGTH:
        return text[: MAX_ERROR_LENGTH - 3] + "..."
    return text


def _json_list(values: Optional[Iterable[Any]]) -> str:
    return json.dumps([str(value) for value in values or []])


def _sanitize_detail_value(value: object) -> str:
    text = _sanitize_error(value)
    if len(text) > MAX_DETAIL_VALUE_LENGTH:
        return text[: MAX_DETAIL_VALUE_LENGTH - 3] + "..."
    return text


def _json_details(values: Optional[Iterable[Any]]) -> str:
    details = []
    for value in list(values or [])[:MAX_STORED_DETAILS]:
        if not isinstance(value, dict):
            continue
        entry = {}
        for key in DETAIL_FIELDS:
            if key in value and value[key] not in (None, ""):
                entry[key] = _sanitize_detail_value(value[key])
        if entry:
            details.append(entry)
    return json.dumps(details)


def record_import_attempt(
    db: Session,
    source: MailSource,
    results: Dict[str, Any],
    *,
    started_at: datetime,
    trigger: str,
) -> MailSourceImport:
    """Persist a sanitized summary of a mail source import attempt."""
    result_errors = list(results.get("errors") or [])
    errors = [_sanitize_error(error) for error in result_errors[:MAX_STORED_ERRORS]]
    success = bool(results.get("success", False))
    status = "success" if success and not errors else "warning" if success else "failed"

    attempt = MailSourceImport(
        mail_source_id=source.id,
        trigger=trigger,
        status=status,
        processed=int(results.get("processed", 0) or 0),
        reports_found=int(results.get("reports_found", 0) or 0),
        duplicate_reports=int(results.get("duplicate_reports", 0) or 0),
        error_count=len(result_errors),
        new_domains=_json_list(results.get("new_domains", [])),
        errors=json.dumps(errors),
        details=_json_details(results.get("details", [])),
        started_at=started_at,
        finished_at=datetime.utcnow(),
    )
    db.add(attempt)
    return attempt
