import json
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from sqlalchemy.orm import Session

from app.core.redaction import redact_sensitive_text
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.services.mail_source_recovery import recovery_binding
from app.utils.stats_summarizer import StatsSummarizer

MAX_STORED_ERRORS = 10
MAX_ERROR_LENGTH = 500
MAX_STORED_DETAILS = 50
MAX_DETAIL_VALUE_LENGTH = 300
MAX_RECOVERY_LABEL_LENGTH = 120
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
RECOVERY_METHODS = {"GMAIL_API", "M365_GRAPH"}


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


def _json_recovery_metadata(source: MailSource, values: Optional[Iterable[Any]]) -> str:
    """Persist only complete provider IDs and source binding for item recovery."""
    items = []
    binding = recovery_binding(source)
    method = binding["method"]
    for value in list(values or []):
        if not isinstance(value, dict):
            continue
        if value.get("status") != "error" and value.get("reason") != "already_ingested_message":
            continue
        message_id = str(value.get("message_id") or "")
        if (
            not message_id
            or len(message_id) > 512
            or message_id.endswith("...")
            or any(ord(character) < 32 for character in message_id)
        ):
            continue
        item = {
            "message_id": message_id,
            "source_id": int(source.id),
            "workspace_id": getattr(source, "workspace_id", None),
            "disposition": "pending",
            "supported": method in RECOVERY_METHODS,
            **binding,
        }
        for field in ("filename", "report_id"):
            label = _sanitize_detail_value(value.get(field) or "")
            if label:
                item["label"] = (
                    label[: MAX_RECOVERY_LABEL_LENGTH - 3] + "..."
                    if len(label) > MAX_RECOVERY_LABEL_LENGTH
                    else label
                )
                break
        if method == "IMAP":
            item["unsupported_reason"] = (
                "Legacy IMAP history lacks UIDVALIDITY-bound stable message metadata."
            )
        if not any(existing["message_id"] == message_id for existing in items):
            items.append(item)
    return json.dumps(items[:MAX_STORED_DETAILS])


def _invalidate_imported_report_caches(source: MailSource, results: Dict[str, Any]) -> None:
    """Discard cached dashboard/domain summaries after persisted report imports."""
    imported = int(results.get("reports_found", 0) or 0) + int(
        results.get("forensic_reports_found", 0) or 0
    )
    if imported <= 0:
        return

    workspace_id = getattr(source, "workspace_id", None)
    summarizer = StatsSummarizer()
    summarizer.invalidate_cache(workspace_id=workspace_id)

    imported_domains = {
        str(detail.get("domain") or "").strip().lower()
        for detail in results.get("details", [])
        if isinstance(detail, dict) and detail.get("status") == "imported"
    }
    for domain in imported_domains - {""}:
        summarizer.invalidate_cache(domain, workspace_id=workspace_id)


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
        recovery_metadata=_json_recovery_metadata(source, results.get("details", [])),
        started_at=started_at,
        finished_at=datetime.utcnow(),
    )
    db.add(attempt)
    _invalidate_imported_report_caches(source, results)
    return attempt
