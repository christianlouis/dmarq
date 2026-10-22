import json
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.core.redaction import redact_sensitive_text
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.services.mail_source_recovery import ignored_message_ids, recovery_binding
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
        is_error = value.get("status") == "error"
        is_already_ingested = value.get("reason") == "already_ingested_message"
        if not is_error and not is_already_ingested:
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
            # An already-ingested observation is useful audit history, but it
            # is not an operator recovery case. Keep it settled from the
            # moment it is recorded so polling cannot manufacture work.
            "disposition": "pending" if is_error else "settled",
            "reason": str(value.get("reason") or "") if is_already_ingested else "",
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


def _recovery_case_key(item: Dict[str, Any]) -> tuple:
    """Identify one provider message within one source mailbox context."""
    binding_keys = (
        "method",
        "folder",
        "account",
        "auth_mode",
        "tenant_id",
        "client_id",
        "folder_id",
    )
    return (
        str(item.get("message_id") or ""),
        tuple((key, str(item.get(key) or "")) for key in binding_keys),
    )


def _recovery_outcomes(source: MailSource, results: Dict[str, Any]) -> Dict[tuple, str]:
    observed: Dict[tuple, str] = {}
    binding = recovery_binding(source)
    # Reconciliation must only settle a failed case when this attempt stores
    # the corresponding recovery item.  The provider result can contain more
    # than MAX_STORED_DETAILS entries; otherwise an omitted error would
    # supersede the old case without leaving a successor visible in history.
    try:
        stored_items = json.loads(_json_recovery_metadata(source, results.get("details", [])))
    except (TypeError, json.JSONDecodeError):
        stored_items = []
    stored_error_keys = {
        _recovery_case_key(item)
        for item in stored_items
        if isinstance(item, dict) and item.get("disposition") == "pending"
    }
    for value in list(results.get("details") or []):
        if not isinstance(value, dict):
            continue
        message_id = str(value.get("message_id") or "")
        if not message_id:
            continue
        item = {"message_id": message_id, **binding}
        key = _recovery_case_key(item)
        if value.get("status") == "error":
            # One message can produce multiple attachment outcomes. A later
            # success must not hide an earlier failure for the same case.
            observed[key] = "failed"
        elif value.get("status") == "imported" and observed.get(key) != "failed":
            observed[key] = "settled"
    outcomes: Dict[tuple, str] = {}
    for key, disposition in observed.items():
        if disposition == "failed" and key not in stored_error_keys:
            continue
        outcomes[key] = disposition
    return outcomes


def _latest_recovery_dispositions(db: Session, source: MailSource) -> Dict[tuple, str]:
    """Return the most recent disposition for each exact recovery case."""
    latest: Dict[tuple, str] = {}
    prior_rows = (
        db.query(MailSourceImport)
        .filter(MailSourceImport.mail_source_id == source.id)
        .order_by(MailSourceImport.id.asc())
        .all()
    )
    for row in prior_rows:
        try:
            items = json.loads(row.recovery_metadata or "[]")
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if (
                isinstance(item, dict)
                and item.get("message_id")
                # A cache hit records an observation, not resolution of an
                # existing recovery case. Preserve the authoritative outcome
                # from an earlier failure or explicit ignore.
                and item.get("reason") != "already_ingested_message"
            ):
                latest[_recovery_case_key(item)] = str(item.get("disposition") or "")
    return latest


def _suppress_ignored_recovery_cases(metadata: str, ignored_cases: set[tuple]) -> str:
    """Keep a newly observed failure ignored when its latest case was ignored."""
    try:
        items = json.loads(metadata or "[]")
    except (TypeError, json.JSONDecodeError):
        return metadata
    if not isinstance(items, list):
        return metadata
    changed = False
    for item in items:
        if (
            isinstance(item, dict)
            and item.get("disposition") == "pending"
            and _recovery_case_key(item) in ignored_cases
        ):
            item["disposition"] = "ignored"
            item["last_status"] = "ignored"
            changed = True
    return json.dumps(items) if changed else metadata


def _reconcile_recovery_metadata(metadata: Optional[str], outcomes: Dict[tuple, str]) -> str:
    try:
        items = json.loads(metadata or "[]")
    except (TypeError, json.JSONDecodeError):
        return metadata or "[]"
    if not isinstance(items, list):
        return metadata or "[]"
    changed = False
    for item in items:
        if not isinstance(item, dict) or (
            item.get("disposition") != "pending"
            and not (item.get("disposition") == "retried" and item.get("last_status") == "failed")
        ):
            continue
        outcome = outcomes.get(_recovery_case_key(item))
        if outcome == "failed":
            item["disposition"] = "superseded"
            item["last_status"] = "failed"
            changed = True
        elif outcome == "settled":
            item["disposition"] = "settled"
            item["last_status"] = "success"
            changed = True
    if changed:
        return json.dumps(items)
    return metadata or "[]"


def _reconcile_recovery_history(
    db: Session,
    source: MailSource,
    results: Dict[str, Any],
) -> None:
    """Settle or supersede exact prior recovery cases without deleting history."""
    outcomes = _recovery_outcomes(source, results)
    if not outcomes:
        return
    prior_rows = (
        db.query(MailSourceImport.id, MailSourceImport.recovery_metadata)
        .filter(MailSourceImport.mail_source_id == source.id)
        .all()
    )
    for row_id, original in prior_rows:
        replacement = _reconcile_recovery_metadata(original, outcomes)
        if replacement == (original or "[]"):
            continue
        updated = (
            db.query(MailSourceImport)
            .filter(
                MailSourceImport.id == row_id,
                MailSourceImport.recovery_metadata == original,
            )
            .update(
                {MailSourceImport.recovery_metadata: replacement},
                synchronize_session=False,
            )
        )
        if updated != 1:
            # A concurrent ignore/retry won the race. Re-read and reconcile
            # only still-pending items, never restoring a terminal outcome.
            current = (
                db.query(MailSourceImport.recovery_metadata)
                .filter(MailSourceImport.id == row_id)
                .scalar()
            )
            retry_replacement = _reconcile_recovery_metadata(current, outcomes)
            if retry_replacement != (current or "[]"):
                db.query(MailSourceImport).filter(
                    MailSourceImport.id == row_id,
                    MailSourceImport.recovery_metadata == current,
                ).update(
                    {MailSourceImport.recovery_metadata: retry_replacement},
                    synchronize_session=False,
                )
                if retry_replacement != (current or "[]"):
                    tracked = db.get(MailSourceImport, row_id)
                    if tracked is not None:
                        set_committed_value(tracked, "recovery_metadata", retry_replacement)
        else:
            tracked = db.get(MailSourceImport, row_id)
            if tracked is not None:
                set_committed_value(tracked, "recovery_metadata", replacement)


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
    latest = _latest_recovery_dispositions(db, source)
    _reconcile_recovery_history(db, source, results)
    ignored_cases = {key for key, disposition in latest.items() if disposition == "ignored"}
    # Re-read after reconciliation so an ignore committed while older rows
    # were being inspected still suppresses this newly-created failure.
    latest = _latest_recovery_dispositions(db, source)
    ignored_cases.update(key for key, disposition in latest.items() if disposition == "ignored")
    binding = recovery_binding(source)
    ignored_cases.update(
        _recovery_case_key(
            {
                "message_id": message_id,
                "source_id": source.id,
                "workspace_id": source.workspace_id,
                **binding,
            }
        )
        for message_id in ignored_message_ids(db, source)
    )
    attempt.recovery_metadata = _suppress_ignored_recovery_cases(
        attempt.recovery_metadata, ignored_cases
    )
    db.add(attempt)
    _invalidate_imported_report_caches(source, results)
    return attempt
