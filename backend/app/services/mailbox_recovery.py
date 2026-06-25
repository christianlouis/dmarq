"""Operator-facing recovery guidance for mailbox tests and imports."""

import json
from typing import Any, Dict, Optional

from app.core.redaction import redact_sensitive_text


DIAGNOSTIC_COPY: Dict[str, Dict[str, Any]] = {
    "ok": {
        "summary": "Mailbox operation completed successfully.",
        "recovery_steps": [],
    },
    "auth_required": {
        "summary": "The mailbox has not been connected yet.",
        "recovery_steps": [
            "Use the Connect Gmail or Connect Microsoft 365 action to complete authorization.",
            "Confirm the authorized mailbox is the one that receives DMARC aggregate reports.",
        ],
    },
    "auth_expired": {
        "summary": "The saved authorization is expired, revoked, or no longer accepted.",
        "recovery_steps": [
            "Reconnect the mailbox from Mail Sources.",
            "If your provider shows a consent screen, approve read-only mailbox access again.",
        ],
    },
    "authentication": {
        "summary": "The server rejected the username, password, app password, or OAuth token.",
        "recovery_steps": [
            "Verify the username and use an app-specific password when the provider requires one.",
            "Reconnect OAuth sources if the provider recently changed account security settings.",
        ],
    },
    "permissions": {
        "summary": "The account is connected but does not have enough mailbox access.",
        "recovery_steps": [
            "Grant read access for the mailbox that receives DMARC reports.",
            "For OAuth sources, reconnect and approve the requested read-only mail scope.",
        ],
    },
    "connectivity": {
        "summary": "DMARQ could not reach the mail server reliably.",
        "recovery_steps": [
            "Check the server hostname, port, TLS setting, and any firewall allowlists.",
            "Use port 993 with SSL for most IMAP providers.",
        ],
    },
    "mailbox_not_found": {
        "summary": "The configured mailbox folder could not be opened.",
        "recovery_steps": [
            "Choose one of the available mailbox names returned by the test.",
            "Check capitalization and nested folder separators such as Archive/DMARC.",
        ],
    },
    "folder_search": {
        "summary": (
            "The mailbox was reachable, but the selected folder or search window did not "
            "contain new DMARC reports."
        ),
        "recovery_steps": [
            "Confirm DMARC aggregate reports are delivered to the configured mailbox and folder.",
            "Run a wider backfill window if reports may be older than the current search range.",
        ],
    },
    "parsing": {
        "summary": "DMARQ reached the mailbox but could not parse one or more report attachments.",
        "recovery_steps": [
            "Open the latest import details and identify the affected attachment or reporter.",
            "Upload a known-good XML, ZIP, or GZIP aggregate report to confirm parsing works.",
        ],
    },
    "duplicate_only": {
        "summary": "The latest run only found reports that were already imported.",
        "recovery_steps": [
            "No immediate action is needed if the mailbox is expected to be quiet.",
            "If fresh reports are expected, confirm they are arriving in the configured folder.",
        ],
    },
    "throttling": {
        "summary": "The mail provider is rate limiting or temporarily refusing requests.",
        "recovery_steps": [
            "Wait a few minutes and retry the test.",
            "Increase the polling interval if repeated imports trigger provider limits.",
        ],
    },
    "missing_config": {
        "summary": "Required connection settings are missing.",
        "recovery_steps": [
            "Fill in the server, username, and password or complete OAuth authorization.",
            "Save the source before running stored-source tests.",
        ],
    },
    "not_implemented": {
        "summary": "This connection method cannot be tested from this screen yet.",
        "recovery_steps": [
            "Use IMAP, Gmail API, or Microsoft 365 Graph for mailbox ingestion.",
            "Keep unsupported sources disabled until a test path is implemented.",
        ],
    },
    "not_configured": {
        "summary": "No enabled mailbox source is available for scheduled DMARC imports.",
        "recovery_steps": [
            "Add or enable a mail source that receives DMARC aggregate reports.",
            "Run Test Connection before relying on scheduled imports.",
        ],
    },
    "unknown": {
        "summary": "The connection failed, but DMARQ could not classify the provider response.",
        "recovery_steps": [
            "Retry the test once to rule out a transient provider issue.",
            "Check the latest import history and server logs for the sanitized provider response.",
        ],
    },
}


def redact_recovery_text(value: object) -> str:
    """Return a log-safe, secret-redacted string for operator payloads."""
    return redact_sensitive_text(value)


def diagnostic_category(message: str, details: Optional[object] = None) -> str:
    """Map provider-specific failures to operator-friendly categories."""
    text = f"{message} {redact_recovery_text(details or '')}".lower()
    if any(term in text for term in ("not yet authorised", "not yet authorized", "complete oauth")):
        return "auth_required"
    if any(
        term in text
        for term in (
            "expired",
            "revoked",
            "invalid_grant",
            "interaction_required",
            "refresh token",
            "oauth",
        )
    ):
        return "auth_expired"
    if any(term in text for term in ("rate", "quota", "throttl", "too many", "429")):
        return "throttling"
    if any(
        term in text
        for term in ("scope", "permission", "access denied", "insufficient", "forbidden", "403")
    ):
        return "permissions"
    if any(term in text for term in ("credential", "password", "auth", "login", "invalid token")):
        return "authentication"
    if any(
        term in text
        for term in (
            "folder",
            "select failed",
            "does not exist",
            "mailbox not found",
            "no such mailbox",
        )
    ):
        return "mailbox_not_found"
    if any(
        term in text
        for term in (
            "timeout",
            "timed out",
            "dns",
            "resolve",
            "refused",
            "network",
            "ssl",
            "certificate",
        )
    ):
        return "connectivity"
    if "not yet implemented" in text:
        return "not_implemented"
    if any(term in text for term in ("not fully configured", "missing", "required")):
        return "missing_config"
    return "unknown"


def connection_diagnostic(
    success: bool, message: str, details: Optional[object] = None
) -> Dict[str, Any]:
    """Build sanitized connection diagnostics for API responses and UI recovery copy."""
    category = "ok" if success else diagnostic_category(message, details)
    diagnostic_copy = DIAGNOSTIC_COPY[category]
    diagnostic: Dict[str, Any] = {
        "category": category,
        "summary": diagnostic_copy["summary"],
        "recovery_steps": diagnostic_copy["recovery_steps"],
    }
    if details and not success:
        diagnostic["details"] = redact_recovery_text(details)
    return diagnostic


def connection_test_response(
    success: bool,
    message: str,
    stats: Optional[Dict[str, Any]] = None,
    details: Optional[object] = None,
) -> Dict[str, Any]:
    """Normalize stored and ad-hoc mailbox test responses."""
    stats = stats or {}
    diagnostic = connection_diagnostic(success, message, details or stats.get("diagnostic_detail"))
    return {
        "success": success,
        "message": redact_recovery_text(message),
        "message_count": stats.get("message_count", 0),
        "unread_count": stats.get("unread_count", 0),
        "dmarc_count": stats.get("dmarc_count", 0),
        "available_mailboxes": stats.get("available_mailboxes", []),
        "diagnostic": diagnostic,
        "diagnostic_category": diagnostic["category"],
        "diagnostic_summary": diagnostic["summary"],
        "recovery_steps": diagnostic["recovery_steps"],
    }


def not_configured_guidance() -> Dict[str, Any]:
    """Return setup/health guidance when no enabled mailbox source exists."""
    return _guidance("not_configured")


def import_result_diagnostic(results: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a mailbox import result into recovery guidance."""
    success = bool(results.get("success", False))
    errors = [str(error) for error in results.get("errors") or []]
    detail_text = " ".join(str(detail) for detail in results.get("details") or [])
    combined = " ".join(errors + [detail_text]).lower()

    if errors:
        if any(
            term in combined
            for term in (
                "xml",
                "zip",
                "gzip",
                "attachment",
                "parse",
                "parsing",
                "malformed",
                "decode",
                "unsupported",
            )
        ):
            return _guidance("parsing")
        return _guidance(diagnostic_category(" ".join(errors), detail_text))

    reports_found = int(results.get("reports_found", 0) or 0) + int(
        results.get("forensic_reports_found", 0) or 0
    )
    duplicate_reports = int(results.get("duplicate_reports", 0) or 0) + int(
        results.get("duplicate_forensic_reports", 0) or 0
    )
    processed = int(results.get("processed", 0) or 0)

    if success and reports_found == 0 and duplicate_reports > 0:
        return _guidance("duplicate_only")
    if success and processed > 0 and reports_found == 0:
        return _guidance("folder_search")
    if success:
        return _guidance("ok")
    return _guidance("unknown")


def import_row_diagnostic(row: Optional[Any]) -> Optional[Dict[str, Any]]:
    """Classify a persisted import-history row, if one exists."""
    if row is None:
        return None

    return import_result_diagnostic(
        {
            "success": row.status in {"success", "warning"},
            "processed": row.processed,
            "reports_found": row.reports_found,
            "duplicate_reports": row.duplicate_reports,
            "errors": _decode_json_list(row.errors),
            "details": _decode_json_list(row.details),
        }
    )


def _guidance(category: str) -> Dict[str, Any]:
    copy = DIAGNOSTIC_COPY[category]
    return {
        "category": category,
        "summary": copy["summary"],
        "recovery_steps": copy["recovery_steps"],
    }


def _decode_json_list(value: Optional[str]) -> list:
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    if isinstance(decoded, list):
        return decoded
    return []
