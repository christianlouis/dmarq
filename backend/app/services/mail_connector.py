"""Shared contracts and helpers for mail-source connectors."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Protocol

from app.core.redaction import redact_sensitive_text

MAX_CONNECTOR_ERROR_LENGTH = 500


@dataclass(frozen=True)
class ConnectorImportContext:
    """Safe import context that can be returned to operators and import history."""

    source_type: str
    mailbox: Optional[str] = None
    folder: Optional[str] = None
    search_window_days: Optional[int] = None

    def as_stats(self) -> Dict[str, Any]:
        stats: Dict[str, Any] = {"source_type": self.source_type}
        if self.mailbox:
            stats["target_mailbox"] = self.mailbox
        if self.folder:
            stats["target_folder"] = self.folder
        if self.search_window_days is not None:
            stats["search_window_days"] = self.search_window_days
        return stats


@dataclass(frozen=True)
class ConnectorMessage:
    """Provider-neutral message metadata used by connector implementations."""

    message_id: str
    subject: str = ""
    sender: str = ""
    received_at: Optional[str] = None
    has_attachments: bool = False
    raw: Any = None


@dataclass(frozen=True)
class ConnectorAttachment:
    """Provider-neutral attachment payload used by connector implementations."""

    filename: str
    content: bytes
    content_type: str = ""
    raw: Any = None


class MailSourceConnector(Protocol):
    """Interface new mailbox connectors should satisfy before endpoint wiring."""

    def import_context(self, days: Optional[int] = None) -> ConnectorImportContext:
        """Return safe, non-secret context for history and API responses."""

    def search_messages(self, days: int) -> Iterable[Any]:
        """Return provider messages in the requested search window."""

    def iter_attachments(self, message: Any) -> Iterable[Any]:
        """Yield provider attachments for one message."""

    def fetch_reports(self, days: int = 7) -> Dict[str, Any]:
        """Fetch, parse, and persist DMARC reports."""


def clamp_search_window(days: Optional[int], *, default: int = 7, maximum: int = 365) -> int:
    """Normalize user-supplied backfill windows for connector fetches."""
    try:
        value = int(days or default)
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, maximum))


def initial_import_stats(
    context: Optional[ConnectorImportContext] = None,
    *,
    deleted: bool = False,
) -> Dict[str, Any]:
    """Return the shared import-result shape used by mailbox connectors."""
    stats: Dict[str, Any] = {
        "success": True,
        "processed": 0,
        "reports_found": 0,
        "forensic_reports_found": 0,
        "duplicate_reports": 0,
        "duplicate_forensic_reports": 0,
        "new_domains": [],
        "errors": [],
        "new_ingested_ids": [],
        "details": [],
    }
    if deleted:
        stats["deleted"] = 0
    if context:
        stats.update(context.as_stats())
    return stats


def append_import_detail(
    stats: Optional[Dict[str, Any]],
    *,
    context: Optional[ConnectorImportContext] = None,
    **detail: Any,
) -> None:
    """Append one compact, sanitized message or attachment outcome."""
    if stats is None:
        return
    if context:
        detail.setdefault("mailbox", context.mailbox)
        detail.setdefault("folder", context.folder)
    clean_detail = {
        str(key): sanitize_connector_error(value)
        for key, value in detail.items()
        if value not in (None, "")
    }
    if clean_detail:
        stats.setdefault("details", []).append(clean_detail)


def sanitize_connector_error(value: object) -> str:
    """Return a compact, log-safe connector diagnostic with secrets redacted."""
    text = redact_sensitive_text(value).strip()
    if len(text) > MAX_CONNECTOR_ERROR_LENGTH:
        return text[: MAX_CONNECTOR_ERROR_LENGTH - 3] + "..."
    return text


def connector_failure_stats(
    stats: Dict[str, Any],
    message: str,
    *,
    error: Optional[object] = None,
) -> Dict[str, Any]:
    """Return a standardized failed import payload for provider errors."""
    _ = error
    safe_message = sanitize_connector_error(message)
    return {
        **stats,
        "success": False,
        "error": safe_message,
        "errors": [safe_message],
    }


def load_ingested_ids(json_text: Optional[str]) -> List[str]:
    """Deserialize a connector ingested-message-id JSON column."""
    if not json_text:
        return []
    try:
        decoded = json.loads(json_text)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(item) for item in decoded] if isinstance(decoded, list) else []


def dump_ingested_ids(ids: Iterable[Any]) -> str:
    """Serialize connector ingested-message IDs for database storage."""
    return json.dumps([str(item) for item in ids])
