"""Read-only dispatch readiness for remediation notification previews."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from sqlalchemy.orm import Session

from app.models.setting import Setting
from app.models.webhook import WebhookEndpoint
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog
from app.services.webhook_events import SUPPORTED_EVENT_TYPES, endpoint_matches_event

DISPATCH_ENABLED_KEY = "notifications.remediation_dispatch_enabled"
DISPATCH_CHANNEL_KEY = "notifications.remediation_dispatch_channel"
DISPATCH_REQUIRE_ACK_KEY = "notifications.remediation_dispatch_require_acknowledgement"
DISPATCH_EVENTS_KEY = "notifications.remediation_dispatch_events"

DEFAULT_DISPATCH_EVENTS = {
    "dmarq.remediation.approval_required",
    "dmarq.remediation.manual_action_required",
    "dmarq.remediation.investigation_required",
}
ACKNOWLEDGED_LIFECYCLE_STATES = {"previewed", "acknowledged"}


def _truthy(value: Optional[str], *, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _settings(db: Session) -> Dict[str, str]:
    rows = (
        db.query(Setting)
        .filter(
            Setting.key.in_(
                [
                    DISPATCH_ENABLED_KEY,
                    DISPATCH_CHANNEL_KEY,
                    DISPATCH_REQUIRE_ACK_KEY,
                    DISPATCH_EVENTS_KEY,
                ]
            )
        )
        .all()
    )
    return {row.key: row.value or "" for row in rows}


def _configured_events(value: str) -> Set[str]:
    if not value.strip():
        return set(DEFAULT_DISPATCH_EVENTS)
    configured = {item.strip() for item in value.split(",") if item.strip()}
    return {event for event in configured if event in SUPPORTED_EVENT_TYPES}


def _latest_lifecycle_marker(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    item_id: str,
) -> Dict[str, Optional[str]]:
    row = (
        db.query(WorkspaceAuditLog)
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.action == "remediation.notification_lifecycle_recorded",
            WorkspaceAuditLog.entity_type == "remediation_notification",
            WorkspaceAuditLog.entity_id == item_id,
            WorkspaceAuditLog.entity_name == domain,
        )
        .order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
        .first()
    )
    if row is None:
        return {"state": None, "recorded_at": None}
    try:
        details = json.loads(row.details or "{}")
    except (json.JSONDecodeError, TypeError):
        details = {}
    recorded_at = row.created_at.isoformat() if isinstance(row.created_at, datetime) else None
    return {"state": details.get("lifecycle_state"), "recorded_at": recorded_at}


def _enabled_webhook_endpoints(db: Session, *, workspace: Workspace) -> List[WebhookEndpoint]:
    return (
        db.query(WebhookEndpoint)
        .filter(
            WebhookEndpoint.workspace_id == workspace.id,
            WebhookEndpoint.enabled.is_(True),
        )
        .all()
    )


def _matching_webhook_count(
    endpoints: Sequence[WebhookEndpoint], *, event_type: str
) -> int:
    return sum(1 for endpoint in endpoints if endpoint_matches_event(endpoint, event_type))


def _webhook_event_counts(
    endpoints: Sequence[WebhookEndpoint], event_types: Iterable[str]
) -> Dict[str, int]:
    return {
        event_type: _matching_webhook_count(endpoints, event_type=event_type)
        for event_type in set(event_types)
    }


def build_remediation_dispatch_preview(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    item: Dict[str, Any],
    settings: Optional[Dict[str, str]] = None,
    webhook_event_counts: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Return a read-only dispatch readiness summary for one remediation item."""
    settings = settings if settings is not None else _settings(db)
    enabled = _truthy(settings.get(DISPATCH_ENABLED_KEY), default=False)
    channel = (settings.get(DISPATCH_CHANNEL_KEY) or "webhook").strip().lower() or "webhook"
    require_ack = _truthy(settings.get(DISPATCH_REQUIRE_ACK_KEY), default=True)
    configured_events = _configured_events(settings.get(DISPATCH_EVENTS_KEY, ""))
    notification = item.get("notification") or {}
    event_type = str(notification.get("event") or "")
    item_id = str(item.get("id") or "")
    lifecycle = _latest_lifecycle_marker(db, workspace=workspace, domain=domain, item_id=item_id)
    lifecycle_state = lifecycle.get("state")
    if webhook_event_counts is None:
        endpoints = _enabled_webhook_endpoints(db, workspace=workspace)
        webhook_count = _matching_webhook_count(endpoints, event_type=event_type)
    else:
        webhook_count = webhook_event_counts.get(event_type, 0)
    blocked_reasons: List[str] = []

    if not enabled:
        blocked_reasons.append("Remediation dispatch is disabled in notification settings.")
    if event_type not in configured_events:
        blocked_reasons.append("This remediation event is not enabled for dispatch.")
    if channel != "webhook":
        blocked_reasons.append("Only webhook dispatch is supported in this release slice.")
    if require_ack and lifecycle_state not in ACKNOWLEDGED_LIFECYCLE_STATES:
        blocked_reasons.append("Record a previewed or acknowledged lifecycle marker first.")
    if channel == "webhook" and webhook_count == 0:
        blocked_reasons.append("No enabled webhook endpoint is subscribed to this event.")

    return {
        "enabled": enabled,
        "eligible": enabled and not blocked_reasons,
        "channel": channel,
        "event_enabled": event_type in configured_events,
        "requires_lifecycle_acknowledgement": require_ack,
        "lifecycle_state": lifecycle_state,
        "lifecycle_recorded_at": lifecycle.get("recorded_at"),
        "webhook_endpoint_count": webhook_count,
        "blocked_reasons": blocked_reasons,
        "would_enqueue": enabled and not blocked_reasons,
        "delivery_enqueued": False,
        "next_steps": _next_steps(blocked_reasons),
    }


def _next_steps(blocked_reasons: List[str]) -> List[str]:
    if not blocked_reasons:
        return ["Review the payload preview, then use the future dispatch endpoint to enqueue it."]
    steps = []
    for reason in blocked_reasons:
        if reason.startswith("Remediation dispatch is disabled"):
            steps.append(f"Enable {DISPATCH_ENABLED_KEY} after testing routing.")
        elif reason.startswith("This remediation event"):
            steps.append(f"Add the event to {DISPATCH_EVENTS_KEY}.")
        elif reason.startswith("Only webhook"):
            steps.append(f"Set {DISPATCH_CHANNEL_KEY}=webhook.")
        elif reason.startswith("Record a previewed"):
            steps.append(
                "Record a previewed or acknowledged remediation notification audit marker."
            )
        elif reason.startswith("No enabled webhook"):
            steps.append("Create or enable a webhook endpoint subscribed to the remediation event.")
    return steps


def attach_remediation_dispatch_previews(
    db: Session,
    *,
    workspace: Workspace,
    queue: Dict[str, Any],
) -> Dict[str, Any]:
    """Attach read-only dispatch readiness to every queue item notification."""
    domain = str(queue.get("domain") or "")
    items = list(queue.get("items", []))
    if not items:
        return queue
    settings = _settings(db)
    configured_events = _configured_events(settings.get(DISPATCH_EVENTS_KEY, ""))
    event_types = {
        str((item.get("notification") or {}).get("event") or "")
        for item in items
    }
    endpoints = _enabled_webhook_endpoints(db, workspace=workspace)
    webhook_event_counts = _webhook_event_counts(
        endpoints,
        configured_events | event_types,
    )
    for item in items:
        notification = item.setdefault("notification", {})
        notification["dispatch"] = build_remediation_dispatch_preview(
            db,
            workspace=workspace,
            domain=domain,
            item=item,
            settings=settings,
            webhook_event_counts=webhook_event_counts,
        )
    return queue
