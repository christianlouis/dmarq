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
OPERATOR_HELD_LIFECYCLE_STATES = {"resolved", "rejected", "snoozed"}
BLOCKED_REASON_NEXT_STEPS = (
    (
        "Remediation dispatch is disabled",
        f"Enable {DISPATCH_ENABLED_KEY} after testing routing.",
    ),
    ("This remediation event", f"Add the event to {DISPATCH_EVENTS_KEY}."),
    ("Only webhook", f"Set {DISPATCH_CHANNEL_KEY}=webhook."),
    (
        "Record a previewed",
        "Record a previewed or acknowledged remediation notification audit marker.",
    ),
    (
        "Operator marked this remediation item resolved",
        "Keep monitoring new reports; reopen the item only if the finding returns.",
    ),
    (
        "Operator marked this remediation item rejected",
        "Review the rejection history before creating a new dispatch request.",
    ),
    (
        "Operator marked this remediation item snoozed",
        "Wait for the snooze window or record a new lifecycle marker to resume.",
    ),
    (
        "No enabled webhook",
        "Create or enable a webhook endpoint subscribed to the remediation event.",
    ),
)
HISTORY_ACTIONS = {
    "remediation.notification_lifecycle_recorded",
    "remediation.notification_dispatch_enqueued",
}


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


def _audit_details(row: WorkspaceAuditLog) -> Dict[str, Any]:
    try:
        details = json.loads(row.details or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return details if isinstance(details, dict) else {}


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _history_entry(row: WorkspaceAuditLog) -> Optional[Dict[str, Any]]:
    details = _audit_details(row)
    created_at = row.created_at.isoformat() if isinstance(row.created_at, datetime) else None
    action = str(row.action or "")
    if action == "remediation.notification_dispatch_enqueued":
        state = "delivery_enqueued" if details.get("delivery_enqueued") else "dispatch_requested"
        label = "Dispatch enqueued" if details.get("delivery_enqueued") else "Dispatch requested"
    else:
        lifecycle_state = str(details.get("lifecycle_state") or "")
        if not lifecycle_state:
            return None
        state = lifecycle_state
        label = f"Lifecycle {lifecycle_state.replace('_', ' ')}"

    return {
        "action": action,
        "state": state,
        "label": label,
        "created_at": created_at,
        "actor_type": row.actor_type,
        "operator_note": details.get("operator_note"),
        "delivery_enqueued": bool(details.get("delivery_enqueued")),
        "delivery_count": _safe_int(details.get("delivery_count")),
        "dns_write_attempted": bool(details.get("dns_write_attempted")),
        "sent": bool(details.get("sent")),
    }


def _notification_histories(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    item_ids: Iterable[str],
    limit_per_item: int = 5,
) -> Dict[str, List[Dict[str, Any]]]:
    ids = [item_id for item_id in {str(item_id or "") for item_id in item_ids} if item_id]
    if not ids:
        return {}
    row_cap = max(len(ids) * limit_per_item * 3, limit_per_item)
    rows = (
        db.query(WorkspaceAuditLog)
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.entity_type == "remediation_notification",
            WorkspaceAuditLog.entity_id.in_(ids),
            WorkspaceAuditLog.entity_name == domain,
            WorkspaceAuditLog.action.in_(HISTORY_ACTIONS),
        )
        .order_by(
            WorkspaceAuditLog.entity_id.asc(),
            WorkspaceAuditLog.created_at.desc(),
            WorkspaceAuditLog.id.desc(),
        )
        .limit(row_cap)
        .all()
    )
    histories: Dict[str, List[Dict[str, Any]]] = {item_id: [] for item_id in ids}
    for row in rows:
        item_id = str(row.entity_id or "")
        if len(histories.setdefault(item_id, [])) >= limit_per_item:
            continue
        entry = _history_entry(row)
        if entry is None:
            continue
        histories[item_id].append(entry)
    return histories


def _latest_lifecycle_marker_from_history(
    history: Sequence[Dict[str, Any]],
) -> Dict[str, Optional[str]]:
    for entry in history:
        if entry.get("action") == "remediation.notification_lifecycle_recorded":
            return {
                "state": entry.get("state"),
                "recorded_at": entry.get("created_at"),
            }
    return {"state": None, "recorded_at": None}


def _enabled_webhook_endpoints(db: Session, *, workspace: Workspace) -> List[WebhookEndpoint]:
    return (
        db.query(WebhookEndpoint)
        .filter(
            WebhookEndpoint.workspace_id == workspace.id,
            WebhookEndpoint.enabled.is_(True),
        )
        .all()
    )


def _matching_webhook_count(endpoints: Sequence[WebhookEndpoint], *, event_type: str) -> int:
    return sum(1 for endpoint in endpoints if endpoint_matches_event(endpoint, event_type))


def _webhook_event_counts(
    endpoints: Sequence[WebhookEndpoint], event_types: Iterable[str]
) -> Dict[str, int]:
    return {
        event_type: _matching_webhook_count(endpoints, event_type=event_type)
        for event_type in set(event_types)
    }


def _endpoint_route_key(endpoint: WebhookEndpoint) -> str:
    return str(getattr(endpoint, "id", None) or getattr(endpoint, "url", None) or id(endpoint))


def _webhook_event_route_keys(
    endpoints: Sequence[WebhookEndpoint], event_types: Iterable[str]
) -> Dict[str, Set[str]]:
    return {
        event_type: {
            _endpoint_route_key(endpoint)
            for endpoint in endpoints
            if endpoint_matches_event(endpoint, event_type)
        }
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
    history: Optional[Sequence[Dict[str, Any]]] = None,
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
    lifecycle = (
        _latest_lifecycle_marker_from_history(history)
        if history is not None
        else _latest_lifecycle_marker(db, workspace=workspace, domain=domain, item_id=item_id)
    )
    lifecycle_state = lifecycle.get("state")
    if webhook_event_counts is None:
        endpoints = _enabled_webhook_endpoints(db, workspace=workspace)
        webhook_count = _matching_webhook_count(endpoints, event_type=event_type)
    else:
        webhook_count = webhook_event_counts.get(event_type, 0)
    blocked_reasons: List[str] = []

    operator_hold = lifecycle_state in OPERATOR_HELD_LIFECYCLE_STATES
    if operator_hold:
        blocked_reasons.append(
            f"Operator marked this remediation item {str(lifecycle_state).replace('_', ' ')}."
        )
    else:
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
        "operator_hold": operator_hold,
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
        steps.extend(
            step for prefix, step in BLOCKED_REASON_NEXT_STEPS if reason.startswith(prefix)
        )
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
        _attach_dispatch_summary(queue, items)
        return queue
    settings = _settings(db)
    configured_events = _configured_events(settings.get(DISPATCH_EVENTS_KEY, ""))
    event_types = {str((item.get("notification") or {}).get("event") or "") for item in items}
    endpoints = _enabled_webhook_endpoints(db, workspace=workspace)
    histories = _notification_histories(
        db,
        workspace=workspace,
        domain=domain,
        item_ids=[str(item.get("id") or "") for item in items],
    )
    webhook_event_counts = _webhook_event_counts(
        endpoints,
        configured_events | event_types,
    )
    webhook_event_route_keys = _webhook_event_route_keys(
        endpoints,
        configured_events | event_types,
    )
    for item in items:
        notification = item.setdefault("notification", {})
        item_history = histories.get(str(item.get("id") or ""), [])
        notification["history"] = item_history
        notification["dispatch"] = build_remediation_dispatch_preview(
            db,
            workspace=workspace,
            domain=domain,
            item=item,
            settings=settings,
            webhook_event_counts=webhook_event_counts,
            history=item_history,
        )
    _attach_dispatch_summary(
        queue,
        items,
        webhook_event_route_keys=webhook_event_route_keys,
    )
    return queue


def _attach_dispatch_summary(
    queue: Dict[str, Any],
    items: Sequence[Dict[str, Any]],
    *,
    webhook_event_route_keys: Optional[Dict[str, Set[str]]] = None,
) -> None:
    """Expose queue-level dispatch readiness counters for dashboards."""
    summary = dict(queue.get("summary") or {})
    notifications = [
        item.get("notification") or {}
        for item in items
        if (item.get("notification") or {}).get("dispatch") is not None
    ]
    dispatches = [notification.get("dispatch") or {} for notification in notifications]
    blocked = [dispatch for dispatch in dispatches if dispatch.get("blocked_reasons")]
    awaiting_ack = [
        dispatch
        for dispatch in blocked
        if dispatch.get("requires_lifecycle_acknowledgement")
        and not dispatch.get("operator_hold")
        and dispatch.get("lifecycle_state") not in ACKNOWLEDGED_LIFECYCLE_STATES
    ]
    route_keys: Set[str] = set()
    if webhook_event_route_keys:
        for notification in notifications:
            event_type = str(notification.get("event") or "")
            route_keys.update(webhook_event_route_keys.get(event_type, set()))
    summary.update(
        {
            "dispatch_ready": sum(1 for dispatch in dispatches if dispatch.get("eligible")),
            "dispatch_blocked": len(blocked),
            "dispatch_disabled": sum(1 for dispatch in dispatches if not dispatch.get("enabled")),
            "dispatch_awaiting_acknowledgement": len(awaiting_ack),
            "dispatch_webhook_routes": len(route_keys),
            "dispatch_resolved": sum(
                1 for dispatch in dispatches if dispatch.get("lifecycle_state") == "resolved"
            ),
            "dispatch_rejected": sum(
                1 for dispatch in dispatches if dispatch.get("lifecycle_state") == "rejected"
            ),
            "dispatch_snoozed": sum(
                1 for dispatch in dispatches if dispatch.get("lifecycle_state") == "snoozed"
            ),
        }
    )
    queue["summary"] = summary
