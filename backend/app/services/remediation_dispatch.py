"""Read-only dispatch readiness for remediation notification previews."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.setting import Setting
from app.models.webhook import WebhookEndpoint
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog
from app.services.webhook_events import SUPPORTED_EVENT_TYPES, endpoint_matches_event
from app.utils.domain_validator import normalize_domain_name

DISPATCH_ENABLED_KEY = "notifications.remediation_dispatch_enabled"
DISPATCH_CHANNEL_KEY = "notifications.remediation_dispatch_channel"
DISPATCH_REQUIRE_ACK_KEY = "notifications.remediation_dispatch_require_acknowledgement"
DISPATCH_EVENTS_KEY = "notifications.remediation_dispatch_events"

DEFAULT_DISPATCH_EVENTS = {
    "dmarq.remediation.approval_required",
    "dmarq.remediation.manual_action_required",
    "dmarq.remediation.investigation_required",
}
ACKNOWLEDGED_LIFECYCLE_STATES = {
    "previewed",
    "preview_change",
    "acknowledged",
    "approve_after_preview",
    "mark_legitimate",
    "convert_to_manual_action",
}
OPERATOR_HELD_LIFECYCLE_STATES = {"resolved", "rejected", "snoozed", "mark_unknown"}
LIFECYCLE_HISTORY_LABELS = {
    "preview_change": "Previewed provider change",
    "approve_after_preview": "Approved after preview",
    "mark_legitimate": "Marked legitimate sender",
    "mark_unknown": "Marked unknown sender",
    "convert_to_manual_action": "Converted to manual action",
    "previewed": "Marked reviewed",
    "acknowledged": "Marked acknowledged",
    "resolved": "Marked resolved",
    "rejected": "Marked rejected",
    "snoozed": "Marked snoozed",
}
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
        "Operator marked this remediation item unknown sender",
        "Keep the source treated as unauthorized until fresh evidence proves ownership.",
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
PROVIDER_REPAIR_HISTORY_ACTION = "domain.dns_change_applied"
VERIFIED_FIXED_STALE_AFTER = timedelta(days=7)


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
    recorded_at = _audit_timestamp(row.created_at)
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


def _audit_timestamp(value: Any) -> Optional[str]:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _verified_fixed_freshness(
    recorded_at: Any, *, now: Optional[datetime] = None
) -> Dict[str, str]:
    if not isinstance(recorded_at, datetime):
        return {
            "freshness_status": "unknown_queue_absence_age",
            "freshness_label": "Queue absence age unknown",
        }
    if recorded_at.tzinfo is None:
        recorded_at = recorded_at.replace(tzinfo=timezone.utc)
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    if now - recorded_at > VERIFIED_FIXED_STALE_AFTER:
        return {
            "freshness_status": "stale_queue_absence",
            "freshness_label": "Stale queue absence",
        }
    return {
        "freshness_status": "current_queue_absence",
        "freshness_label": "Fresh queue absence",
    }


def _history_entry(row: WorkspaceAuditLog) -> Optional[Dict[str, Any]]:
    details = _audit_details(row)
    created_at = _audit_timestamp(row.created_at)
    action = str(row.action or "")
    if action == "remediation.notification_dispatch_enqueued":
        state = "delivery_enqueued" if details.get("delivery_enqueued") else "dispatch_requested"
        label = "Dispatch enqueued" if details.get("delivery_enqueued") else "Dispatch requested"
    else:
        lifecycle_state = str(details.get("lifecycle_state") or "")
        if not lifecycle_state:
            return None
        state = lifecycle_state
        label = LIFECYCLE_HISTORY_LABELS.get(
            lifecycle_state,
            f"Marked {lifecycle_state.replace('_', ' ')}",
        )

    return {
        "item_id": str(row.entity_id or ""),
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


def _lifecycle_reason_label(lifecycle_state: Optional[str]) -> str:
    if lifecycle_state == "mark_unknown":
        return "unknown sender"
    return str(lifecycle_state or "").replace("_", " ")


def _empty_domain_activity(domain: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "status": "none",
        "latest_state": None,
        "latest_label": "No operator activity",
        "latest_at": None,
        "previewed": 0,
        "acknowledged": 0,
        "resolved": 0,
        "rejected": 0,
        "snoozed": 0,
        "verified_fixed": 0,
        "dispatch_enqueued": 0,
        "delivery_count": 0,
        "needs_operator_follow_up": False,
    }


def _apply_activity_entry(
    summary: Dict[str, Any],
    entry: Dict[str, Any],
    *,
    active_item_ids: Optional[Set[str]] = None,
) -> None:
    state = str(entry.get("state") or "")
    if summary["latest_state"] is None:
        summary["latest_state"] = state
        summary["latest_label"] = str(entry.get("label") or state.replace("_", " ").title())
        summary["latest_at"] = entry.get("created_at")
    if state in {"previewed", "acknowledged", "resolved", "rejected", "snoozed"}:
        summary[state] += 1
    if state == "resolved" and active_item_ids is not None:
        item_id = str(entry.get("item_id") or "")
        if item_id.startswith("health:") and item_id not in active_item_ids:
            summary["verified_fixed"] += 1
    if state == "delivery_enqueued":
        summary["dispatch_enqueued"] += 1
        summary["delivery_count"] += _safe_int(entry.get("delivery_count"))


def _activity_status(summary: Dict[str, Any]) -> str:
    latest_state = summary["latest_state"]
    if latest_state == "resolved":
        return "resolved"
    if latest_state in {"rejected", "snoozed", "mark_unknown"}:
        return "operator_hold"
    if summary["dispatch_enqueued"]:
        return "dispatched"
    if latest_state in ACKNOWLEDGED_LIFECYCLE_STATES:
        return "reviewed"
    if latest_state:
        return "activity"
    return "none"


def _finalize_activity_summary(summary: Dict[str, Any]) -> None:
    summary["status"] = _activity_status(summary)
    summary["needs_operator_follow_up"] = summary["status"] in {
        "dispatched",
        "reviewed",
        "operator_hold",
    }


def _remediation_activity_totals(summaries: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    return {
        "domains_with_activity": sum(
            1 for summary in summaries.values() if summary["latest_state"] is not None
        ),
        "dispatch_enqueued": sum(summary["dispatch_enqueued"] for summary in summaries.values()),
        "resolved": sum(summary["resolved"] for summary in summaries.values()),
        "verified_fixed": sum(summary["verified_fixed"] for summary in summaries.values()),
        "operator_holds": sum(
            summary["rejected"] + summary["snoozed"] for summary in summaries.values()
        ),
        "needs_operator_follow_up": sum(
            1 for summary in summaries.values() if summary["needs_operator_follow_up"]
        ),
        "delivery_count": sum(summary["delivery_count"] for summary in summaries.values()),
    }


def summarize_remediation_activity(
    db: Session,
    *,
    workspace: Workspace,
    domains: Iterable[str],
    active_item_ids_by_domain: Optional[Dict[str, Iterable[str]]] = None,
    row_limit: int = 500,
) -> Dict[str, Any]:
    """Summarize remediation audit activity without rebuilding domain queues."""
    domain_names = []
    for domain in domains:
        domain_name = normalize_domain_name(str(domain or ""))
        if domain_name:
            domain_names.append(domain_name)
    domain_names = list(dict.fromkeys(domain_names))
    summaries = {domain: _empty_domain_activity(domain) for domain in domain_names}
    if not domain_names:
        return {
            "summary": {
                "domains_with_activity": 0,
                "dispatch_enqueued": 0,
                "resolved": 0,
                "verified_fixed": 0,
                "operator_holds": 0,
                "needs_operator_follow_up": 0,
                "delivery_count": 0,
            },
            "domains": summaries,
        }
    active_item_ids = {
        normalize_domain_name(domain): {
            str(item_id or "") for item_id in item_ids if str(item_id or "").strip()
        }
        for domain, item_ids in (active_item_ids_by_domain or {}).items()
        if normalize_domain_name(domain)
    }

    normalized_entity_name = func.lower(func.rtrim(func.trim(WorkspaceAuditLog.entity_name), "."))
    rows: List[WorkspaceAuditLog] = []
    per_domain_limit = max(row_limit, 1)
    for domain in domain_names:
        rows.extend(
            db.query(WorkspaceAuditLog)
            .filter(
                WorkspaceAuditLog.workspace_id == workspace.id,
                WorkspaceAuditLog.entity_type == "remediation_notification",
                normalized_entity_name == domain,
                WorkspaceAuditLog.action.in_(HISTORY_ACTIONS),
            )
            .order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
            .limit(per_domain_limit)
            .all()
        )

    for row in rows:
        domain = normalize_domain_name(str(row.entity_name or ""))
        if domain not in summaries:
            continue
        entry = _history_entry(row)
        if entry is None:
            continue
        _apply_activity_entry(
            summaries[domain],
            entry,
            active_item_ids=active_item_ids.get(domain),
        )

    for summary in summaries.values():
        _finalize_activity_summary(summary)

    return {"summary": _remediation_activity_totals(summaries), "domains": summaries}


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


def _provider_repair_attempt_entry(row: WorkspaceAuditLog) -> Optional[Dict[str, Any]]:
    details = _audit_details(row)
    mutation = details.get("mutation") if isinstance(details.get("mutation"), dict) else {}
    verification = (
        details.get("verification") if isinstance(details.get("verification"), dict) else {}
    )
    provider = str(details.get("provider") or mutation.get("provider") or "")
    plan_id = str(details.get("plan_id") or "")
    if not plan_id:
        return None
    verified = bool(verification.get("verified"))
    applied = bool(details.get("applied"))
    applied_and_verified = applied and verified
    state = "verified_after_apply" if applied_and_verified else "apply_recorded"
    if applied and not verified:
        state = "apply_needs_verification"
    return {
        "plan_id": plan_id,
        "state": state,
        "label": (
            "Verified provider apply" if applied_and_verified else "Provider apply recorded"
        ),
        "created_at": _audit_timestamp(row.created_at),
        "provider": provider,
        "record_name": str(mutation.get("name") or ""),
        "record_type": str(mutation.get("record_type") or ""),
        "verification_status": str(verification.get("status") or ""),
        "detail": (
            "Provider readback verified the applied DNS value."
            if applied_and_verified
            else "Provider apply was recorded; keep the item open until readback and fresh DNS evidence pass."
        ),
    }


def _provider_repair_attempt_histories(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    plan_ids: Iterable[str],
    limit_per_plan: int = 3,
) -> Dict[str, List[Dict[str, Any]]]:
    ids = {str(plan_id or "") for plan_id in plan_ids if str(plan_id or "").strip()}
    if not ids:
        return {}
    normalized_domain = normalize_domain_name(domain)
    normalized_entity_name = func.lower(func.rtrim(func.trim(WorkspaceAuditLog.entity_name), "."))
    rows = (
        db.query(WorkspaceAuditLog)
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.action == PROVIDER_REPAIR_HISTORY_ACTION,
            WorkspaceAuditLog.entity_type == "domain",
            normalized_entity_name == normalized_domain,
        )
        .order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
        .limit(max(len(ids) * limit_per_plan * 3, limit_per_plan))
        .all()
    )
    histories: Dict[str, List[Dict[str, Any]]] = {plan_id: [] for plan_id in ids}
    for row in rows:
        entry = _provider_repair_attempt_entry(row)
        if entry is None:
            continue
        plan_id = str(entry.get("plan_id") or "")
        if plan_id not in histories or len(histories[plan_id]) >= limit_per_plan:
            continue
        histories[plan_id].append(entry)
    return histories


def _attach_provider_repair_attempt_history(
    item: Dict[str, Any],
    history: Sequence[Dict[str, Any]],
) -> None:
    plan = item.get("provider_repair_plan") or {}
    if plan.get("kind") != "dns_provider_repair":
        return
    entries = [dict(entry) for entry in history][:3]
    if not entries:
        return
    latest = entries[0]
    plan["attempt_history"] = {
        "source": "workspace_audit.domain.dns_change_applied",
        "status": str(latest.get("state") or "apply_recorded"),
        "label": str(latest.get("label") or "Provider apply recorded"),
        "latest_at": str(latest.get("created_at") or ""),
        "entries": entries,
        "next_step": str(
            latest.get("detail")
            or "Refresh DNS evidence and keep the remediation item open until verification passes."
        ),
    }
    item["provider_repair_plan"] = plan


def _verified_fixed_items(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    current_item_ids: Iterable[str],
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Return resolved remediation markers whose items no longer appear in current evidence."""
    return _verified_fixed_items_result(
        db,
        workspace=workspace,
        domain=domain,
        current_item_ids=current_item_ids,
        limit=limit,
    )["items"]


def _verified_fixed_items_result(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    current_item_ids: Iterable[str],
    limit: int = 5,
) -> Dict[str, Any]:
    """Return capped verified-fixed rows plus the total latest resolved count."""
    if not hasattr(db, "query"):
        return {"items": [], "total": 0}
    normalized_domain = normalize_domain_name(domain)
    if not normalized_domain:
        return {"items": [], "total": 0}
    active_ids = {str(item_id or "") for item_id in current_item_ids if str(item_id or "")}
    normalized_entity_name = func.lower(
        func.rtrim(func.ltrim(func.trim(WorkspaceAuditLog.entity_name), "."), ".")
    )
    resolved_details = or_(
        WorkspaceAuditLog.details.like('%"lifecycle_state": "resolved"%'),
        WorkspaceAuditLog.details.like('%"lifecycle_state":"resolved"%'),
    )
    ranked_lifecycle_rows = (
        db.query(WorkspaceAuditLog)
        .with_entities(
            WorkspaceAuditLog.id.label("audit_id"),
            func.row_number()
            .over(
                partition_by=WorkspaceAuditLog.entity_id,
                order_by=(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc()),
            )
            .label("row_number"),
        )
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.action == "remediation.notification_lifecycle_recorded",
            WorkspaceAuditLog.entity_type == "remediation_notification",
            WorkspaceAuditLog.entity_id.isnot(None),
            normalized_entity_name == normalized_domain,
        )
        .subquery()
    )
    latest_lifecycle_ids = (
        select(ranked_lifecycle_rows.c.audit_id).where(ranked_lifecycle_rows.c.row_number == 1)
    )
    verified_query = (
        db.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.id.in_(latest_lifecycle_ids), resolved_details)
        .order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
    )
    if active_ids:
        verified_query = verified_query.filter(WorkspaceAuditLog.entity_id.notin_(active_ids))
    verified_total = verified_query.count()
    rows = verified_query.limit(limit).all()

    verified: List[Dict[str, Any]] = []
    for row in rows:
        item_id = str(row.entity_id or "")
        if not item_id:
            continue
        details = _audit_details(row)
        if details.get("lifecycle_state") != "resolved":
            continue
        freshness = _verified_fixed_freshness(row.created_at)
        verified.append(
            {
                "item_id": item_id,
                "state": "verified_fixed",
                "verified": True,
                "label": "Verified fixed",
                "detail": (
                    "This remediation item was marked resolved and no longer appears "
                    "in the current remediation queue."
                ),
                "verification_status": "no_longer_observed",
                "verification_method": "current_queue_absence",
                **freshness,
                "closure_gate": (
                    "Closed only while the latest remediation queue and imported evidence "
                    "keep this finding absent."
                ),
                "next_check": (
                    "Keep importing fresh DMARC reports and refresh DNS evidence; reopen "
                    "the item if the same finding returns."
                ),
                "next_safe_action": (
                    "Keep monitoring fresh reports and DNS evidence before treating this "
                    "repair as permanently closed."
                ),
                "evidence_needed": [
                    "The latest lifecycle marker for this item is resolved.",
                    "The same item id is absent from the current remediation queue.",
                ],
                "recorded_at": _audit_timestamp(row.created_at),
                "operator_note": details.get("operator_note"),
                "actor_type": row.actor_type,
            }
        )
    return {"items": verified, "total": verified_total}


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
    verification = _verification_state(lifecycle_state, lifecycle.get("recorded_at"))

    operator_hold = lifecycle_state in OPERATOR_HELD_LIFECYCLE_STATES
    if operator_hold:
        label = _lifecycle_reason_label(lifecycle_state)
        blocked_reasons.append(f"Operator marked this remediation item {label}.")
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
        "verification": verification,
        "webhook_endpoint_count": webhook_count,
        "blocked_reasons": blocked_reasons,
        "would_enqueue": enabled and not blocked_reasons,
        "delivery_enqueued": False,
        "next_steps": _next_steps(blocked_reasons),
    }


def _verification_state(
    lifecycle_state: Optional[str],
    lifecycle_recorded_at: Optional[str],
) -> Dict[str, Any]:
    if lifecycle_state == "resolved":
        return {
            "state": "still_observed",
            "verified": False,
            "label": "Still observed",
            "detail": (
                "An operator marked this remediation item resolved, but current "
                "domain evidence still produces the same finding."
            ),
            "recorded_at": lifecycle_recorded_at,
        }
    if lifecycle_state in OPERATOR_HELD_LIFECYCLE_STATES:
        label = (
            LIFECYCLE_HISTORY_LABELS[lifecycle_state]
            if lifecycle_state == "mark_unknown"
            else str(lifecycle_state or "").replace("_", " ").title()
        )
        return {
            "state": f"operator_{lifecycle_state}",
            "verified": False,
            "label": label,
            "detail": "Operator hold is active; DMARQ will keep showing current evidence.",
            "recorded_at": lifecycle_recorded_at,
        }
    if lifecycle_state in ACKNOWLEDGED_LIFECYCLE_STATES:
        return {
            "state": "pending_operator_action",
            "verified": False,
            "label": "Pending action",
            "detail": "Operator reviewed this item; current evidence still needs remediation.",
            "recorded_at": lifecycle_recorded_at,
        }
    return {
        "state": "not_started",
        "verified": False,
        "label": "Not started",
        "detail": "No verification marker exists for this current remediation item.",
        "recorded_at": lifecycle_recorded_at,
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
    item_ids = [str(item.get("id") or "") for item in items]
    verified_fixed_result = _verified_fixed_items_result(
        db,
        workspace=workspace,
        domain=domain,
        current_item_ids=item_ids,
    )
    verified_fixed_items = verified_fixed_result["items"]
    queue["verified_items"] = verified_fixed_items
    queue["verified_items_total"] = verified_fixed_result["total"]
    if not items:
        _attach_dispatch_summary(
            queue,
            items,
            verified_fixed_items=verified_fixed_items,
            verified_fixed_total=verified_fixed_result["total"],
        )
        return queue
    settings = _settings(db)
    configured_events = _configured_events(settings.get(DISPATCH_EVENTS_KEY, ""))
    event_types = {str((item.get("notification") or {}).get("event") or "") for item in items}
    endpoints = _enabled_webhook_endpoints(db, workspace=workspace)
    histories = _notification_histories(
        db,
        workspace=workspace,
        domain=domain,
        item_ids=item_ids,
    )
    provider_plan_ids = [
        str((item.get("provider_repair_plan") or {}).get("plan_id") or "")
        for item in items
        if (item.get("provider_repair_plan") or {}).get("kind") == "dns_provider_repair"
    ]
    provider_attempts = _provider_repair_attempt_histories(
        db,
        workspace=workspace,
        domain=domain,
        plan_ids=provider_plan_ids,
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
        provider_plan_id = str((item.get("provider_repair_plan") or {}).get("plan_id") or "")
        _attach_provider_repair_attempt_history(
            item,
            provider_attempts.get(provider_plan_id, []),
        )
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
        verified_fixed_items=verified_fixed_items,
        verified_fixed_total=verified_fixed_result["total"],
    )
    return queue


def _attach_dispatch_summary(
    queue: Dict[str, Any],
    items: Sequence[Dict[str, Any]],
    *,
    webhook_event_route_keys: Optional[Dict[str, Set[str]]] = None,
    verified_fixed_items: Optional[Sequence[Dict[str, Any]]] = None,
    verified_fixed_total: Optional[int] = None,
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
    provider_attempt_histories = [
        (item.get("provider_repair_plan") or {}).get("attempt_history") or {}
        for item in items
    ]
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
            "dispatch_verified_fixed": (
                verified_fixed_total
                if verified_fixed_total is not None
                else len(verified_fixed_items or [])
            ),
            "dispatch_verified_fixed_visible": len(verified_fixed_items or []),
            "dispatch_verified_fixed_hidden": max(
                (
                    verified_fixed_total
                    if verified_fixed_total is not None
                    else len(verified_fixed_items or [])
                )
                - len(verified_fixed_items or []),
                0,
            ),
            "provider_apply_attempts": sum(
                len(history.get("entries") or []) for history in provider_attempt_histories
            ),
            "provider_apply_verified": sum(
                1
                for history in provider_attempt_histories
                for entry in history.get("entries") or []
                if entry.get("state") == "verified_after_apply"
            ),
        }
    )
    queue["summary"] = summary
