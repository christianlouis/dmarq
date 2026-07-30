"""Stateful, low-noise notification delivery for interpreted mail-health incidents."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.workspace import Workspace
from app.services.mail_health import build_workspace_mail_health_assessment
from app.services.mail_health_incidents import (
    record_incident_notification_result,
    record_mail_health_assessment,
)
from app.services.notifications import send_notification
from app.services.webhook_events import (
    EVENT_MAIL_HEALTH_INCIDENT_CHANGED,
    EVENT_MAIL_HEALTH_INCIDENT_CREATED,
    EVENT_MAIL_HEALTH_INCIDENT_RESOLVED,
    enqueue_webhook_event,
)

logger = logging.getLogger(__name__)
MAX_NOTIFICATIONS_PER_CYCLE = 5


def _incident_payload(incident: Dict[str, Any]) -> Dict[str, Any]:
    assessment = incident.get("assessment") or {}
    return {
        "incident_id": incident.get("id"),
        "domain": incident.get("domain"),
        "outcome": incident.get("outcome"),
        "intended_mail_impact": incident.get("intended_mail_impact"),
        "urgency": incident.get("urgency"),
        "confidence": incident.get("confidence"),
        "title": assessment.get("title"),
        "summary": assessment.get("summary"),
        "next_action": assessment.get("next_action"),
        "freshness": assessment.get("freshness"),
    }


def _message(incident: Dict[str, Any]) -> tuple[str, str]:
    assessment = incident.get("assessment") or {}
    action = assessment.get("next_action") or {}
    base_url = str(get_settings().PUBLIC_BASE_URL or "").rstrip("/")
    href = str(action.get("href") or assessment.get("href") or "/")
    deep_link = f"{base_url}{href}" if base_url else href
    title = str(assessment.get("title") or "DMARQ found a mail-health issue")
    body = "\n".join(
        [
            f"What happened: {assessment.get('summary') or title}",
            f"Intended mail impact: {assessment.get('intended_mail_impact') or 'unknown'}",
            f"Next action: {action.get('label') or assessment.get('next_step') or 'Review evidence'}",
            f"Urgency: {assessment.get('urgency') or 'monitor'} · Confidence: {assessment.get('confidence') or 'unknown'}",
            f"Evidence freshness: {assessment.get('freshness') or 'unknown'}",
            f"Open: {deep_link}",
        ]
    )
    return title, body


def evaluate_and_send_calm_watch(db: Session, *, days: int = 30) -> Dict[str, Any]:
    """Evaluate every active workspace and interrupt only for incident state changes."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=max(1, min(days, 365)))
    sent = []
    suppressed = []
    resolved = []
    for workspace in db.query(Workspace).filter(Workspace.active.is_(True)).order_by(Workspace.id):
        assessment = build_workspace_mail_health_assessment(
            db,
            workspace=workspace,
            start_ts=int(start.timestamp()),
            end_ts=int(now.timestamp()),
        )
        lifecycle = record_mail_health_assessment(db, workspace=workspace, assessment=assessment)
        for item in lifecycle.get("resolved") or []:
            resolved.append(item)
            enqueue_webhook_event(
                db,
                workspace_id=workspace.id,
                event_type=EVENT_MAIL_HEALTH_INCIDENT_RESOLVED,
                payload=_incident_payload(item),
                idempotency_key=f"calm-watch:resolved:{item.get('id')}:{item.get('resolved_at')}",
            )
        incident = lifecycle.get("incident")
        reason = lifecycle.get("notification_reason")
        if not incident or not reason:
            suppressed.append({"workspace_id": workspace.id, "reason": "unchanged_or_suppressed"})
            continue
        event_type = (
            EVENT_MAIL_HEALTH_INCIDENT_CREATED
            if reason in {"created", "pending_delivery"}
            else EVENT_MAIL_HEALTH_INCIDENT_CHANGED
        )
        enqueue_webhook_event(
            db,
            workspace_id=workspace.id,
            event_type=event_type,
            payload=_incident_payload(incident),
            idempotency_key=(
                f"calm-watch:{reason}:{incident.get('id')}:"
                f"{incident.get('last_material_change_at')}"
            ),
        )
        if len(sent) >= MAX_NOTIFICATIONS_PER_CYCLE:
            suppressed.append({"workspace_id": workspace.id, "reason": "cycle_cap"})
            continue
        title, body = _message(incident)
        result = send_notification(
            db,
            title=title,
            body=body,
            bypass_rate_limit=True,
        ).to_dict()
        record_incident_notification_result(
            db,
            workspace=workspace,
            incident_id=int(incident["id"]),
            reason=reason,
            result=result,
        )
        (sent if result.get("success") else suppressed).append(
            {"workspace_id": workspace.id, "incident_id": incident.get("id"), "result": result}
        )
    return {"sent": sent, "suppressed": suppressed, "resolved": resolved}
