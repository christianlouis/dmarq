"""Calm, workspace-scoped lifecycle for interpreted mail-health assessments."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import MailHealthIncident
from app.models.workspace import Workspace
from app.services.workspace_audit import record_workspace_audit_log

ACTIONABLE_OUTCOMES = {"action_required", "investigation_required"}
NOTIFICATION_POSTURES = {"actionable_only", "important_plus_digest", "all_signals", "disabled"}


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: object) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _incident_key(workspace: Workspace, assessment: Dict[str, Any]) -> str:
    """Keep one incident identity through threshold/configuration changes."""
    return _hash(
        {
            "workspace_id": workspace.id,
            "domain": assessment.get("domain"),
            "outcome": assessment.get("outcome"),
            "assessment_version": assessment.get("assessment_version"),
        }
    )


def _material_state(assessment: Dict[str, Any]) -> str:
    """Only lifecycle-relevant changes qualify for another human interruption."""
    return _hash(
        {
            "outcome": assessment.get("outcome"),
            "domain": assessment.get("domain"),
            "intended_mail_impact": assessment.get("intended_mail_impact"),
            "urgency": assessment.get("urgency"),
            "confidence": assessment.get("confidence"),
            "next_action": assessment.get("next_action", {}).get("href"),
            "assessment_version": assessment.get("assessment_version"),
        }
    )


def incident_to_dict(row: MailHealthIncident, *, notification_reason: Optional[str] = None) -> Dict[str, Any]:
    try:
        assessment = json.loads(row.assessment)
    except (TypeError, ValueError, json.JSONDecodeError):
        assessment = {}
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "domain": row.domain,
        "incident_key": row.incident_key,
        "outcome": row.outcome,
        "intended_mail_impact": row.intended_mail_impact,
        "urgency": row.urgency,
        "confidence": row.confidence,
        "status": row.status,
        "assessment": assessment,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "last_material_change_at": row.last_material_change_at.isoformat() if row.last_material_change_at else None,
        "last_notified_at": row.last_notified_at.isoformat() if row.last_notified_at else None,
        "last_notification_reason": row.last_notification_reason,
        "snoozed_until": row.snoozed_until.isoformat() if row.snoozed_until else None,
        "operator_note": row.operator_note,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "resolution_evidence": row.resolution_evidence,
        "notification_reason": notification_reason,
    }


def _should_notify(
    workspace: Workspace,
    assessment: Dict[str, Any],
    *,
    is_new: bool,
    materially_changed: bool,
    now: datetime,
    row: MailHealthIncident,
) -> Optional[str]:
    posture = workspace.notification_posture or "actionable_only"
    if posture == "disabled" or (
        row.status == "snoozed" and row.snoozed_until and row.snoozed_until > now
    ):
        return None
    outcome = str(assessment.get("outcome") or "")
    if outcome not in ACTIONABLE_OUTCOMES and posture != "all_signals":
        return None
    if is_new:
        return "created"
    if materially_changed:
        return "material_change"
    return None


def _resolve_active_incidents(
    db: Session,
    *,
    workspace: Workspace,
    domain: Optional[str],
    now: datetime,
    evidence: str,
) -> List[MailHealthIncident]:
    query = db.query(MailHealthIncident).filter(
        MailHealthIncident.workspace_id == workspace.id,
        MailHealthIncident.status.in_(["open", "acknowledged", "snoozed"]),
    )
    if domain:
        query = query.filter(MailHealthIncident.domain == domain)
    resolved = query.all()
    for row in resolved:
        row.status = "resolved"
        row.resolved_at = now
        row.resolution_evidence = evidence
        row.last_seen_at = now
    return resolved


def _resolve_superseded_incidents(
    db: Session,
    *,
    workspace: Workspace,
    domain: Optional[str],
    outcome: str,
    now: datetime,
) -> None:
    for previous in (
        db.query(MailHealthIncident)
        .filter(
            MailHealthIncident.workspace_id == workspace.id,
            MailHealthIncident.domain == domain,
            MailHealthIncident.outcome != outcome,
            MailHealthIncident.status.in_(["open", "acknowledged", "snoozed"]),
        )
        .all()
    ):
        previous.status = "resolved"
        previous.resolved_at = now
        previous.resolution_evidence = "Superseded by a newer report-backed assessment."
        previous.last_seen_at = now


def _create_incident_row(
    db: Session,
    *,
    workspace: Workspace,
    assessment: Dict[str, Any],
    key: str,
    state_hash: str,
    outcome: str,
    domain: Optional[str],
    now: datetime,
) -> tuple[MailHealthIncident, bool, bool]:
    """Create an incident, tolerating a concurrent insert for the same key."""
    _resolve_superseded_incidents(db, workspace=workspace, domain=domain, outcome=outcome, now=now)
    row = MailHealthIncident(
        workspace_id=workspace.id,
        domain=domain,
        incident_key=key,
        outcome=outcome,
        intended_mail_impact=str(assessment.get("intended_mail_impact") or "unknown"),
        urgency=str(assessment.get("urgency") or "monitor"),
        confidence=str(assessment.get("confidence") or "Not enough evidence"),
        status="open",
        material_state_hash=state_hash,
        assessment=_json(assessment),
        first_seen_at=now,
        last_seen_at=now,
        last_material_change_at=now,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        # Concurrent scheduler/manual evaluations can reach this branch together.
        # Reuse the first committed incident instead of failing.
        row = db.query(MailHealthIncident).filter(MailHealthIncident.incident_key == key).one()
        return row, False, row.material_state_hash != state_hash
    return row, True, False


def _update_incident_row(
    row: MailHealthIncident,
    *,
    assessment: Dict[str, Any],
    state_hash: str,
    outcome: str,
    domain: Optional[str],
    now: datetime,
) -> bool:
    materially_changed = row.material_state_hash != state_hash
    row.domain = domain
    row.outcome = outcome
    row.intended_mail_impact = str(assessment.get("intended_mail_impact") or "unknown")
    row.urgency = str(assessment.get("urgency") or "monitor")
    row.confidence = str(assessment.get("confidence") or "Not enough evidence")
    row.assessment = _json(assessment)
    row.last_seen_at = now
    if row.status == "resolved":
        row.status = "open"
        materially_changed = True
    if materially_changed:
        row.material_state_hash = state_hash
        row.last_material_change_at = now
    return materially_changed


def record_mail_health_assessment(
    db: Session,
    *,
    workspace: Workspace,
    assessment: Dict[str, Any],
    observed_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Upsert one assessment and return its interrupt-or-suppress decision."""
    now = observed_at or datetime.now(timezone.utc).replace(tzinfo=None)
    outcome = str(assessment.get("outcome") or "insufficient_evidence")
    domain = assessment.get("domain")

    if outcome in {"healthy", "insufficient_evidence"}:
        resolved = _resolve_active_incidents(
            db,
            workspace=workspace,
            domain=domain,
            now=now,
            evidence="A fresh report-backed assessment no longer found this actionable state.",
        )
        db.commit()
        return {"incident": None, "notification_reason": None, "resolved": [incident_to_dict(row) for row in resolved]}

    key = _incident_key(workspace, assessment)
    state_hash = _material_state(assessment)
    row = db.query(MailHealthIncident).filter(MailHealthIncident.incident_key == key).one_or_none()
    is_new = row is None
    if row is None:
        row, is_new, materially_changed = _create_incident_row(
            db,
            workspace=workspace,
            assessment=assessment,
            key=key,
            state_hash=state_hash,
            outcome=outcome,
            domain=domain,
            now=now,
        )
    if not is_new:
        materially_changed = _update_incident_row(
            row,
            assessment=assessment,
            state_hash=state_hash,
            outcome=outcome,
            domain=domain,
            now=now,
        )

    db.flush()
    reason = _should_notify(
        workspace, assessment, is_new=is_new, materially_changed=materially_changed, now=now, row=row
    )
    if reason:
        row.last_notified_at = now
        row.last_notification_reason = reason
    db.commit()
    db.refresh(row)
    return {"incident": incident_to_dict(row, notification_reason=reason), "notification_reason": reason, "resolved": []}


def list_mail_health_incidents(db: Session, *, workspace: Workspace, limit: int = 50) -> List[Dict[str, Any]]:
    rows = (
        db.query(MailHealthIncident)
        .filter(MailHealthIncident.workspace_id == workspace.id)
        .order_by(MailHealthIncident.last_seen_at.desc(), MailHealthIncident.id.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [incident_to_dict(row) for row in rows]


def update_incident_operator_state(
    db: Session,
    *,
    workspace: Workspace,
    incident_id: int,
    action: str,
    note: Optional[str],
    snoozed_until: Optional[datetime],
    auth_context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    row = (
        db.query(MailHealthIncident)
        .filter(MailHealthIncident.id == incident_id, MailHealthIncident.workspace_id == workspace.id)
        .one_or_none()
    )
    if row is None:
        raise LookupError("Mail-health incident was not found in this workspace.")
    if action == "acknowledge":
        row.status = "acknowledged"
    elif action == "snooze":
        if snoozed_until is None:
            raise ValueError("A snooze-until timestamp is required.")
        row.status = "snoozed"
        row.snoozed_until = snoozed_until
    else:
        raise ValueError("Unsupported incident action.")
    row.operator_note = (note or "").strip()[:500] or None
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action=f"mail_health_incident_{action}",
        entity_type="mail_health_incident",
        entity_id=row.id,
        entity_name=row.domain,
        details={"status": row.status, "snoozed_until": row.snoozed_until.isoformat() if row.snoozed_until else None},
        auth_context=auth_context,
    )
    db.commit()
    db.refresh(row)
    return incident_to_dict(row)
