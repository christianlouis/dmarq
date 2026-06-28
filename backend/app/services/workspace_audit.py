"""Sanitized workspace audit logging helpers."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.organization import BillingEvent, Entitlement
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog

SECRET_FIELD_MARKERS = (
    "password",
    "secret",
    "token",
    "credential",
    "authorization",
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "webhook_secret",
)


def _is_secret_key(key: str) -> bool:
    normalized = key.lower()
    return any(marker in normalized for marker in SECRET_FIELD_MARKERS)


def sanitize_audit_details(value: Any) -> Any:
    """Return a JSON-serializable value with secret-like fields redacted."""
    if isinstance(value, dict):
        return {
            str(key): "[redacted]" if _is_secret_key(str(key)) else sanitize_audit_details(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def actor_from_auth(auth_context: Optional[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    """Normalize an auth context into audit actor fields."""
    auth_context = auth_context or {}
    auth_type = str(auth_context.get("auth_type") or "unknown")
    actor_id: Optional[str] = None
    if auth_context.get("user_id") is not None:
        actor_id = str(auth_context["user_id"])
    elif auth_context.get("payload", {}).get("sub"):
        actor_id = str(auth_context["payload"]["sub"])
    elif auth_context.get("token_id") is not None:
        actor_id = str(auth_context["token_id"])
    elif auth_type:
        actor_id = auth_type
    return {"actor_type": auth_type, "actor_id": actor_id}


def client_ip_from_request(request: Optional[Request]) -> Optional[str]:
    """Return the client IP address from a FastAPI request, if available."""
    if request is None:
        return None
    forwarded_for = (request.headers.get("x-forwarded-for") or "").split(",", maxsplit=1)[0]
    if forwarded_for.strip():
        return forwarded_for.strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    if request.client is None:
        return None
    return request.client.host


def record_workspace_audit_log(
    db: Session,
    *,
    workspace: Workspace,
    action: str,
    entity_type: str,
    auth_context: Optional[Dict[str, Any]] = None,
    entity_id: Optional[Any] = None,
    entity_name: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
    created_at: Optional[datetime] = None,
    commit: bool = False,
) -> WorkspaceAuditLog:
    """Persist one sanitized workspace audit event."""
    actor = actor_from_auth(auth_context)
    safe_details = sanitize_audit_details(details or {})
    row = WorkspaceAuditLog(
        workspace_id=workspace.id,
        actor_type=actor["actor_type"] or "unknown",
        actor_id=actor["actor_id"],
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        entity_name=entity_name,
        details=json.dumps(safe_details, sort_keys=True),
        ip_address=client_ip_from_request(request),
        created_at=created_at or datetime.utcnow(),
    )
    db.add(row)
    if commit:
        db.commit()
        db.refresh(row)
    else:
        db.flush()
    return row


def audit_log_to_dict(row: WorkspaceAuditLog) -> Dict[str, Any]:
    """Return an API-safe audit row."""
    try:
        details = json.loads(row.details or "{}")
    except (json.JSONDecodeError, TypeError):
        details = {}
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "actor_type": row.actor_type,
        "actor_id": row.actor_id,
        "action": row.action,
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "entity_name": row.entity_name,
        "details": details,
        "ip_address": row.ip_address,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def list_workspace_audit_logs(
    db: Session,
    *,
    workspace: Workspace,
    limit: int = 50,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return recent audit logs for a workspace."""
    query = db.query(WorkspaceAuditLog).filter(WorkspaceAuditLog.workspace_id == workspace.id)
    if action:
        query = query.filter(WorkspaceAuditLog.action == action)
    if entity_type:
        query = query.filter(WorkspaceAuditLog.entity_type == entity_type)
    rows = (
        query.order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [audit_log_to_dict(row) for row in rows]


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _enterprise_audit_row(
    *,
    category: str,
    workspace_id: Optional[int],
    organization_id: Optional[int],
    actor_type: str,
    actor_id: Optional[str],
    action: str,
    entity_type: str,
    entity_id: Optional[Any],
    entity_name: Optional[str],
    details: Optional[Dict[str, Any]],
    ip_address: Optional[str],
    created_at: Optional[datetime],
) -> Dict[str, Any]:
    safe_details = sanitize_audit_details(details or {})
    return {
        "category": category,
        "workspace_id": workspace_id,
        "organization_id": organization_id,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "entity_type": entity_type,
        "entity_id": str(entity_id) if entity_id is not None else None,
        "entity_name": entity_name,
        "details": json.dumps(safe_details, sort_keys=True),
        "ip_address": ip_address,
        "created_at": _iso(created_at),
    }


def build_enterprise_audit_export(
    db: Session,
    *,
    workspace: Workspace,
    limit: int = 1000,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return sanitized audit rows suitable for enterprise CSV exports."""
    row_limit = max(1, min(limit, 5000))
    rows: List[Dict[str, Any]] = []
    organization_id = workspace.organization_id
    audit_query = db.query(WorkspaceAuditLog).filter(WorkspaceAuditLog.workspace_id == workspace.id)
    if action:
        audit_query = audit_query.filter(WorkspaceAuditLog.action == action)
    if entity_type:
        audit_query = audit_query.filter(WorkspaceAuditLog.entity_type == entity_type)
    for audit_row in (
        audit_query.order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
        .limit(row_limit)
        .all()
    ):
        rows.append(
            _enterprise_audit_row(
                category="workspace_audit",
                workspace_id=audit_row.workspace_id,
                organization_id=organization_id,
                actor_type=audit_row.actor_type,
                actor_id=audit_row.actor_id,
                action=audit_row.action,
                entity_type=audit_row.entity_type,
                entity_id=audit_row.entity_id,
                entity_name=audit_row.entity_name,
                details=audit_log_to_dict(audit_row)["details"],
                ip_address=audit_row.ip_address,
                created_at=audit_row.created_at,
            )
        )

    if organization_id is not None:
        for billing_event in (
            db.query(BillingEvent)
            .filter(BillingEvent.organization_id == organization_id)
            .order_by(BillingEvent.created_at.desc(), BillingEvent.id.desc())
            .limit(row_limit)
            .all()
        ):
            rows.append(
                _enterprise_audit_row(
                    category="billing_event",
                    workspace_id=None,
                    organization_id=organization_id,
                    actor_type="system",
                    actor_id=billing_event.provider_id or billing_event.billing_mode,
                    action=billing_event.event_type,
                    entity_type="billing_event",
                    entity_id=billing_event.id,
                    entity_name=billing_event.external_event_id,
                    details={
                        "billing_mode": billing_event.billing_mode,
                        "provider_id": billing_event.provider_id,
                        "external_event_id": billing_event.external_event_id,
                        "status": billing_event.status,
                        "payload_summary_present": bool(billing_event.payload_summary),
                        "subscription_id": billing_event.subscription_id,
                    },
                    ip_address=None,
                    created_at=billing_event.created_at,
                )
            )
        for entitlement in (
            db.query(Entitlement)
            .filter(Entitlement.organization_id == organization_id)
            .order_by(Entitlement.updated_at.desc().nullslast(), Entitlement.id.desc())
            .limit(row_limit)
            .all()
        ):
            rows.append(
                _enterprise_audit_row(
                    category="entitlement",
                    workspace_id=None,
                    organization_id=organization_id,
                    actor_type="system",
                    actor_id=entitlement.source,
                    action="entitlement.active" if entitlement.active else "entitlement.inactive",
                    entity_type="entitlement",
                    entity_id=entitlement.id,
                    entity_name=entitlement.key,
                    details={
                        "key": entitlement.key,
                        "value": entitlement.value,
                        "source": entitlement.source,
                        "subscription_id": entitlement.subscription_id,
                        "effective_from": _iso(entitlement.effective_from),
                        "expires_at": _iso(entitlement.expires_at),
                    },
                    ip_address=None,
                    created_at=entitlement.updated_at or entitlement.created_at,
                )
            )

    rows.sort(key=lambda row: (row["created_at"] or "", row["category"]), reverse=True)
    return rows[:row_limit]


def changed_fields(fields: Iterable[str]) -> List[str]:
    """Return sorted field names safe for audit details."""
    return sorted({str(field) for field in fields})
