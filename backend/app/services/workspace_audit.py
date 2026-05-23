"""Sanitized workspace audit logging helpers."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from fastapi import Request
from sqlalchemy.orm import Session

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


def changed_fields(fields: Iterable[str]) -> List[str]:
    """Return sorted field names safe for audit details."""
    return sorted({str(field) for field in fields})
