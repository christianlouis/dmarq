"""Workspace RBAC and audit endpoints."""

import csv
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.workspace_access import WorkspaceAuditLog
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    PERMISSION_WORKSPACE_ADMIN,
    list_workspace_roles,
    parse_selected_workspace_id,
    require_workspace_permission,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import (
    audit_log_to_dict,
    build_enterprise_audit_export,
    list_workspace_audit_logs,
    record_workspace_audit_log,
)
from app.services.workspaces import assign_default_workspace_to_unscoped_rows, get_default_workspace

router = APIRouter()


class WorkspaceRoleResponse(BaseModel):
    """Workspace role and permission definitions."""

    roles: List[Dict[str, Any]]


class WorkspaceAuditLogResponse(BaseModel):
    """Workspace audit log list response."""

    audit: List[Dict[str, Any]]


class SupportAccessGrantRequest(BaseModel):
    """Explicit customer-approved support access grant."""

    approved_principal: str = Field(..., min_length=3, max_length=255)
    reason: str = Field(..., min_length=5, max_length=1000)
    expires_at: datetime
    scope: str = Field(default="read_only_diagnostics", max_length=80)


class SupportAccessRevokeRequest(BaseModel):
    """Reason for revoking an approved support access grant."""

    reason: str = Field(default="Revoked by workspace administrator", max_length=1000)


class SupportAccessGrantResponse(BaseModel):
    """Visible support access grant state."""

    grants: List[Dict[str, Any]]


ENTERPRISE_AUDIT_EXPORT_FIELDS = [
    "category",
    "workspace_id",
    "organization_id",
    "actor_type",
    "actor_id",
    "action",
    "entity_type",
    "entity_id",
    "entity_name",
    "details",
    "ip_address",
    "created_at",
]

SUPPORT_ACCESS_ENTITY_TYPE = "support_access_grant"
SUPPORT_ACCESS_CREATED_ACTION = "support_access.grant_created"
SUPPORT_ACCESS_REVOKED_ACTION = "support_access.grant_revoked"


def _authorized_audit_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    selected_workspace_id: Optional[int] = None,
):
    """Resolve the selected audit workspace without unsafe legacy bootstrapping."""
    if selected_workspace_id is not None:
        return resolve_authorized_workspace(
            db,
            auth_context,
            PERMISSION_AUDIT_READ,
            selected_workspace_id=selected_workspace_id,
        )

    workspace = get_default_workspace(db)
    if workspace is None:
        if (auth_context or {}).get("auth_type") not in {"api_key", "disabled"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Workspace permission required: {PERMISSION_AUDIT_READ}",
            )
        workspace = assign_default_workspace_to_unscoped_rows(db)
    require_workspace_permission(auth_context, PERMISSION_AUDIT_READ, db, workspace)
    return assign_default_workspace_to_unscoped_rows(db)


def _authorized_support_admin_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    selected_workspace_id: Optional[int] = None,
):
    """Resolve the workspace for explicit support-access administration."""
    return resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_WORKSPACE_ADMIN,
        selected_workspace_id=selected_workspace_id,
    )


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _support_access_grant_from_audit(row) -> Dict[str, Any]:
    audit_row = audit_log_to_dict(row)
    details = audit_row.get("details") or {}
    expires_at = _parse_timestamp(details.get("expires_at"))
    now = datetime.now(timezone.utc)
    status_value = str(details.get("status") or "active")
    expired = bool(expires_at and expires_at <= now)
    status_value = "expired" if status_value == "active" and expired else status_value
    return {
        "id": audit_row.get("entity_id"),
        "workspace_id": audit_row.get("workspace_id"),
        "approved_principal": details.get("approved_principal"),
        "scope": details.get("scope"),
        "reason": details.get("reason"),
        "status": status_value,
        "expires_at": details.get("expires_at"),
        "created_at": audit_row.get("created_at"),
        "last_changed_at": audit_row.get("created_at"),
        "last_action": audit_row.get("action"),
        "actor_type": audit_row.get("actor_type"),
        "actor_id": audit_row.get("actor_id"),
    }


def _list_latest_support_access_grants(
    db: Session,
    *,
    workspace,
    include_inactive: bool = False,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    rows = (
        db.query(WorkspaceAuditLog)
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.entity_type == SUPPORT_ACCESS_ENTITY_TYPE,
        )
        .order_by(
            WorkspaceAuditLog.created_at.desc(),
            WorkspaceAuditLog.id.desc(),
        )
        .limit(max(1, min(limit * 5, 500)))
        .all()
    )
    grants: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        entity_id = str(row.entity_id or "")
        if not entity_id or entity_id in seen:
            continue
        seen.add(entity_id)
        grant = _support_access_grant_from_audit(row)
        if include_inactive or grant["status"] == "active":
            grants.append(grant)
        if len(grants) >= limit:
            break
    return grants


@router.get("/roles", response_model=WorkspaceRoleResponse)
async def get_workspace_roles(
    _auth: dict = Depends(require_admin_auth),
) -> WorkspaceRoleResponse:
    """Return the supported workspace role definitions."""
    return {"roles": list_workspace_roles()}


@router.get("/logs", response_model=WorkspaceAuditLogResponse)
async def get_workspace_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> WorkspaceAuditLogResponse:
    """Return recent sanitized audit events for the selected workspace."""
    workspace = _authorized_audit_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    return {
        "audit": list_workspace_audit_logs(
            db,
            workspace=workspace,
            limit=limit,
            action=action,
            entity_type=entity_type,
        )
    }


@router.get("/support-access/grants", response_model=SupportAccessGrantResponse)
async def list_support_access_grants(
    include_inactive: bool = False,
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> SupportAccessGrantResponse:
    """Return visible support-access grants for the selected workspace."""
    workspace = _authorized_audit_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    return {
        "grants": _list_latest_support_access_grants(
            db,
            workspace=workspace,
            include_inactive=include_inactive,
            limit=limit,
        )
    }


@router.post(
    "/support-access/grants",
    response_model=SupportAccessGrantResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_support_access_grant(
    payload: SupportAccessGrantRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> SupportAccessGrantResponse:
    """Create an explicit, time-boxed support access approval marker."""
    workspace = _authorized_support_admin_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    expires_at = _parse_timestamp(payload.expires_at)
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="expires_at must be a future timestamp",
        )
    grant_id = uuid4().hex
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action=SUPPORT_ACCESS_CREATED_ACTION,
        entity_type=SUPPORT_ACCESS_ENTITY_TYPE,
        entity_id=grant_id,
        entity_name=payload.approved_principal,
        details={
            "status": "active",
            "approved_principal": payload.approved_principal,
            "scope": payload.scope,
            "reason": payload.reason,
            "expires_at": expires_at.isoformat(),
            "impersonation_enabled": False,
            "customer_visible": True,
        },
        request=request,
        auth_context=_auth,
        commit=True,
    )
    return {
        "grants": _list_latest_support_access_grants(
            db,
            workspace=workspace,
            include_inactive=True,
            limit=1,
        )
    }


@router.post("/support-access/grants/{grant_id}/revoke", response_model=SupportAccessGrantResponse)
async def revoke_support_access_grant(
    grant_id: str,
    payload: SupportAccessRevokeRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> SupportAccessGrantResponse:
    """Revoke a previously approved support access grant."""
    workspace = _authorized_support_admin_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    existing = (
        db.query(WorkspaceAuditLog)
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.entity_type == SUPPORT_ACCESS_ENTITY_TYPE,
            WorkspaceAuditLog.entity_id == grant_id,
        )
        .order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
        .first()
    )
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Support access grant not found",
        )
    existing_grant = _support_access_grant_from_audit(existing)
    if existing_grant["status"] == "revoked":
        return {"grants": [existing_grant]}
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action=SUPPORT_ACCESS_REVOKED_ACTION,
        entity_type=SUPPORT_ACCESS_ENTITY_TYPE,
        entity_id=grant_id,
        entity_name=existing.entity_name,
        details={
            "status": "revoked",
            "approved_principal": existing_grant.get("approved_principal"),
            "scope": existing_grant.get("scope"),
            "reason": payload.reason,
            "expires_at": existing_grant.get("expires_at"),
            "customer_visible": True,
        },
        request=request,
        auth_context=_auth,
        commit=True,
    )
    latest = (
        db.query(WorkspaceAuditLog)
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.entity_type == SUPPORT_ACCESS_ENTITY_TYPE,
            WorkspaceAuditLog.entity_id == grant_id,
        )
        .order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
        .first()
    )
    return {"grants": [_support_access_grant_from_audit(latest)] if latest else []}


@router.get("/export")
async def export_enterprise_audit_logs(
    limit: int = Query(1000, ge=1, le=5000),
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Export sanitized enterprise audit rows for the selected workspace/account."""
    workspace = _authorized_audit_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    rows = build_enterprise_audit_export(
        db,
        workspace=workspace,
        limit=limit,
        action=action,
        entity_type=entity_type,
    )
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=ENTERPRISE_AUDIT_EXPORT_FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    filename = f"{workspace.slug.replace('/', '_')}-enterprise-audit.csv"
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
