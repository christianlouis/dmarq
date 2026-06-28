"""Workspace RBAC and audit endpoints."""

import csv
from io import StringIO
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    list_workspace_roles,
    parse_selected_workspace_id,
    require_workspace_permission,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import build_enterprise_audit_export, list_workspace_audit_logs
from app.services.workspaces import assign_default_workspace_to_unscoped_rows, get_default_workspace

router = APIRouter()


class WorkspaceRoleResponse(BaseModel):
    """Workspace role and permission definitions."""

    roles: List[Dict[str, Any]]


class WorkspaceAuditLogResponse(BaseModel):
    """Workspace audit log list response."""

    audit: List[Dict[str, Any]]


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
