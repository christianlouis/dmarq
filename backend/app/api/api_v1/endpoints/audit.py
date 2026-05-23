"""Workspace RBAC and audit endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    list_workspace_roles,
    require_workspace_permission,
)
from app.services.workspace_audit import list_workspace_audit_logs
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

router = APIRouter()


class WorkspaceRoleResponse(BaseModel):
    """Workspace role and permission definitions."""

    roles: List[Dict[str, Any]]


class WorkspaceAuditLogResponse(BaseModel):
    """Workspace audit log list response."""

    audit: List[Dict[str, Any]]


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
) -> WorkspaceAuditLogResponse:
    """Return recent sanitized audit events for the default workspace."""
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    workspace = assign_default_workspace_to_unscoped_rows(db)
    return {
        "audit": list_workspace_audit_logs(
            db,
            workspace=workspace,
            limit=limit,
            action=action,
            entity_type=entity_type,
        )
    }
