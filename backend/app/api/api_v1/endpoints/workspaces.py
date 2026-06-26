"""Current-user workspace context endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.workspace import Workspace
from app.services.workspace_access import (
    permissions_for_role,
    role_for_workspace,
)

router = APIRouter()


class WorkspaceContextResponse(BaseModel):
    """Visible workspace context for client-side scope selection."""

    workspaces: List[Dict[str, Any]]
    default_workspace_id: Optional[int] = None


def _workspace_context_row(
    db: Session,
    auth_context: dict,
    workspace: Workspace,
) -> Optional[Dict[str, Any]]:
    role = role_for_workspace(db, auth_context, workspace)
    if not role:
        return None
    organization = workspace.organization
    return {
        "id": workspace.id,
        "slug": workspace.slug,
        "name": workspace.name,
        "active": bool(workspace.active),
        "organization": (
            {
                "id": organization.id,
                "slug": organization.slug,
                "name": organization.name,
                "active": bool(organization.active),
            }
            if organization is not None
            else None
        ),
        "effective_role": role,
        "permissions": sorted(permissions_for_role(role)),
    }


@router.get("", response_model=WorkspaceContextResponse)
async def list_visible_workspaces(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> WorkspaceContextResponse:
    """Return workspaces visible to the current admin/session context."""
    workspaces = db.query(Workspace).order_by(Workspace.active.desc(), Workspace.slug.asc()).all()
    visible = [
        row
        for workspace in workspaces
        if (row := _workspace_context_row(db, _auth, workspace)) is not None
    ]
    default_workspace_id = visible[0]["id"] if visible else None
    return {"workspaces": visible, "default_workspace_id": default_workspace_id}
