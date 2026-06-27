"""Current-user workspace context endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspace_access import (
    ROLE_ANALYST,
    ROLE_WORKSPACE_OWNER,
    _auth_user,
    is_platform_admin_auth,
    permissions_for_role,
)

router = APIRouter()


class WorkspaceContextResponse(BaseModel):
    """Visible workspace context for client-side scope selection."""

    workspaces: List[Dict[str, Any]]
    default_workspace_id: Optional[int] = None


def _workspace_context_row(
    workspace: Workspace,
    role: str,
) -> Optional[Dict[str, Any]]:
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


def _visible_workspace_roles(db: Session, auth_context: dict) -> Dict[int, str]:
    if is_platform_admin_auth(auth_context):
        return {
            workspace_id: ROLE_WORKSPACE_OWNER
            for (workspace_id,) in db.query(Workspace.id).all()
        }

    if (auth_context or {}).get("auth_type") == "api_token":
        try:
            workspace_id = int((auth_context or {}).get("workspace_id") or 0)
        except (TypeError, ValueError):
            workspace_id = 0
        return {workspace_id: ROLE_ANALYST} if workspace_id else {}

    user = _auth_user(db, auth_context)
    if user is None:
        return {}

    rows = (
        db.query(WorkspaceMembership.workspace_id, WorkspaceMembership.role)
        .filter(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.active.is_(True),
        )
        .all()
    )
    roles = {workspace_id: role for workspace_id, role in rows}
    if user.is_superuser and user.workspace_id:
        roles.setdefault(user.workspace_id, ROLE_WORKSPACE_OWNER)
    return roles


@router.get("", response_model=WorkspaceContextResponse)
async def list_visible_workspaces(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> WorkspaceContextResponse:
    """Return workspaces visible to the current admin/session context."""
    roles_by_workspace = _visible_workspace_roles(db, _auth)
    if not roles_by_workspace:
        return {"workspaces": [], "default_workspace_id": None}
    workspaces = (
        db.query(Workspace)
        .options(selectinload(Workspace.organization))
        .filter(Workspace.id.in_(list(roles_by_workspace)))
        .order_by(Workspace.active.desc(), Workspace.slug.asc())
        .all()
    )
    visible = []
    for workspace in workspaces:
        row = _workspace_context_row(workspace, roles_by_workspace.get(workspace.id, ""))
        if row is not None:
            visible.append(row)
    default_workspace_id = visible[0]["id"] if visible else None
    return {"workspaces": visible, "default_workspace_id": default_workspace_id}
