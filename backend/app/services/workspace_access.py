"""Workspace role and permission foundations."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership

ROLE_WORKSPACE_OWNER = "workspace_owner"
ROLE_DOMAIN_ADMIN = "domain_admin"
ROLE_OPERATOR = "operator"
ROLE_ANALYST = "analyst"
ROLE_AUDITOR = "auditor"

PERMISSION_WORKSPACE_ADMIN = "workspace:admin"
PERMISSION_DOMAINS_WRITE = "domains:write"
PERMISSION_MAIL_SOURCES_WRITE = "mail_sources:write"
PERMISSION_NOTIFICATIONS_WRITE = "notifications:write"
PERMISSION_INTEGRATIONS_WRITE = "integrations:write"
PERMISSION_AUDIT_READ = "audit:read"
PERMISSION_REPORTS_READ = "reports:read"
PERMISSION_REPORTS_WRITE = "reports:write"

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    ROLE_WORKSPACE_OWNER: {
        PERMISSION_WORKSPACE_ADMIN,
        PERMISSION_DOMAINS_WRITE,
        PERMISSION_MAIL_SOURCES_WRITE,
        PERMISSION_NOTIFICATIONS_WRITE,
        PERMISSION_INTEGRATIONS_WRITE,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
        PERMISSION_REPORTS_WRITE,
    },
    ROLE_DOMAIN_ADMIN: {
        PERMISSION_DOMAINS_WRITE,
        PERMISSION_MAIL_SOURCES_WRITE,
        PERMISSION_NOTIFICATIONS_WRITE,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
        PERMISSION_REPORTS_WRITE,
    },
    ROLE_OPERATOR: {
        PERMISSION_MAIL_SOURCES_WRITE,
        PERMISSION_NOTIFICATIONS_WRITE,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
        PERMISSION_REPORTS_WRITE,
    },
    ROLE_ANALYST: {
        PERMISSION_REPORTS_READ,
    },
    ROLE_AUDITOR: {
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
    },
}


def permissions_for_role(role: str) -> Set[str]:
    """Return normalized permissions for a workspace role."""
    return set(ROLE_PERMISSIONS.get((role or "").strip().lower(), set()))


def role_allows(role: str, permission: str) -> bool:
    """Return True when a role grants a permission."""
    return permission in permissions_for_role(role)


def list_workspace_roles() -> List[dict]:
    """Return API-safe role definitions for operator documentation and UI use."""
    return [
        {
            "role": role,
            "permissions": sorted(permissions),
        }
        for role, permissions in sorted(ROLE_PERMISSIONS.items())
    ]


def role_for_auth_context(auth_context: dict) -> str:
    """Map current admin auth into an initial workspace role.

    Existing non-workspace-aware endpoints keep owner-level access for any
    authenticated admin context until they are moved to workspace-aware checks.
    """
    auth_type = (auth_context or {}).get("auth_type")
    if auth_type in {"session", "bearer", "jwt", "api_key", "disabled"}:
        return ROLE_WORKSPACE_OWNER
    return ROLE_AUDITOR


def _auth_user_id(auth_context: dict) -> Optional[int]:
    user_id = (auth_context or {}).get("user_id")
    if user_id is not None:
        try:
            return int(user_id)
        except (TypeError, ValueError):
            return None

    payload = (auth_context or {}).get("payload") or {}
    subject = payload.get("sub")
    if subject is not None:
        try:
            return int(subject)
        except (TypeError, ValueError):
            return None
    return None


def _active_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email, User.is_active.is_(True)).first()


def _active_user_by_logto_id(db: Session, logto_id: str) -> Optional[User]:
    return db.query(User).filter(User.logto_id == logto_id, User.is_active.is_(True)).first()


def _auth_user(db: Session, auth_context: dict) -> Optional[User]:
    user_id = _auth_user_id(auth_context)
    if user_id is not None:
        return db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()

    payload = (auth_context or {}).get("payload") or {}
    subject = payload.get("sub")
    if subject:
        subject = str(subject)
        user = _active_user_by_logto_id(db, subject)
        if user is not None:
            return user
        user = _active_user_by_email(db, subject)
        if user is not None:
            return user

    email = payload.get("email") or (auth_context or {}).get("email")
    if email:
        return _active_user_by_email(db, str(email))
    return None


def role_for_workspace(
    db: Session,
    auth_context: dict,
    workspace: Workspace,
) -> str:
    """Resolve the caller's effective role for one workspace."""
    auth_type = (auth_context or {}).get("auth_type")
    if auth_type in {"api_key", "disabled"}:
        return ROLE_WORKSPACE_OWNER
    if auth_type == "api_token":
        try:
            token_workspace_id = int((auth_context or {}).get("workspace_id") or 0)
        except (TypeError, ValueError):
            token_workspace_id = 0
        if token_workspace_id == workspace.id:
            return ROLE_ANALYST

    user = _auth_user(db, auth_context)
    if user is None:
        return ""

    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.active.is_(True),
        )
        .first()
    )
    if membership is not None:
        return membership.role

    if user and user.workspace_id == workspace.id and user.is_superuser:
        return ROLE_WORKSPACE_OWNER
    return ""


def require_workspace_permission(
    auth_context: dict,
    permission: str,
    db: Optional[Session] = None,
    workspace: Optional[Workspace] = None,
) -> None:
    """Raise HTTP 403 when the current role does not grant a permission."""
    if db is not None and workspace is not None:
        role = role_for_workspace(db, auth_context, workspace)
    else:
        role = role_for_auth_context(auth_context)
    if role_allows(role, permission):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Workspace permission required: {permission}",
    )
