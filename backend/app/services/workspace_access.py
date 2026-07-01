"""Workspace role and permission foundations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from fastapi import HTTPException, status
from sqlalchemy import case
from sqlalchemy.orm import Session

from app.models.organization import Organization, OrganizationMembership, Subscription
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.organizations import (
    ACCOUNT_ACTIVE_STATUSES,
    ACCOUNT_CLOSED_STATUSES,
    ACCOUNT_GRACE_STATUSES,
    account_state_for_subscriptions,
)
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

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
TENANT_MUTATION_PERMISSIONS = {
    PERMISSION_WORKSPACE_ADMIN,
    PERMISSION_DOMAINS_WRITE,
    PERMISSION_MAIL_SOURCES_WRITE,
    PERMISSION_NOTIFICATIONS_WRITE,
    PERMISSION_INTEGRATIONS_WRITE,
    PERMISSION_REPORTS_WRITE,
}

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

PLATFORM_ADMIN_AUTH_TYPES = {"api_key", "disabled"}

ORGANIZATION_ROLE_ALIASES = {
    "organization_owner": ROLE_WORKSPACE_OWNER,
    "owner": ROLE_WORKSPACE_OWNER,
    "admin": ROLE_WORKSPACE_OWNER,
    "organization_admin": ROLE_WORKSPACE_OWNER,
    "billing_admin": ROLE_WORKSPACE_OWNER,
    "auditor": ROLE_AUDITOR,
    "organization_auditor": ROLE_AUDITOR,
    "analyst": ROLE_ANALYST,
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
    if auth_type in {"session", "bearer", "jwt", "trusted_proxy", *PLATFORM_ADMIN_AUTH_TYPES}:
        return ROLE_WORKSPACE_OWNER
    return ROLE_AUDITOR


def is_platform_admin_auth(auth_context: dict) -> bool:
    """Return True for deployment-wide admin credentials."""
    return (auth_context or {}).get("auth_type") in PLATFORM_ADMIN_AUTH_TYPES


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


def user_for_auth_context(db: Session, auth_context: dict) -> Optional[User]:
    """Return the active local user represented by an auth context, when available."""
    return _auth_user(db, auth_context)


def _normalize_organization_role(role: str) -> str:
    normalized = (role or "").strip().lower()
    return ORGANIZATION_ROLE_ALIASES.get(normalized, normalized)


def role_for_workspace(
    db: Session,
    auth_context: dict,
    workspace: Workspace,
) -> str:
    """Resolve the caller's effective role for one workspace."""
    auth_type = (auth_context or {}).get("auth_type")
    if auth_type in {"api_key", "disabled", "trusted_proxy"}:
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
    """Raise HTTP 403 for missing access or HTTP 402 for read-only accounts."""
    if db is not None and workspace is not None:
        role = role_for_workspace(db, auth_context, workspace)
    else:
        role = role_for_auth_context(auth_context)
    if role_allows(role, permission):
        require_workspace_account_mutation_allowed(permission, db, workspace)
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Workspace permission required: {permission}",
    )


def require_workspace_account_mutation_allowed(
    permission: str,
    db: Optional[Session],
    workspace: Optional[Workspace],
) -> None:
    """Block tenant mutations while the organization subscription is read-only."""
    if permission not in TENANT_MUTATION_PERMISSIONS:
        return
    if db is None or workspace is None or workspace.organization_id is None:
        return

    status_priority = case(
        (Subscription.status.in_(ACCOUNT_ACTIVE_STATUSES), 0),
        (Subscription.status.in_(ACCOUNT_GRACE_STATUSES), 1),
        (Subscription.status == "suspended", 2),
        (Subscription.status.in_(ACCOUNT_CLOSED_STATUSES), 3),
        else_=4,
    )
    subscription = (
        db.query(Subscription)
        .filter(
            Subscription.organization_id == workspace.organization_id,
        )
        .order_by(
            status_priority.asc(),
            Subscription.updated_at.desc().nullslast(),
            Subscription.created_at.desc().nullslast(),
        )
        .first()
    )
    account_state = account_state_for_subscriptions(
        [subscription] if subscription is not None else [],
        include_plan_code=False,
    )
    if account_state["can_mutate"]:
        return

    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "code": "account_read_only",
            "message": account_state["reason"],
            "subscription_status": account_state["status"],
            "subscription_id": account_state["blocking_subscription_id"],
            "organization_id": workspace.organization_id,
            "can_export": account_state["can_export"],
        },
    )


def parse_selected_workspace_id(value: Optional[Any]) -> Optional[int]:
    """Return a selected workspace id from the UI propagation header."""
    if value is not None and not isinstance(value, (str, int)):
        return None
    if value is None or not str(value).strip():
        return None
    try:
        workspace_id = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-DMARQ-Workspace-ID must be an integer",
        ) from exc
    if workspace_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-DMARQ-Workspace-ID must be a positive integer",
        )
    return workspace_id


def _workspace_id_from_auth_context(auth_context: dict) -> Optional[int]:
    """Return the workspace bound to scoped API-token auth, when present."""
    if (auth_context or {}).get("auth_type") != "api_token":
        return None
    try:
        workspace_id = int((auth_context or {}).get("workspace_id") or 0)
    except (TypeError, ValueError):
        return None
    return workspace_id if workspace_id > 0 else None


def resolve_authorized_workspace(
    db: Session,
    auth_context: dict,
    permission: str,
    *,
    selected_workspace_id: Optional[int] = None,
) -> Workspace:
    """Resolve and authorize the selected workspace, defaulting legacy installs safely."""
    selected_workspace_id = selected_workspace_id or _workspace_id_from_auth_context(auth_context)
    if selected_workspace_id is None:
        workspace = assign_default_workspace_to_unscoped_rows(db)
    else:
        workspace = (
            db.query(Workspace)
            .filter(
                Workspace.id == selected_workspace_id,
                Workspace.active.is_(True),
            )
            .first()
        )
        if workspace is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Selected workspace not found",
            )
    require_workspace_permission(auth_context, permission, db, workspace)
    return workspace


def role_for_organization(
    db: Session,
    auth_context: dict,
    organization: Organization,
    permission: str,
) -> str:
    """Resolve an effective organization role for tenant-state endpoints."""
    if is_platform_admin_auth(auth_context):
        return ROLE_WORKSPACE_OWNER

    user = _auth_user(db, auth_context)
    if user is None:
        return ""

    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.active.is_(True),
        )
        .first()
    )
    if membership is not None:
        role = _normalize_organization_role(membership.role)
        if role_allows(role, permission):
            return role

    workspace_roles = (
        db.query(WorkspaceMembership.role)
        .join(Workspace, WorkspaceMembership.workspace_id == Workspace.id)
        .filter(
            Workspace.organization_id == organization.id,
            Workspace.active.is_(True),
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.active.is_(True),
        )
        .all()
    )
    for row in workspace_roles:
        role = _normalize_organization_role(row[0])
        if role_allows(role, permission):
            return role

    if user.workspace_id is not None and user.is_superuser:
        workspace = (
            db.query(Workspace)
            .filter(
                Workspace.id == user.workspace_id,
                Workspace.organization_id == organization.id,
                Workspace.active.is_(True),
            )
            .first()
        )
        if workspace is not None and role_allows(ROLE_WORKSPACE_OWNER, permission):
            return ROLE_WORKSPACE_OWNER
    return ""


def organization_ids_for_permission(
    db: Session,
    auth_context: dict,
    permission: str,
) -> Optional[List[int]]:
    """Return authorized organization IDs, or None for platform-wide access."""
    if is_platform_admin_auth(auth_context):
        return None

    user = _auth_user(db, auth_context)
    if user is None:
        return []

    organization_ids: Set[int] = set()
    organization_roles = (
        db.query(OrganizationMembership.organization_id, OrganizationMembership.role)
        .filter(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.active.is_(True),
        )
        .all()
    )
    for organization_id, role in organization_roles:
        if role_allows(_normalize_organization_role(role), permission):
            organization_ids.add(organization_id)

    workspace_roles = (
        db.query(Workspace.organization_id, WorkspaceMembership.role)
        .join(Workspace, WorkspaceMembership.workspace_id == Workspace.id)
        .filter(
            Workspace.organization_id.isnot(None),
            Workspace.active.is_(True),
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.active.is_(True),
        )
        .all()
    )
    for organization_id, role in workspace_roles:
        if role_allows(_normalize_organization_role(role), permission):
            organization_ids.add(organization_id)

    if user.workspace_id is not None and user.is_superuser:
        workspace = (
            db.query(Workspace)
            .filter(
                Workspace.id == user.workspace_id,
                Workspace.organization_id.isnot(None),
                Workspace.active.is_(True),
            )
            .first()
        )
        if workspace is not None and role_allows(ROLE_WORKSPACE_OWNER, permission):
            organization_ids.add(workspace.organization_id)

    return sorted(organization_ids)


def require_organization_permission(
    auth_context: dict,
    permission: str,
    db: Session,
    organization: Organization,
) -> None:
    """Raise HTTP 403 when the caller cannot access organization tenant state."""
    if role_for_organization(db, auth_context, organization, permission):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Organization permission required: {permission}",
    )
