"""Workspace role and permission foundations."""

from __future__ import annotations

from typing import Dict, List, Set

from fastapi import HTTPException, status

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

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    ROLE_WORKSPACE_OWNER: {
        PERMISSION_WORKSPACE_ADMIN,
        PERMISSION_DOMAINS_WRITE,
        PERMISSION_MAIL_SOURCES_WRITE,
        PERMISSION_NOTIFICATIONS_WRITE,
        PERMISSION_INTEGRATIONS_WRITE,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
    },
    ROLE_DOMAIN_ADMIN: {
        PERMISSION_DOMAINS_WRITE,
        PERMISSION_MAIL_SOURCES_WRITE,
        PERMISSION_NOTIFICATIONS_WRITE,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
    },
    ROLE_OPERATOR: {
        PERMISSION_MAIL_SOURCES_WRITE,
        PERMISSION_NOTIFICATIONS_WRITE,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
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

    Logto users and static admin credentials keep owner-level access until
    membership assignment and enforcement screens are added.
    """
    auth_type = (auth_context or {}).get("auth_type")
    if auth_type in {"session", "bearer", "jwt", "api_key", "disabled"}:
        return ROLE_WORKSPACE_OWNER
    return ROLE_AUDITOR


def require_workspace_permission(auth_context: dict, permission: str) -> None:
    """Raise HTTP 403 when the current role does not grant a permission."""
    role = role_for_auth_context(auth_context)
    if role_allows(role, permission):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Workspace permission required: {permission}",
    )
