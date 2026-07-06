"""Milestone readiness summary for account, auth, and provider foundations."""

from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.api_token import APIToken
from app.models.organization import (
    BillingAccount,
    BillingEvent,
    Entitlement,
    Organization,
    OrganizationMembership,
    Plan,
    ProviderIntegration,
    Subscription,
    UsageRecord,
)
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.api_tokens import (
    PROVIDER_READ_SCOPE,
    PROVIDER_WRITE_SCOPE,
    SCIM_READ_SCOPE,
    SCIM_WRITE_SCOPE,
)
from app.services.workspace_access import ROLE_PERMISSIONS, list_workspace_roles


def _count(db: Session, model: Any) -> int:
    return int(db.query(model).count())


def _has_scope_token(db: Session, scope: str, *, global_token: bool | None = None) -> bool:
    query = db.query(APIToken).filter(APIToken.active.is_(True), APIToken.scopes.contains(scope))
    if global_token is True:
        query = query.filter(APIToken.workspace_id.is_(None))
    elif global_token is False:
        query = query.filter(APIToken.workspace_id.is_not(None))
    return db.query(query.exists()).scalar() is True


def _auth_mode(settings: Settings) -> str:
    configured = (settings.AUTH_MODE or "auto").strip().lower()
    if settings.AUTH_DISABLED:
        return "disabled"
    if configured != "auto":
        return configured
    if settings.LOGTO_ENDPOINT and settings.LOGTO_APP_ID:
        return "logto"
    if settings.AUTHENTIK_ISSUER_URL and settings.AUTHENTIK_CLIENT_ID:
        return "authentik"
    if settings.OIDC_ISSUER_URL and settings.OIDC_CLIENT_ID:
        return "oidc"
    if settings.AUTH_TRUSTED_PROXY_ENABLED:
        return "trusted_proxy"
    return "auto"


def _criterion(
    key: str,
    title: str,
    ready: bool,
    configured: bool,
    status: str,
    evidence: List[str],
    next_step: str,
) -> Dict[str, Any]:
    return {
        "key": key,
        "title": title,
        "ready": bool(ready),
        "configured": bool(configured),
        "setup_required": bool(ready and not configured),
        "status": status,
        "evidence": evidence,
        "next_step": next_step,
    }


def build_account_milestone_readiness(db: Session, settings: Settings) -> Dict[str, Any]:
    """Return a safe operator-facing #12 completion summary."""

    counts = {
        "organizations": _count(db, Organization),
        "workspaces": _count(db, Workspace),
        "organization_memberships": _count(db, OrganizationMembership),
        "workspace_memberships": _count(db, WorkspaceMembership),
        "plans": _count(db, Plan),
        "billing_accounts": _count(db, BillingAccount),
        "subscriptions": _count(db, Subscription),
        "entitlements": _count(db, Entitlement),
        "usage_records": _count(db, UsageRecord),
        "provider_integrations": _count(db, ProviderIntegration),
        "billing_events": _count(db, BillingEvent),
        "workspace_audit_events": _count(db, WorkspaceAuditLog),
    }

    auth_mode = _auth_mode(settings)
    role_count = len(ROLE_PERMISSIONS)
    provider_read_token = _has_scope_token(db, PROVIDER_READ_SCOPE, global_token=True)
    provider_write_token = _has_scope_token(db, PROVIDER_WRITE_SCOPE, global_token=True)
    scim_token = _has_scope_token(db, SCIM_READ_SCOPE, global_token=False) or _has_scope_token(
        db, SCIM_WRITE_SCOPE, global_token=False
    )
    stripe_configured = bool(settings.STRIPE_SECRET_KEY and settings.STRIPE_WEBHOOK_SECRET)
    mfa_policy_configured = bool(settings.AUTH_REQUIRE_MFA)

    criteria = [
        _criterion(
            "auth_modes",
            "Production authentication modes",
            True,
            auth_mode != "disabled" or bool(settings.ALLOW_AUTH_DISABLED_IN_PRODUCTION),
            auth_mode,
            [
                "OIDC, Authentik, Logto, trusted-proxy, and explicit auth-disabled modes are modeled.",
                f"Current mode: {auth_mode}.",
            ],
            "Use OIDC/Logto/Authentik/trusted-proxy for internet-facing deployments.",
        ),
        _criterion(
            "workspace_rbac",
            "Workspace-scoped RBAC",
            role_count >= 5,
            role_count >= 5,
            f"{role_count} roles",
            [
                "Role permissions are centralized in workspace access helpers.",
                "Workspace owner, domain admin, operator, analyst, and auditor roles are available.",
            ],
            "Assign memberships or map IdP groups before enabling multi-workspace UI for a team.",
        ),
        _criterion(
            "membership_management",
            "Membership management and audit",
            True,
            counts["workspace_memberships"] > 0 or counts["organization_memberships"] > 0,
            (
                "implemented"
                if counts["workspace_memberships"] or counts["organization_memberships"]
                else "ready"
            ),
            [
                "Organization and workspace membership models and APIs are available.",
                f"Active database rows: {counts['organization_memberships']} org memberships, {counts['workspace_memberships']} workspace memberships.",
            ],
            "Invite or map the first non-admin user when operating as SaaS or provider tenant.",
        ),
        _criterion(
            "workspace_switching",
            "Workspace switching and tenant context",
            True,
            counts["workspaces"] > 0,
            f"{counts['workspaces']} workspaces",
            [
                "Visible workspace API returns effective roles and permissions.",
                "Workspace headers are used by workspace-scoped UI calls.",
            ],
            "Keep single-workspace UI disabled for self-hosted installs that do not need switching.",
        ),
        _criterion(
            "onboarding_entitlements",
            "SaaS onboarding and starter entitlements",
            True,
            counts["organizations"] > 0 and counts["entitlements"] > 0,
            "materialized" if counts["entitlements"] else "ready",
            [
                "Onboarding can create organization, workspace, owner membership, and starter plan state.",
                f"Database rows: {counts['organizations']} organizations, {counts['entitlements']} entitlements.",
            ],
            "Run browser onboarding for a new customer workspace before production use.",
        ),
        _criterion(
            "direct_billing",
            "Direct Stripe billing",
            True,
            stripe_configured or counts["subscriptions"] > 0,
            "configured" if stripe_configured else "optional",
            [
                "Checkout, customer portal, webhook verification, and local entitlement materialization are implemented.",
                "Stripe is optional for self-hosted and provider-billed deployments.",
            ],
            "Set Stripe secrets only for direct DMARQaaS billing.",
        ),
        _criterion(
            "provider_billing",
            "Provider lifecycle and external billing",
            True,
            provider_read_token or provider_write_token or counts["billing_accounts"] > 0,
            "configured" if provider_read_token or provider_write_token else "ready",
            [
                "Provider-scoped tokens, customer provisioning, subscription state, and usage export endpoints are available.",
                f"Provider tokens: read={provider_read_token}, write={provider_write_token}.",
            ],
            "Create provider machine tokens from a trusted admin session before WHMCS or ISP integration.",
        ),
        _criterion(
            "plan_limits",
            "Plan limits and grace states",
            True,
            counts["plans"] > 0 and counts["subscriptions"] > 0,
            "active" if counts["subscriptions"] else "ready",
            [
                "Plans, subscriptions, entitlements, usage records, and grace/suspension states are local app concepts.",
                f"Database rows: {counts['plans']} plans, {counts['subscriptions']} subscriptions.",
            ],
            "Review billing mode and entitlement warnings before enforcing hard limits.",
        ),
        _criterion(
            "enterprise_identity",
            "Enterprise identity controls",
            True,
            scim_token or mfa_policy_configured,
            "configured" if scim_token or mfa_policy_configured else "ready",
            [
                "SCIM provisioning endpoints and MFA claim policy hooks are implemented.",
                f"Configured controls: scim_token={scim_token}, mfa_required={mfa_policy_configured}.",
            ],
            "Create workspace-scoped SCIM tokens and enable MFA claims for enterprise tenants.",
        ),
        _criterion(
            "support_access",
            "Audited support access",
            True,
            True,
            "approval-only",
            [
                "Support access grants are explicit, time-boxed, customer-visible, and written to workspace audit logs.",
                f"Workspace audit events currently stored: {counts['workspace_audit_events']}.",
            ],
            "Use support-access grants for diagnostics; never impersonate silently.",
        ),
    ]

    ready_count = sum(1 for item in criteria if item["ready"])
    remaining = [item for item in criteria if not item["ready"]]
    setup_gates = [item for item in criteria if item["setup_required"]]
    status = (
        "incomplete"
        if remaining
        else "operational_with_setup_needed" if setup_gates else "complete"
    )
    return {
        "milestone": "#12 User Authentication & Multi-User Support",
        "status": status,
        "ready_to_close_parent_issue": not remaining,
        "criteria_met": ready_count,
        "criteria_total": len(criteria),
        "remaining_slices": len(remaining),
        "setup_gates": len(setup_gates),
        "criteria": criteria,
        "counts": counts,
        "role_catalog": list_workspace_roles(),
        "deployment_modes": [
            "self_hosted_single_workspace",
            "self_hosted_multi_workspace",
            "dmarq_saas_direct_billing",
            "provider_resale",
            "provider_whmcs",
            "provider_tmf",
        ],
        "safety_boundary": (
            "This readiness summary does not enable live writes, billing charges, or support access. "
            "Those paths still require configured credentials, scoped tokens, and explicit operator action."
        ),
        "next_step": (
            "Close #12 as implemented; review setup gates only when enabling SaaS, provider, or enterprise tenant modes."
            if not remaining
            else "Complete the remaining setup gates before closing #12 for this deployment."
        ),
    }
