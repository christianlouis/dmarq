"""MSP operator endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import BillingAccount, Subscription
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.demo_data import build_demo_multi_user_deployment
from app.services.demo_provider import build_demo_provider_console, build_demo_provider_seed_spec
from app.services.organizations import (
    OrganizationPlanLimitError,
    require_organization_retention_limit,
)
from app.services.provider_access import require_provider_operator_access
from app.services.provider_console import build_provider_console
from app.services.support_sessions import (
    SUPPORT_SESSION_COOKIE,
    create_support_session_token,
    support_session_from_request,
    support_session_metadata,
)
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    PERMISSION_WORKSPACE_ADMIN,
    require_workspace_permission,
    user_for_auth_context,
)
from app.services.workspace_audit import record_workspace_audit_log
from app.services.workspace_operator import (
    list_workspace_operator_summaries,
    retention_to_dict,
    workspace_operator_summary,
)

router = APIRouter()


class OperatorWorkspacesResponse(BaseModel):
    """Cross-workspace operator summaries."""

    workspaces: List[Dict[str, Any]]


class WorkspaceRetentionUpdate(BaseModel):
    """Workspace retention controls."""

    aggregate_reports_days: int = Field(..., ge=1, le=3650)
    forensic_reports_days: int = Field(..., ge=1, le=3650)
    tls_reports_days: int = Field(..., ge=1, le=3650)


class WorkspaceRetentionResponse(BaseModel):
    """Updated workspace retention response."""

    workspace: Dict[str, Any]
    retention: Dict[str, int]


class DemoMultiUserDeploymentResponse(BaseModel):
    """Read-only SaaS/ISP demo deployment showcase."""

    demo_mode: bool
    deployment: Dict[str, Any]


class DemoProviderConsoleResponse(BaseModel):
    """Provider-console shaped demo dataset."""

    demo_mode: bool
    provider_console: Dict[str, Any]


class DemoSupportSessionRequest(BaseModel):
    """Demo-only support access action."""

    workspace_slug: str = Field("bakery-example", min_length=1, max_length=120)
    account_slug: Optional[str] = Field(default=None, min_length=1, max_length=120)
    target_user_email: Optional[str] = Field(default=None, min_length=3, max_length=255)
    reason: str = Field("Customer support walkthrough", min_length=1, max_length=200)


class DemoSupportSessionResponse(BaseModel):
    """Synthetic support session audit result."""

    demo_mode: bool
    session: Dict[str, Any]
    audit_event: Dict[str, Any]


class ProviderConsoleResponse(BaseModel):
    """Site-manager console backed by persisted tenant data."""

    provider_console: Dict[str, Any]


class SupportSessionRequest(BaseModel):
    """Audited provider request to enter one customer workspace."""

    workspace_id: int = Field(..., gt=0)
    target_user_id: int = Field(..., gt=0)
    reason: str = Field(..., min_length=3, max_length=200)
    access_mode: str = Field("read_only", pattern="^(read_only|role_scoped)$")


class SupportSessionResponse(BaseModel):
    """API-safe support-session state and its audit marker."""

    active: bool
    session: Optional[Dict[str, Any]] = None
    audit_event: Optional[Dict[str, Any]] = None


def _workspace_or_404(db: Session, workspace_id: int) -> Workspace:
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace {workspace_id} not found",
        )
    return workspace


def _raise_plan_limit_error(db: Session, exc: OrganizationPlanLimitError) -> None:
    db.rollback()
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=exc.to_detail(),
    ) from exc


@router.get("/workspaces", response_model=OperatorWorkspacesResponse)
async def list_operator_workspaces(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> OperatorWorkspacesResponse:
    """Return safe cross-workspace health, drift, import, and retention summaries."""
    require_provider_operator_access(db, _auth)
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    return {"workspaces": list_workspace_operator_summaries(db)}


def _operator_profile(db: Session, auth: dict) -> Dict[str, Any]:
    user = user_for_auth_context(db, auth)
    if user is not None:
        return {
            "id": user.id,
            "name": user.full_name or user.email,
            "email": user.email,
            "role": "site_manager" if user.is_superuser else "provider_operator",
        }
    if get_settings().DEMO_MODE:
        operator = build_demo_provider_seed_spec()["provider"]["operator"]
        return {"id": "provider-demo-operator", **operator}
    return {
        "id": auth.get("user_id") or auth.get("auth_type") or "site-manager",
        "name": "Site Manager",
        "email": "Aktuelle Administratorsitzung",
        "role": "site_manager",
    }


@router.get("/provider-console", response_model=ProviderConsoleResponse)
async def get_provider_console(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderConsoleResponse:
    """Return the provider console from the persisted multi-tenant product model."""
    require_provider_operator_access(db, _auth)
    return {
        "provider_console": build_provider_console(
            db,
            organization_ids=None,
            operator=_operator_profile(db, _auth),
            demo_mode=get_settings().DEMO_MODE,
        )
    }


@router.get("/support-session", response_model=SupportSessionResponse)
async def get_support_session(request: Request) -> SupportSessionResponse:
    """Return the current customer-visible support-session state."""
    payload = support_session_from_request(request)
    return {
        "active": payload is not None,
        "session": support_session_metadata(payload) if payload is not None else None,
        "audit_event": None,
    }


@router.post("/support-session", response_model=SupportSessionResponse)
async def start_support_session(
    payload: SupportSessionRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> SupportSessionResponse:
    """Start a signed, audited session constrained to one customer workspace."""
    require_provider_operator_access(db, _auth)
    if support_session_from_request(request) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="End the active support session before starting another one",
        )
    workspace = _workspace_or_404(db, payload.workspace_id)
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == payload.target_user_id,
            WorkspaceMembership.active.is_(True),
        )
        .first()
    )
    target_user = (
        db.query(User).filter(User.id == payload.target_user_id, User.is_active.is_(True)).first()
    )
    if membership is None or target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active target user membership not found in this workspace",
        )
    operator = _operator_profile(db, _auth)
    subscription = (
        db.query(Subscription)
        .filter(Subscription.organization_id == workspace.organization_id)
        .order_by(Subscription.created_at.desc(), Subscription.id.desc())
        .first()
    )
    billing_account = (
        db.query(BillingAccount)
        .filter(BillingAccount.organization_id == workspace.organization_id)
        .order_by(BillingAccount.id.asc())
        .first()
    )
    read_only = (
        get_settings().DEMO_MODE
        or payload.access_mode == "read_only"
        or not workspace.active
        or (workspace.organization is not None and not workspace.organization.active)
    )
    token, session = create_support_session_token(
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        target_user_id=target_user.id,
        target_user_email=target_user.email,
        target_user_role=membership.role,
        operator=operator,
        reason=payload.reason.strip(),
        account_name=workspace.organization.name if workspace.organization else workspace.name,
        customer_number=(
            billing_account.external_customer_id if billing_account is not None else None
        ),
        plan_code=(subscription.plan.code if subscription is not None else None),
        plan_label=(subscription.plan.name if subscription is not None else None),
        read_only=read_only,
    )
    audit = record_workspace_audit_log(
        db,
        workspace=workspace,
        action="support_session.started",
        entity_type="support_session",
        entity_id=session["id"],
        entity_name=target_user.email,
        details={
            "summary": f"Support session started for {target_user.email}",
            "operator": operator,
            "target_user_id": target_user.id,
            "target_role": membership.role,
            "reason": payload.reason.strip(),
            "access_mode": "read_only" if read_only else "role_scoped",
            "expires_at": session["expires_at"],
            "customer_visible": True,
        },
        request=request,
        auth_context=_auth,
        commit=True,
    )
    response.set_cookie(
        SUPPORT_SESSION_COOKIE,
        token,
        max_age=30 * 60,
        httponly=True,
        secure=(
            request.url.scheme == "https"
            or get_settings().ENVIRONMENT.strip().lower() in {"prod", "production"}
        ),
        samesite="lax",
        path="/",
    )
    return {
        "active": True,
        "session": session,
        "audit_event": {
            "id": audit.id,
            "action": audit.action,
            "occurred_at": audit.created_at.isoformat(),
        },
    }


@router.delete("/support-session", response_model=SupportSessionResponse)
async def end_support_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> SupportSessionResponse:
    """End the active support session and record the exit."""
    payload = support_session_from_request(request)
    if payload is not None:
        workspace = db.query(Workspace).filter(Workspace.id == int(payload["workspace_id"])).first()
        operator = payload.get("operator") or {}
        operator_auth = {
            "auth_type": "provider_operator",
            "user_id": operator.get("id") or operator.get("email") or "provider_operator",
            "email": operator.get("email"),
        }
        if workspace is not None:
            record_workspace_audit_log(
                db,
                workspace=workspace,
                action="support_session.ended",
                entity_type="support_session",
                entity_id=payload.get("session_id"),
                entity_name=payload.get("target_user_email"),
                details={
                    "summary": "Provider operator ended the customer support session",
                    "operator": operator,
                    "reason": payload.get("reason"),
                    "customer_visible": True,
                },
                request=request,
                auth_context=operator_auth,
                commit=True,
            )
    response.delete_cookie(SUPPORT_SESSION_COOKIE, path="/")
    return {"active": False, "session": None, "audit_event": None}


@router.get("/demo/multi-user", response_model=DemoMultiUserDeploymentResponse)
async def get_demo_multi_user_deployment(
    _auth: dict = Depends(require_admin_auth),
) -> DemoMultiUserDeploymentResponse:
    """Return deterministic demo data for SaaS, managed-service, and ISP views."""
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    if not get_settings().DEMO_MODE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Demo multi-user deployment is only available in demo mode",
        )
    return {
        "demo_mode": True,
        "deployment": build_demo_multi_user_deployment(),
    }


@router.get("/demo/provider-console", response_model=DemoProviderConsoleResponse)
async def get_demo_provider_console(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> DemoProviderConsoleResponse:
    """Compatibility alias for the DB-backed provider console in demo mode."""
    require_provider_operator_access(db, _auth)
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    if not get_settings().DEMO_MODE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Demo provider console is only available in demo mode",
        )
    console = build_provider_console(
        db,
        organization_ids=None,
        operator=_operator_profile(db, _auth),
        demo_mode=True,
    )
    return {
        "demo_mode": True,
        "provider_console": console,
    }


@router.post("/demo/support-session", response_model=DemoSupportSessionResponse)
async def start_demo_support_session(
    payload: DemoSupportSessionRequest,
    _auth: dict = Depends(require_admin_auth),
) -> DemoSupportSessionResponse:
    """Return a synthetic audit event for demo-only support access."""
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    if not get_settings().DEMO_MODE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Demo support access is only available in demo mode",
        )

    console = build_demo_provider_console()
    session = dict(console.get("support_access_demo") or {})
    accounts = {
        account.get("slug"): account
        for account in console.get("accounts", [])
        if account.get("slug")
    }
    account_slug = payload.account_slug or payload.workspace_slug
    account = accounts.get(account_slug) or accounts.get("bakery-example") or {}
    target_users = [user for user in account.get("users", []) if user.get("can_impersonate")]
    target_user = next(
        (user for user in target_users if user.get("email") == payload.target_user_email),
        target_users[0] if target_users else {},
    )
    primary_domain = (account.get("domains") or [{}])[0].get("name")
    audit_event = {
        "event_id": f"audit-demo-{console.get('generated_for')}-{account.get('slug', 'account')}",
        "action": "support_access.started",
        "occurred_at": f"{console.get('generated_for')}T09:45:00Z",
        "operator_email": (session.get("operator") or {}).get("email"),
        "organization_slug": (console.get("provider") or {}).get("slug"),
        "account_slug": account.get("slug"),
        "workspace_slug": account.get("slug") or payload.workspace_slug,
        "domain": primary_domain,
        "target_user_email": target_user.get("email"),
        "target_user_name": target_user.get("name"),
        "target_role": target_user.get("role"),
        "reason": payload.reason.strip() or session.get("reason"),
        "scope": session.get("mode"),
        "result": "demo_session_ready",
    }
    session["account"] = {
        "slug": account.get("slug"),
        "name": account.get("name"),
        "customer_number": account.get("customer_number"),
    }
    session["target_user"] = {
        **target_user,
        "workspace_slug": audit_event["workspace_slug"],
        "domain": audit_event["domain"],
    }
    session["audit_events"] = [audit_event]
    return {
        "demo_mode": True,
        "session": session,
        "audit_event": audit_event,
    }


@router.get("/workspaces/{workspace_id}", response_model=Dict[str, Any])
async def get_operator_workspace(
    workspace_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Return one workspace operator summary."""
    workspace = _workspace_or_404(db, workspace_id)
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ, db, workspace)
    return workspace_operator_summary(db, workspace)


@router.put("/workspaces/{workspace_id}/retention", response_model=WorkspaceRetentionResponse)
async def update_workspace_retention(
    workspace_id: int,
    payload: WorkspaceRetentionUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> WorkspaceRetentionResponse:
    """Update workspace retention controls and audit the change."""
    workspace = _workspace_or_404(db, workspace_id)
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, workspace)
    if workspace.organization is not None:
        try:
            require_organization_retention_limit(
                db,
                workspace.organization,
                max(
                    payload.aggregate_reports_days,
                    payload.forensic_reports_days,
                    payload.tls_reports_days,
                ),
            )
        except OrganizationPlanLimitError as exc:
            _raise_plan_limit_error(db, exc)
    old_retention = retention_to_dict(workspace)
    workspace.report_retention_days = payload.aggregate_reports_days
    workspace.forensic_retention_days = payload.forensic_reports_days
    workspace.tls_report_retention_days = payload.tls_reports_days
    new_retention = retention_to_dict(workspace)
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="workspace.retention_updated",
        entity_type="workspace",
        entity_id=workspace.id,
        entity_name=workspace.slug,
        details={"old": old_retention, "new": new_retention},
        auth_context=_auth,
        request=request,
    )
    db.commit()
    db.refresh(workspace)
    return {
        "workspace": {"id": workspace.id, "slug": workspace.slug, "name": workspace.name},
        "retention": retention_to_dict(workspace),
    }
