"""MSP operator endpoints."""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.workspace import Workspace
from app.services.demo_data import build_demo_multi_user_deployment
from app.services.organizations import (
    OrganizationPlanLimitError,
    require_organization_retention_limit,
)
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    PERMISSION_WORKSPACE_ADMIN,
    require_workspace_permission,
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
    reason: str = Field("Customer support walkthrough", min_length=1, max_length=200)


class DemoSupportSessionResponse(BaseModel):
    """Synthetic support session audit result."""

    demo_mode: bool
    session: Dict[str, Any]
    audit_event: Dict[str, Any]


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
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    return {"workspaces": list_workspace_operator_summaries(db)}


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
    _auth: dict = Depends(require_admin_auth),
) -> DemoProviderConsoleResponse:
    """Return demo data in the same shape the provider console consumes."""
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    if not get_settings().DEMO_MODE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Demo provider console is only available in demo mode",
        )
    deployment = build_demo_multi_user_deployment()
    return {
        "demo_mode": True,
        "provider_console": {
            "source": "demo_multi_user_deployment",
            "organizations": deployment.get("organizations", []),
            "support_access_demo": deployment.get("support_access_demo", {}),
            "billing_modes": deployment.get("billing_modes", []),
            "tenant_health_segments": deployment.get("tenant_health_segments", []),
        },
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

    deployment = build_demo_multi_user_deployment()
    session = dict(deployment.get("support_access_demo") or {})
    targets = {
        target.get("workspace_slug"): target
        for target in session.get("allowed_targets", [])
        if target.get("workspace_slug")
    }
    target = targets.get(payload.workspace_slug) or targets.get("bakery-example") or {}
    audit_template = (session.get("audit_events") or [{}])[0]
    audit_event = {
        **audit_template,
        "workspace_slug": target.get("workspace_slug") or payload.workspace_slug,
        "domain": target.get("domain") or audit_template.get("domain"),
        "target_user_email": target.get("target_user") or audit_template.get("target_user_email"),
        "reason": payload.reason.strip() or session.get("reason"),
        "result": "demo_session_ready",
    }
    session["target_user"] = {
        **(session.get("target_user") or {}),
        "workspace_slug": audit_event["workspace_slug"],
        "domain": audit_event["domain"],
        "email": audit_event["target_user_email"],
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
