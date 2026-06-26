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


def _workspace_or_404(db: Session, workspace_id: int) -> Workspace:
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace {workspace_id} not found",
        )
    return workspace


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


@router.get("/workspaces/{workspace_id}", response_model=Dict[str, Any])
async def get_operator_workspace(
    workspace_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Return one workspace operator summary."""
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    return workspace_operator_summary(db, _workspace_or_404(db, workspace_id))


@router.put("/workspaces/{workspace_id}/retention", response_model=WorkspaceRetentionResponse)
async def update_workspace_retention(
    workspace_id: int,
    payload: WorkspaceRetentionUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> WorkspaceRetentionResponse:
    """Update workspace retention controls and audit the change."""
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN)
    workspace = _workspace_or_404(db, workspace_id)
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
