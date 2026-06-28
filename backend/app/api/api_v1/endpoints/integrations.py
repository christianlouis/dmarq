"""Integration template endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.organizations import require_organization_feature
from app.services.siem_templates import get_siem_templates
from app.services.ticketing_chatops_templates import get_ticketing_chatops_templates
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)

router = APIRouter()


def _require_advanced_integrations(
    db: Session,
    auth_context: dict,
    selected_workspace: Optional[str],
) -> None:
    workspace = resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    if workspace.organization is None:
        return
    try:
        require_organization_feature(db, workspace.organization, "advanced_integrations")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "code": "feature_not_included",
                "feature": "advanced_integrations",
                "message": str(exc),
                "can_export": True,
            },
        ) from exc


@router.get("/siem/templates")
async def siem_templates(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Return versioned schemas and examples for SIEM ingestion."""
    _require_advanced_integrations(db, _auth, selected_workspace)
    return get_siem_templates()


@router.get("/ticketing-chatops/templates")
async def ticketing_chatops_templates(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Return ticketing and chatops workflow templates."""
    _require_advanced_integrations(db, _auth, selected_workspace)
    return get_ticketing_chatops_templates()
