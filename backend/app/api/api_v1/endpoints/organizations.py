"""Organization/account endpoints for SaaS and provider-ready deployments."""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import Organization
from app.services.organizations import (
    bootstrap_default_commercial_foundation,
    list_organization_summaries,
    organization_summary,
)
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    require_workspace_permission,
)

router = APIRouter()


class OrganizationsResponse(BaseModel):
    """Organization account list response."""

    organizations: List[Dict[str, Any]]


class OrganizationResponse(BaseModel):
    """Single organization account response."""

    organization: Dict[str, Any]


@router.get("", response_model=OrganizationsResponse)
async def list_organizations(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> OrganizationsResponse:
    """Return organization, workspace, subscription, and entitlement summaries."""
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    return {"organizations": list_organization_summaries(db)}


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> OrganizationResponse:
    """Return one organization summary."""
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    bootstrap_default_commercial_foundation(db)
    organization = (
        db.query(Organization)
        .filter(Organization.id == organization_id, Organization.active.is_(True))
        .first()
    )
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {organization_id} not found",
        )
    return {"organization": organization_summary(db, organization)}
