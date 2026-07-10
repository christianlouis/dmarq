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
    list_scoped_organization_summaries,
    organization_summary,
)
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    organization_ids_for_permission,
    require_organization_permission,
    support_session_allows_inactive_tenant_read,
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
    organization_ids = organization_ids_for_permission(db, _auth, PERMISSION_AUDIT_READ)
    return {"organizations": list_scoped_organization_summaries(db, organization_ids)}


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> OrganizationResponse:
    """Return one organization summary."""
    bootstrap_default_commercial_foundation(db)
    query = db.query(Organization).filter(Organization.id == organization_id)
    if not support_session_allows_inactive_tenant_read(
        _auth,
        organization_id=organization_id,
    ):
        query = query.filter(Organization.active.is_(True))
    organization = query.first()
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {organization_id} not found",
        )
    require_organization_permission(_auth, PERMISSION_AUDIT_READ, db, organization)
    return {"organization": organization_summary(db, organization)}
