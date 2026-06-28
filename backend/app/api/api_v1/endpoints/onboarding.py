"""Workspace onboarding template endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.organizations import OrganizationPlanLimitError
from app.services.workspace_access import (
    PERMISSION_WORKSPACE_ADMIN,
    require_workspace_permission,
)
from app.services.workspace_onboarding import (
    apply_onboarding_plan,
    build_onboarding_plan,
    list_onboarding_templates,
    public_onboarding_plan,
)

router = APIRouter()


class OnboardingWorkspace(BaseModel):
    """Workspace target for an onboarding plan."""

    slug: Optional[str] = None
    name: str
    description: Optional[str] = None


class OnboardingOrganization(BaseModel):
    """Organization target for an onboarding plan."""

    slug: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None


class OnboardingPlanRequest(BaseModel):
    """Request body for rendering or applying an onboarding template."""

    template_id: str
    organization: Optional[OnboardingOrganization] = None
    workspace: OnboardingWorkspace
    variables: Dict[str, Any] = Field(default_factory=dict)
    domains: Optional[List[Dict[str, Any]]] = None
    mail_sources: Optional[List[Dict[str, Any]]] = None
    notification_defaults: Optional[Dict[str, Any]] = None
    overwrite_existing: bool = False


class OnboardingTemplatesResponse(BaseModel):
    """Available workspace onboarding templates."""

    templates: List[Dict[str, Any]]


class OnboardingPlanResponse(BaseModel):
    """Rendered onboarding plan response."""

    plan: Dict[str, Any]


class OnboardingApplyResponse(BaseModel):
    """Applied onboarding plan response."""

    result: Dict[str, Any]


def _build_plan_or_422(payload: OnboardingPlanRequest) -> Dict[str, Any]:
    try:
        plan = build_onboarding_plan(
            template_id=payload.template_id,
            organization=payload.organization.model_dump() if payload.organization else None,
            workspace=payload.workspace.model_dump(),
            variables=payload.variables,
            domains=payload.domains,
            mail_sources=payload.mail_sources,
            notification_defaults=payload.notification_defaults,
            overwrite_existing=payload.overwrite_existing,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if plan["errors"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=plan["errors"],
        )
    return plan


@router.get("/templates", response_model=OnboardingTemplatesResponse)
async def get_onboarding_templates(
    _auth: dict = Depends(require_admin_auth),
) -> OnboardingTemplatesResponse:
    """Return versioned workspace onboarding templates."""
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN)
    return {"templates": list_onboarding_templates()}


@router.post("/preview", response_model=OnboardingPlanResponse)
async def preview_onboarding_plan(
    payload: OnboardingPlanRequest,
    _auth: dict = Depends(require_admin_auth),
) -> OnboardingPlanResponse:
    """Render an onboarding template without changing the database."""
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN)
    return {"plan": public_onboarding_plan(_build_plan_or_422(payload))}


@router.post("/apply", response_model=OnboardingApplyResponse)
async def apply_workspace_onboarding(
    payload: OnboardingPlanRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> OnboardingApplyResponse:
    """Apply a workspace onboarding template."""
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN)
    plan = _build_plan_or_422(payload)
    try:
        result = apply_onboarding_plan(db, plan=plan, auth_context=_auth, request=request)
    except OrganizationPlanLimitError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=exc.to_detail(),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Onboarding plan conflicts with existing data",
        ) from exc
    if not result.get("applied"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=result,
        )
    return {"result": result}
