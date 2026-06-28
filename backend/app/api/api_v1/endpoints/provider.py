"""Provider and ISP integration endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.organizations import (
    build_usage_export,
    provision_provider_customer,
    update_external_subscription_state,
    usage_period_for_current_month,
)
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    PERMISSION_WORKSPACE_ADMIN,
    organization_ids_for_permission,
)

router = APIRouter()


class ProviderUsageResponse(BaseModel):
    """Provider billing usage export response."""

    usage: Dict[str, Any]


class ProviderSubscriptionStateUpdate(BaseModel):
    """Provider-reported subscription lifecycle update."""

    status: str
    provider_id: Optional[str] = None
    external_event_id: Optional[str] = None
    payload_summary: Optional[str] = None


class ProviderSubscriptionStateResponse(BaseModel):
    """Provider subscription lifecycle update response."""

    result: Dict[str, Any]


class ProviderCustomerProvisionRequest(BaseModel):
    """Provider request to provision or refresh a billed customer tenant."""

    external_customer_id: str
    external_subscription_id: str
    organization_slug: str
    organization_name: str
    workspace_slug: Optional[str] = None
    workspace_name: Optional[str] = None
    provider_id: Optional[str] = None
    plan_code: str = "starter"
    external_product_code: Optional[str] = None
    external_event_id: Optional[str] = None
    payload_summary: Optional[str] = None


class ProviderCustomerProvisionResponse(BaseModel):
    """Provider customer provisioning response."""

    result: Dict[str, Any]


def _usage_or_400(
    db: Session,
    *,
    period: Optional[str],
    external_customer_id: Optional[str] = None,
    organization_ids: Optional[List[int]] = None,
) -> Dict[str, Any]:
    try:
        return build_usage_export(
            db,
            period=period or usage_period_for_current_month(),
            external_customer_id=external_customer_id,
            organization_ids=organization_ids,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/billing/usage", response_model=ProviderUsageResponse)
async def get_provider_billing_usage(
    period: Optional[str] = Query(
        None,
        description="Billing period in YYYY-MM format; defaults to the current month.",
    ),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderUsageResponse:
    """Return idempotent monthly usage metrics for provider billing systems."""
    organization_ids = organization_ids_for_permission(db, _auth, PERMISSION_AUDIT_READ)
    return {"usage": _usage_or_400(db, period=period, organization_ids=organization_ids)}


@router.get(
    "/billing/accounts/{external_customer_id}/usage",
    response_model=ProviderUsageResponse,
)
async def get_provider_account_billing_usage(
    external_customer_id: str,
    period: Optional[str] = Query(
        None,
        description="Billing period in YYYY-MM format; defaults to the current month.",
    ),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderUsageResponse:
    """Return usage metrics for one provider-billed external customer."""
    organization_ids = organization_ids_for_permission(db, _auth, PERMISSION_AUDIT_READ)
    return {
        "usage": _usage_or_400(
            db,
            period=period,
            external_customer_id=external_customer_id,
            organization_ids=organization_ids,
        )
    }


@router.post("/customers", response_model=ProviderCustomerProvisionResponse)
async def provision_provider_customer_endpoint(
    payload: ProviderCustomerProvisionRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderCustomerProvisionResponse:
    """Provision a provider-billed organization and default workspace."""
    try:
        result = provision_provider_customer(
            db,
            external_customer_id=payload.external_customer_id,
            external_subscription_id=payload.external_subscription_id,
            organization_slug=payload.organization_slug,
            organization_name=payload.organization_name,
            workspace_slug=payload.workspace_slug,
            workspace_name=payload.workspace_name,
            provider_id=payload.provider_id,
            plan_code=payload.plan_code,
            external_product_code=payload.external_product_code,
            external_event_id=payload.external_event_id,
            payload_summary=payload.payload_summary,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return {"result": result}


@router.post(
    "/subscriptions/{external_subscription_id}/state",
    response_model=ProviderSubscriptionStateResponse,
)
async def update_provider_subscription_state(
    external_subscription_id: str,
    payload: ProviderSubscriptionStateUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderSubscriptionStateResponse:
    """Apply a provider-reported subscription lifecycle state."""
    organization_ids = organization_ids_for_permission(db, _auth, PERMISSION_WORKSPACE_ADMIN)
    try:
        result = update_external_subscription_state(
            db,
            external_subscription_id=external_subscription_id,
            status=payload.status,
            organization_ids=organization_ids,
            provider_id=payload.provider_id,
            external_event_id=payload.external_event_id,
            payload_summary=payload.payload_summary,
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return {"result": result}
