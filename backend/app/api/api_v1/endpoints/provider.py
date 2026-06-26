"""Provider and ISP integration endpoints."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.organizations import (
    build_usage_export,
    update_external_subscription_state,
    usage_period_for_current_month,
)
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    require_workspace_permission,
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


def _usage_or_400(
    db: Session,
    *,
    period: Optional[str],
    external_customer_id: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        return build_usage_export(
            db,
            period=period or usage_period_for_current_month(),
            external_customer_id=external_customer_id,
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
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    return {"usage": _usage_or_400(db, period=period)}


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
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    return {
        "usage": _usage_or_400(
            db,
            period=period,
            external_customer_id=external_customer_id,
        )
    }


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
    require_workspace_permission(_auth, PERMISSION_AUDIT_READ)
    try:
        result = update_external_subscription_state(
            db,
            external_subscription_id=external_subscription_id,
            status=payload.status,
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
