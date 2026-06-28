"""Provider and ISP integration endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth, require_provider_auth
from app.models.api_token import APIToken
from app.services.api_tokens import (
    PROVIDER_READ_SCOPE,
    PROVIDER_SCOPES,
    PROVIDER_WRITE_SCOPE,
    create_api_token,
    revoke_api_token,
    token_to_dict,
)
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
require_provider_read_auth = require_provider_auth(PROVIDER_READ_SCOPE)
require_provider_write_auth = require_provider_auth(PROVIDER_WRITE_SCOPE)


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


class ProviderAPITokenCreateRequest(BaseModel):
    """Request body for creating a provider-scoped machine token."""

    name: str = Field(..., min_length=1, max_length=120)
    scopes: List[str] = Field(default_factory=lambda: sorted(PROVIDER_SCOPES))


class ProviderAPITokenResponse(BaseModel):
    """API-safe provider token metadata."""

    id: int
    workspace_id: Optional[int] = None
    name: str
    key_prefix: str
    scopes: List[str]
    active: bool
    created_at: str
    last_used_at: Optional[str] = None
    last_used_ip: Optional[str] = None
    usage_count: int
    revoked_at: Optional[str] = None


class ProviderAPITokenCreateResponse(BaseModel):
    """New provider token response. The secret is returned once."""

    token: str
    metadata: ProviderAPITokenResponse


class ProviderAPITokenListResponse(BaseModel):
    """List of provider API token metadata rows."""

    tokens: List[ProviderAPITokenResponse]
    available_scopes: List[str]


class ProviderCustomerProvisionRequest(BaseModel):
    """Provider request to provision or refresh a billed customer tenant."""

    provider_id: str
    external_customer_id: str
    external_subscription_id: str
    organization_slug: str
    organization_name: str
    workspace_slug: Optional[str] = None
    workspace_name: Optional[str] = None
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


def _provider_organization_ids(
    db: Session,
    auth: Dict[str, Any],
    permission: str,
) -> Optional[List[int]]:
    """Return workspace-derived organization scope unless a provider token is used."""
    if auth.get("auth_type") == "provider_api_token":
        return None
    return organization_ids_for_permission(db, auth, permission)


@router.get("/api-tokens", response_model=ProviderAPITokenListResponse)
async def list_provider_api_tokens(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderAPITokenListResponse:
    """List provider machine-token metadata without exposing raw secrets."""
    rows = (
        db.query(APIToken)
        .filter(
            APIToken.workspace_id.is_(None),
            APIToken.scopes.contains("provider:"),
        )
        .order_by(APIToken.created_at.desc(), APIToken.id.desc())
        .all()
    )
    return ProviderAPITokenListResponse(
        tokens=[ProviderAPITokenResponse(**token_to_dict(row)) for row in rows],
        available_scopes=sorted(PROVIDER_SCOPES),
    )


@router.post(
    "/api-tokens",
    response_model=ProviderAPITokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider_api_token(
    payload: ProviderAPITokenCreateRequest,
    _request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderAPITokenCreateResponse:
    """Create a global provider-scoped machine token."""
    try:
        created = create_api_token(
            db,
            name=payload.name,
            scopes=payload.scopes,
            allowed_scopes=PROVIDER_SCOPES,
            global_token=True,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return ProviderAPITokenCreateResponse(
        token=created.secret,
        metadata=ProviderAPITokenResponse(**token_to_dict(created.token)),
    )


@router.delete("/api-tokens/{token_id}", status_code=status.HTTP_200_OK)
async def revoke_provider_api_token(
    token_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Revoke a provider-scoped machine token."""
    token = (
        db.query(APIToken)
        .filter(
            APIToken.id == token_id,
            APIToken.workspace_id.is_(None),
            APIToken.scopes.contains("provider:"),
        )
        .first()
    )
    if token is None or not revoke_api_token(db, token_id, workspace_id=None):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Provider API token not found",
        )
    return {"revoked": True}


@router.get("/billing/usage", response_model=ProviderUsageResponse)
async def get_provider_billing_usage(
    period: Optional[str] = None,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_provider_read_auth),
) -> ProviderUsageResponse:
    """Return idempotent monthly usage metrics for provider billing systems."""
    organization_ids = _provider_organization_ids(db, _auth, PERMISSION_AUDIT_READ)
    return {"usage": _usage_or_400(db, period=period, organization_ids=organization_ids)}


@router.get(
    "/billing/accounts/{external_customer_id}/usage",
    response_model=ProviderUsageResponse,
)
async def get_provider_account_billing_usage(
    external_customer_id: str,
    period: Optional[str] = None,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_provider_read_auth),
) -> ProviderUsageResponse:
    """Return usage metrics for one provider-billed external customer."""
    organization_ids = _provider_organization_ids(db, _auth, PERMISSION_AUDIT_READ)
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
    _auth: dict = Depends(require_provider_write_auth),
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
    _auth: dict = Depends(require_provider_write_auth),
) -> ProviderSubscriptionStateResponse:
    """Apply a provider-reported subscription lifecycle state."""
    organization_ids = _provider_organization_ids(db, _auth, PERMISSION_WORKSPACE_ADMIN)
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
