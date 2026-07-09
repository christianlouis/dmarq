"""Provider and ISP integration endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth, require_provider_auth
from app.models.api_token import APIToken
from app.models.domain import Domain
from app.models.organization import BillingAccount, Organization, Subscription
from app.models.workspace import Workspace
from app.services.api_tokens import (
    PROVIDER_READ_SCOPE,
    PROVIDER_SCOPES,
    PROVIDER_WRITE_SCOPE,
    create_api_token,
    token_to_dict,
)
from app.services.organizations import (
    build_usage_export,
    organization_summary,
    provision_provider_customer,
    update_external_subscription_state,
    usage_period_for_current_month,
)
from app.services.provider_access import (
    provider_operator_access_allowed,
    require_provider_operator_access,
)
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    PERMISSION_WORKSPACE_ADMIN,
    organization_ids_for_permission,
)
from app.services.workspaces import normalize_workspace_slug
from app.utils.domain_validator import normalize_domain_name, validate_domain_config

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
    primary_domain: Optional[str] = Field(default=None, min_length=4, max_length=253)
    dmarc_report_mailbox: Optional[EmailStr] = None
    invoice_reference: Optional[str] = Field(default=None, max_length=120)
    invoice_delivery_mode: Optional[str] = Field(default=None, max_length=50)
    billing_contact_email: Optional[EmailStr] = None
    monthly_price_cents: Optional[int] = Field(default=None, ge=0)


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
    if provider_operator_access_allowed(db, auth):
        return None
    return organization_ids_for_permission(db, auth, permission)


def _load_provisioned_customer(
    db: Session,
    payload: ProviderCustomerProvisionRequest,
) -> tuple[Organization, Workspace]:
    organization_slug = normalize_workspace_slug(payload.organization_slug)
    organization = db.query(Organization).filter(Organization.slug == organization_slug).one()
    workspace_slug = normalize_workspace_slug(
        payload.workspace_slug or f"{organization_slug}-workspace"
    )
    workspace = (
        db.query(Workspace)
        .filter(
            Workspace.organization_id == organization.id,
            Workspace.slug == workspace_slug,
        )
        .one()
    )
    return organization, workspace


def _apply_provider_billing_details(
    db: Session,
    payload: ProviderCustomerProvisionRequest,
    organization: Organization,
) -> None:
    account = (
        db.query(BillingAccount)
        .filter(BillingAccount.organization_id == organization.id)
        .order_by(BillingAccount.id.asc())
        .first()
    )
    if account is not None:
        if payload.invoice_reference is not None:
            account.tax_reference = payload.invoice_reference.strip() or None
        if payload.invoice_delivery_mode is not None:
            account.invoice_delivery_mode = (
                payload.invoice_delivery_mode.strip() or "provider_invoice"
            )
        if payload.billing_contact_email is not None:
            account.billing_contact_email = str(payload.billing_contact_email)

    subscription = (
        db.query(Subscription)
        .filter(
            Subscription.organization_id == organization.id,
            Subscription.external_subscription_id == payload.external_subscription_id,
        )
        .first()
    )
    if subscription is not None and payload.monthly_price_cents is not None:
        subscription.monthly_price_cents = payload.monthly_price_cents


def _apply_provider_primary_domain(
    db: Session,
    payload: ProviderCustomerProvisionRequest,
    workspace: Workspace,
) -> None:
    if not payload.primary_domain:
        return

    domain_name = normalize_domain_name(payload.primary_domain)
    validation = validate_domain_config({"name": domain_name, "description": ""})
    if not validation["valid"]:
        raise ValueError("primary_domain is invalid")
    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if domain is not None and domain.workspace_id != workspace.id:
        raise ValueError("primary_domain is already linked to another customer")
    if domain is None:
        domain = Domain(name=domain_name, workspace_id=workspace.id)
        db.add(domain)
    domain.workspace_id = workspace.id
    domain.active = True
    domain.dmarc_policy = domain.dmarc_policy or "none"
    if payload.dmarc_report_mailbox is not None:
        domain.dmarc_report_mailbox = str(payload.dmarc_report_mailbox)


@router.get("/api-tokens", response_model=ProviderAPITokenListResponse)
async def list_provider_api_tokens(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ProviderAPITokenListResponse:
    """List provider machine-token metadata without exposing raw secrets."""
    require_provider_operator_access(db, _auth)
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
    require_provider_operator_access(db, _auth)
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
    require_provider_operator_access(db, _auth)
    token = (
        db.query(APIToken)
        .filter(
            APIToken.id == token_id,
            APIToken.workspace_id.is_(None),
            APIToken.scopes.contains("provider:"),
        )
        .first()
    )
    if token is None or not token.active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Provider API token not found",
        )
    token.active = False
    token.revoked_at = datetime.utcnow()
    db.commit()
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
    require_provider_operator_access(db, _auth, allow_provider_token=True)
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
            commit=False,
        )
        organization, workspace = _load_provisioned_customer(db, payload)
        _apply_provider_billing_details(db, payload, organization)
        _apply_provider_primary_domain(db, payload, workspace)
        db.commit()
        result["organization"] = organization_summary(db, organization)
    except ValueError as exc:
        db.rollback()
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
    require_provider_operator_access(db, _auth, allow_provider_token=True)
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
