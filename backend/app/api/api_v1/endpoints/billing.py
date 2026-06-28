"""Direct billing endpoints."""

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import Organization
from app.services.stripe_billing import (
    StripeBillingError,
    StripeNotConfiguredError,
    StripeSignatureError,
    apply_stripe_event,
    create_stripe_checkout_session,
    create_stripe_portal_session,
    stripe_public_config,
    verify_stripe_signature,
)
from app.services.workspace_access import (
    PERMISSION_WORKSPACE_ADMIN,
    require_organization_permission,
)

router = APIRouter()


class BillingStripeConfigResponse(BaseModel):
    """API-safe Stripe Billing configuration response."""

    stripe: Dict[str, Any]


class StripeCheckoutRequest(BaseModel):
    """Create a Stripe Checkout subscription session."""

    organization_id: int
    price_id: str
    success_url: str
    cancel_url: str


class StripePortalRequest(BaseModel):
    """Create a Stripe Customer Portal session."""

    organization_id: int
    return_url: str


class StripeHostedSessionResponse(BaseModel):
    """Stripe hosted session response."""

    session: Dict[str, Any]


class StripeWebhookResponse(BaseModel):
    """Verified Stripe webhook application response."""

    result: Dict[str, Any]


def _organization_or_404(db: Session, organization_id: int) -> Organization:
    organization = (
        db.query(Organization)
        .filter(Organization.id == organization_id, Organization.active.is_(True))
        .first()
    )
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return organization


def _stripe_error(exc: StripeBillingError) -> HTTPException:
    if isinstance(exc, StripeNotConfiguredError):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(exc),
    )


@router.get("/stripe/config", response_model=BillingStripeConfigResponse)
async def get_stripe_billing_config(
    _auth: dict = Depends(require_admin_auth),
) -> BillingStripeConfigResponse:
    """Return non-secret Stripe Billing configuration status."""
    return {"stripe": stripe_public_config()}


@router.post("/stripe/checkout", response_model=StripeHostedSessionResponse)
async def create_checkout_session(
    payload: StripeCheckoutRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> StripeHostedSessionResponse:
    """Create a Stripe Checkout session for a direct-billed subscription."""
    organization = _organization_or_404(db, payload.organization_id)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    try:
        session = create_stripe_checkout_session(
            db,
            organization=organization,
            price_id=payload.price_id,
            success_url=payload.success_url,
            cancel_url=payload.cancel_url,
        )
    except StripeBillingError as exc:
        raise _stripe_error(exc) from exc
    return {"session": session}


@router.post("/stripe/portal", response_model=StripeHostedSessionResponse)
async def create_portal_session(
    payload: StripePortalRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> StripeHostedSessionResponse:
    """Create a Stripe Customer Portal session for a direct-billed organization."""
    organization = _organization_or_404(db, payload.organization_id)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    try:
        session = create_stripe_portal_session(
            db,
            organization=organization,
            return_url=payload.return_url,
        )
    except StripeBillingError as exc:
        raise _stripe_error(exc) from exc
    return {"session": session}


@router.post("/stripe/webhook", response_model=StripeWebhookResponse)
async def receive_stripe_webhook(
    request: Request,
    stripe_signature: Optional[str] = Header(None, alias="Stripe-Signature"),
    db: Session = Depends(get_db),
) -> StripeWebhookResponse:
    """Receive and apply a verified Stripe Billing webhook."""
    body = await request.body()
    try:
        verify_stripe_signature(body, stripe_signature)
    except StripeNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except StripeSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    try:
        event = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Stripe webhook JSON",
        ) from exc
    try:
        result = apply_stripe_event(db, event)
    except StripeBillingError as exc:
        raise _stripe_error(exc) from exc
    return {"result": result}
