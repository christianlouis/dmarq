"""Optional Stripe Billing integration helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.organization import BillingAccount, BillingEvent, Organization, Plan, Subscription
from app.services.organizations import (
    BILLING_MODE_DIRECT_STRIPE,
    STARTER_PLAN_CODE,
    STARTER_PLAN_ENTITLEMENTS,
    ensure_billing_account,
    ensure_entitlements,
)

STRIPE_PROVIDER_ID = "stripe"
STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300
ACTIVE_STRIPE_STATUSES = {"active", "trialing"}
TERMINAL_STRIPE_STATUSES = {"canceled", "incomplete_expired", "unpaid"}


class StripeBillingError(ValueError):
    """Base Stripe billing integration error."""


class StripeNotConfiguredError(StripeBillingError):
    """Raised when Stripe-only actions are requested without Stripe credentials."""


class StripeSignatureError(StripeBillingError):
    """Raised when a webhook signature cannot be verified."""


def stripe_is_configured() -> bool:
    """Return True when direct Stripe API calls can be made."""
    return bool(get_settings().STRIPE_SECRET_KEY)


def stripe_webhooks_configured() -> bool:
    """Return True when inbound Stripe webhook verification is configured."""
    return bool(get_settings().STRIPE_WEBHOOK_SECRET)


def stripe_price_plan_map() -> Dict[str, str]:
    """Return the configured Stripe price-to-plan mapping."""
    raw = get_settings().STRIPE_PRICE_PLAN_MAP
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StripeBillingError("STRIPE_PRICE_PLAN_MAP must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise StripeBillingError("STRIPE_PRICE_PLAN_MAP must be a JSON object")
    return {
        str(price_id).strip(): str(plan_code).strip()
        for price_id, plan_code in parsed.items()
        if str(price_id).strip() and str(plan_code).strip()
    }


def stripe_public_config() -> Dict[str, Any]:
    """Return API-safe Stripe configuration metadata."""
    mapping = stripe_price_plan_map()
    return {
        "configured": stripe_is_configured(),
        "webhooks_configured": stripe_webhooks_configured(),
        "price_plan_map": mapping,
    }


def _require_stripe_api_configured() -> str:
    secret_key = get_settings().STRIPE_SECRET_KEY
    if not secret_key:
        raise StripeNotConfiguredError("Stripe Billing is not configured")
    return secret_key


def _plan_code_for_price(price_id: str) -> str:
    mapping = stripe_price_plan_map()
    plan_code = mapping.get(price_id)
    if not plan_code:
        raise StripeBillingError("Stripe price is not configured for a local plan")
    return plan_code


def _stripe_post(path: str, data: Dict[str, Any]) -> Dict[str, Any]:
    settings = get_settings()
    secret_key = _require_stripe_api_configured()
    response = httpx.post(
        f"{settings.STRIPE_API_BASE_URL.rstrip('/')}/{path.lstrip('/')}",
        data=data,
        auth=(secret_key, ""),
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _get_or_create_direct_plan(db: Session, *, code: str, price_id: Optional[str]) -> Plan:
    plan = db.query(Plan).filter(Plan.code == code).first()
    if plan:
        return plan
    plan = Plan(
        code=code,
        name=code.replace("_", " ").replace("-", " ").title(),
        description="Direct Stripe Billing plan mapped from Stripe configuration.",
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        public=True,
        active=True,
        currency="EUR",
    )
    db.add(plan)
    db.flush()
    return plan


def _entitlements_for_plan(plan: Plan) -> Dict[str, str]:
    if plan.code == STARTER_PLAN_CODE:
        return dict(STARTER_PLAN_ENTITLEMENTS)
    entitlements: Dict[str, str] = {}
    if plan.included_sending_domains is not None:
        entitlements["sending_domains"] = str(plan.included_sending_domains)
    if plan.included_message_volume is not None:
        entitlements["aggregate_messages"] = str(plan.included_message_volume)
    if plan.included_users is not None:
        entitlements["users"] = str(plan.included_users)
    if plan.retention_days is not None:
        entitlements["retention_days"] = str(plan.retention_days)
    for feature in (plan.features or "").split(","):
        feature = feature.strip()
        if feature:
            entitlements[feature] = "true"
    return entitlements


def _set_subscription_entitlements(
    db: Session,
    organization: Organization,
    subscription: Subscription,
) -> None:
    if subscription.status in ACTIVE_STRIPE_STATUSES:
        ensure_entitlements(
            db,
            organization,
            subscription,
            _entitlements_for_plan(subscription.plan),
            commit=False,
        )
        return
    if subscription.status in TERMINAL_STRIPE_STATUSES:
        for entitlement in subscription.entitlements:
            entitlement.active = False


def create_stripe_checkout_session(
    db: Session,
    *,
    organization: Organization,
    price_id: str,
    success_url: str,
    cancel_url: str,
) -> Dict[str, Any]:
    """Create a hosted Stripe Checkout subscription session."""
    plan_code = _plan_code_for_price(price_id)
    plan = _get_or_create_direct_plan(db, code=plan_code, price_id=price_id)
    account = ensure_billing_account(
        db,
        organization,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        commit=False,
    )
    account.status = "pending_checkout"
    account.invoice_delivery_mode = "stripe"
    data: Dict[str, Any] = {
        "mode": "subscription",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(organization.id),
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "metadata[organization_id]": str(organization.id),
        "metadata[plan_code]": plan.code,
        "subscription_data[metadata][organization_id]": str(organization.id),
        "subscription_data[metadata][plan_code]": plan.code,
    }
    if account.stripe_customer_id:
        data["customer"] = account.stripe_customer_id
    else:
        data["customer_creation"] = "always"
    session = _stripe_post("checkout/sessions", data)
    db.commit()
    db.refresh(account)
    return {
        "id": session.get("id"),
        "url": session.get("url"),
        "mode": session.get("mode", "subscription"),
        "organization_id": organization.id,
        "billing_account_id": account.id,
        "plan_code": plan.code,
        "price_id": price_id,
    }


def create_stripe_portal_session(
    db: Session,
    *,
    organization: Organization,
    return_url: str,
) -> Dict[str, Any]:
    """Create a hosted Stripe Customer Portal session."""
    _require_stripe_api_configured()
    account = (
        db.query(BillingAccount)
        .filter(
            BillingAccount.organization_id == organization.id,
            BillingAccount.billing_mode == BILLING_MODE_DIRECT_STRIPE,
        )
        .order_by(BillingAccount.id.asc())
        .first()
    )
    if account is None or not account.stripe_customer_id:
        raise StripeBillingError("Organization does not have a Stripe customer yet")
    session = _stripe_post(
        "billing_portal/sessions",
        {"customer": account.stripe_customer_id, "return_url": return_url},
    )
    return {
        "id": session.get("id"),
        "url": session.get("url"),
        "organization_id": organization.id,
        "billing_account_id": account.id,
    }


def _signature_parts(signature_header: str) -> Dict[str, list[str]]:
    parts: Dict[str, list[str]] = {}
    for item in signature_header.split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts.setdefault(key, []).append(value)
    return parts


def verify_stripe_signature(
    body: bytes,
    signature_header: Optional[str],
    *,
    now: Optional[int] = None,
) -> None:
    """Verify Stripe's signed webhook payload."""
    secret = get_settings().STRIPE_WEBHOOK_SECRET
    if not secret:
        raise StripeNotConfiguredError("Stripe webhooks are not configured")
    if not signature_header:
        raise StripeSignatureError("Missing Stripe-Signature header")
    parts = _signature_parts(signature_header)
    timestamps = parts.get("t") or []
    signatures = parts.get("v1") or []
    if not timestamps or not signatures:
        raise StripeSignatureError("Invalid Stripe-Signature header")
    try:
        timestamp = int(timestamps[0])
    except ValueError as exc:
        raise StripeSignatureError("Invalid Stripe-Signature timestamp") from exc
    if abs((now or int(time.time())) - timestamp) > STRIPE_SIGNATURE_TOLERANCE_SECONDS:
        raise StripeSignatureError("Stripe-Signature timestamp is outside tolerance")
    signed_payload = f"{timestamp}.{body.decode('utf-8')}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, signature) for signature in signatures):
        raise StripeSignatureError("Invalid Stripe-Signature")


def _timestamp(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        return datetime.utcfromtimestamp(int(value))
    except (TypeError, ValueError, OSError):
        return None


def _event_payload_summary(event: Dict[str, Any]) -> str:
    data_object = (event.get("data") or {}).get("object") or {}
    object_id = (
        data_object.get("id") or data_object.get("subscription") or data_object.get("customer")
    )
    return f"{event.get('type', 'stripe.event')} object={object_id or 'unknown'}"


def _find_organization(db: Session, data_object: Dict[str, Any]) -> Optional[Organization]:
    metadata = data_object.get("metadata") or {}
    organization_id = metadata.get("organization_id") or data_object.get("client_reference_id")
    if organization_id:
        try:
            return db.query(Organization).filter(Organization.id == int(organization_id)).first()
        except (TypeError, ValueError):
            return None
    customer_id = data_object.get("customer")
    if customer_id:
        account = (
            db.query(BillingAccount)
            .filter(BillingAccount.stripe_customer_id == customer_id)
            .first()
        )
        return account.organization if account else None
    return None


def _price_id_from_subscription_object(data_object: Dict[str, Any]) -> Optional[str]:
    items = (data_object.get("items") or {}).get("data") or []
    if not items:
        return None
    price = items[0].get("price") or {}
    return price.get("id")


def _plan_for_stripe_object(db: Session, data_object: Dict[str, Any]) -> Plan:
    metadata = data_object.get("metadata") or {}
    plan_code = metadata.get("plan_code")
    price_id = _price_id_from_subscription_object(data_object)
    if not plan_code and price_id:
        plan_code = _plan_code_for_price(price_id)
    if not plan_code:
        raise StripeBillingError("Stripe event is missing local plan metadata")
    return _get_or_create_direct_plan(db, code=str(plan_code), price_id=price_id)


def _upsert_stripe_subscription(
    db: Session,
    *,
    organization: Organization,
    data_object: Dict[str, Any],
    status_override: Optional[str] = None,
) -> Subscription:
    customer_id = data_object.get("customer")
    account = ensure_billing_account(
        db,
        organization,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        commit=False,
    )
    account.status = "active"
    account.invoice_delivery_mode = "stripe"
    if customer_id:
        account.stripe_customer_id = customer_id
    stripe_subscription_id = data_object.get("subscription") or data_object.get("id")
    subscription = None
    if stripe_subscription_id:
        subscription = (
            db.query(Subscription)
            .filter(Subscription.stripe_subscription_id == stripe_subscription_id)
            .first()
        )
    if subscription is None:
        plan = _plan_for_stripe_object(db, data_object)
        subscription = Subscription(
            organization_id=organization.id,
            plan_id=plan.id,
            billing_account=account,
            billing_mode=BILLING_MODE_DIRECT_STRIPE,
            stripe_subscription_id=stripe_subscription_id,
            status=status_override or data_object.get("status") or "active",
        )
        db.add(subscription)
        db.flush()
    else:
        if data_object.get("metadata") or _price_id_from_subscription_object(data_object):
            subscription.plan = _plan_for_stripe_object(db, data_object)
        subscription.billing_account = account
        subscription.billing_mode = BILLING_MODE_DIRECT_STRIPE
        subscription.status = status_override or data_object.get("status") or subscription.status
    subscription.external_product_code = _price_id_from_subscription_object(data_object)
    subscription.current_period_start = _timestamp(data_object.get("current_period_start"))
    subscription.current_period_end = _timestamp(data_object.get("current_period_end"))
    subscription.canceled_at = _timestamp(data_object.get("canceled_at"))
    _set_subscription_entitlements(db, organization, subscription)
    return subscription


def _record_billing_event(
    db: Session,
    event: Dict[str, Any],
    *,
    organization: Optional[Organization],
    subscription: Optional[Subscription],
    status: str,
) -> BillingEvent:
    row = BillingEvent(
        organization_id=organization.id if organization else None,
        subscription_id=subscription.id if subscription else None,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        event_type=str(event.get("type") or "stripe.event"),
        provider_id=STRIPE_PROVIDER_ID,
        external_event_id=event.get("id"),
        status=status,
        payload_summary=_event_payload_summary(event),
    )
    db.add(row)
    return row


def apply_stripe_event(db: Session, event: Dict[str, Any]) -> Dict[str, Any]:
    """Apply a verified Stripe webhook event to local billing state."""
    event_id = event.get("id")
    if event_id:
        existing = (
            db.query(BillingEvent)
            .filter(
                BillingEvent.provider_id == STRIPE_PROVIDER_ID,
                BillingEvent.external_event_id == event_id,
            )
            .first()
        )
        if existing:
            return {"status": "duplicate", "billing_event_id": existing.id}

    event_type = str(event.get("type") or "")
    data_object = (event.get("data") or {}).get("object") or {}
    organization = _find_organization(db, data_object)
    subscription: Optional[Subscription] = None
    status = "ignored"

    if event_type == "checkout.session.completed" and organization is not None:
        subscription = _upsert_stripe_subscription(
            db,
            organization=organization,
            data_object=data_object,
            status_override="active",
        )
        status = "applied"
    elif event_type.startswith("customer.subscription.") and organization is not None:
        subscription = _upsert_stripe_subscription(
            db,
            organization=organization,
            data_object=data_object,
        )
        status = "applied"
    elif event_type == "invoice.payment_succeeded" and organization is not None:
        subscription = _upsert_stripe_subscription(
            db,
            organization=organization,
            data_object=data_object,
            status_override="active",
        )
        status = "applied"
    elif event_type == "invoice.payment_failed" and organization is not None:
        subscription = _upsert_stripe_subscription(
            db,
            organization=organization,
            data_object=data_object,
            status_override="past_due",
        )
        status = "applied"
    elif organization is None:
        status = "unmatched"

    billing_event = _record_billing_event(
        db,
        event,
        organization=organization,
        subscription=subscription,
        status=status,
    )
    db.commit()
    db.refresh(billing_event)
    if subscription is not None:
        db.refresh(subscription)
    return {
        "status": status,
        "event_type": event_type,
        "billing_event_id": billing_event.id,
        "organization_id": organization.id if organization else None,
        "subscription_id": subscription.id if subscription else None,
    }
