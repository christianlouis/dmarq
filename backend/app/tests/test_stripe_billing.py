import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from app.models.organization import (
    BillingAccount,
    BillingEvent,
    Entitlement,
    Organization,
    Plan,
    Subscription,
)
from app.services.organizations import BILLING_MODE_DIRECT_STRIPE, STARTER_PLAN_CODE
from app.services.stripe_billing import StripeBillingError, stripe_price_plan_map


def _stripe_settings(**overrides):
    data = {
        "STRIPE_SECRET_KEY": "sk_test_123",
        "STRIPE_WEBHOOK_SECRET": "whsec_test",
        "STRIPE_PRICE_PLAN_MAP": json.dumps({"price_starter": STARTER_PLAN_CODE}),
        "STRIPE_API_BASE_URL": "https://api.stripe.test/v1",
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _stripe_signature(payload: dict, secret: str = "whsec_test") -> tuple[bytes, str]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = int(time.time())
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.{body.decode('utf-8')}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return body, f"t={timestamp},v1={digest}"


def test_stripe_config_reports_optional_state(authed_client: TestClient, monkeypatch):
    monkeypatch.setattr(
        "app.services.stripe_billing.get_settings",
        lambda: _stripe_settings(STRIPE_SECRET_KEY=None, STRIPE_WEBHOOK_SECRET=None),
    )

    response = authed_client.get("/api/v1/billing/stripe/config")

    assert response.status_code == 200
    payload = response.json()["stripe"]
    assert payload["configured"] is False
    assert payload["webhooks_configured"] is False
    assert payload["price_plan_map"] == {"price_starter": STARTER_PLAN_CODE}


def test_stripe_price_plan_map_validates_json(monkeypatch):
    monkeypatch.setattr(
        "app.services.stripe_billing.get_settings",
        lambda: _stripe_settings(STRIPE_PRICE_PLAN_MAP="[not-json"),
    )

    with pytest.raises(StripeBillingError, match="valid JSON"):
        stripe_price_plan_map()

    monkeypatch.setattr(
        "app.services.stripe_billing.get_settings",
        lambda: _stripe_settings(STRIPE_PRICE_PLAN_MAP='["price_starter"]'),
    )

    with pytest.raises(StripeBillingError, match="JSON object"):
        stripe_price_plan_map()


def test_stripe_checkout_is_unavailable_without_credentials(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="acme", name="Acme", active=True)
    db_session.add(organization)
    db_session.commit()
    monkeypatch.setattr(
        "app.services.stripe_billing.get_settings",
        lambda: _stripe_settings(STRIPE_SECRET_KEY=None),
    )

    response = authed_client.post(
        "/api/v1/billing/stripe/checkout",
        json={
            "organization_id": organization.id,
            "price_id": "price_starter",
            "success_url": "https://app.example/billing/success",
            "cancel_url": "https://app.example/billing/cancel",
        },
    )

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_stripe_checkout_creates_hosted_session_request_and_pending_account(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="direct", name="Direct", active=True)
    db_session.add(organization)
    db_session.commit()
    posted = {}

    def fake_post(url, data, auth, timeout):
        posted.update({"url": url, "data": data, "auth": auth, "timeout": timeout})
        return httpx.Response(
            200,
            json={"id": "cs_test_123", "url": "https://checkout.stripe.test/session"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    monkeypatch.setattr("app.services.stripe_billing.httpx.post", fake_post)

    response = authed_client.post(
        "/api/v1/billing/stripe/checkout",
        json={
            "organization_id": organization.id,
            "price_id": "price_starter",
            "success_url": "https://app.example/billing/success",
            "cancel_url": "https://app.example/billing/cancel",
        },
    )

    assert response.status_code == 200
    session = response.json()["session"]
    assert session["id"] == "cs_test_123"
    assert session["url"] == "https://checkout.stripe.test/session"
    assert posted["url"] == "https://api.stripe.test/v1/checkout/sessions"
    assert posted["auth"] == ("sk_test_123", "")
    assert posted["data"]["line_items[0][price]"] == "price_starter"
    assert posted["data"]["metadata[organization_id]"] == str(organization.id)
    account = db_session.query(BillingAccount).filter_by(organization_id=organization.id).one()
    assert account.billing_mode == BILLING_MODE_DIRECT_STRIPE
    assert account.status == "pending_checkout"
    assert account.invoice_delivery_mode == "stripe"


def test_stripe_checkout_reuses_existing_customer(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="existing-customer", name="Existing Customer", active=True)
    db_session.add(organization)
    db_session.flush()
    db_session.add(
        BillingAccount(
            organization_id=organization.id,
            billing_mode=BILLING_MODE_DIRECT_STRIPE,
            stripe_customer_id="cus_existing",
        )
    )
    db_session.commit()
    posted = {}

    def fake_post(url, data, auth, timeout):
        posted.update({"url": url, "data": data, "auth": auth, "timeout": timeout})
        return httpx.Response(
            200,
            json={"id": "cs_existing", "url": "https://checkout.stripe.test/existing"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    monkeypatch.setattr("app.services.stripe_billing.httpx.post", fake_post)

    response = authed_client.post(
        "/api/v1/billing/stripe/checkout",
        json={
            "organization_id": organization.id,
            "price_id": "price_starter",
            "success_url": "https://app.example/billing/success",
            "cancel_url": "https://app.example/billing/cancel",
        },
    )

    assert response.status_code == 200
    assert posted["data"]["customer"] == "cus_existing"
    assert "customer_creation" not in posted["data"]


def test_stripe_checkout_rejects_unmapped_price(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="unmapped", name="Unmapped", active=True)
    db_session.add(organization)
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)

    response = authed_client.post(
        "/api/v1/billing/stripe/checkout",
        json={
            "organization_id": organization.id,
            "price_id": "price_unknown",
            "success_url": "https://app.example/billing/success",
            "cancel_url": "https://app.example/billing/cancel",
        },
    )

    assert response.status_code == 400
    assert "not configured" in response.json()["detail"]


def test_stripe_checkout_rejects_unknown_organization(
    authed_client: TestClient,
    monkeypatch,
):
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)

    response = authed_client.post(
        "/api/v1/billing/stripe/checkout",
        json={
            "organization_id": 999999,
            "price_id": "price_starter",
            "success_url": "https://app.example/billing/success",
            "cancel_url": "https://app.example/billing/cancel",
        },
    )

    assert response.status_code == 404


def test_stripe_portal_creates_hosted_session(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="portal", name="Portal", active=True)
    db_session.add(organization)
    db_session.flush()
    account = BillingAccount(
        organization_id=organization.id,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        stripe_customer_id="cus_portal",
    )
    db_session.add(account)
    db_session.commit()
    posted = {}

    def fake_post(url, data, auth, timeout):
        posted.update({"url": url, "data": data, "auth": auth, "timeout": timeout})
        return httpx.Response(
            200,
            json={"id": "bps_test_123", "url": "https://billing.stripe.test/session"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    monkeypatch.setattr("app.services.stripe_billing.httpx.post", fake_post)

    response = authed_client.post(
        "/api/v1/billing/stripe/portal",
        json={
            "organization_id": organization.id,
            "return_url": "https://app.example/billing",
        },
    )

    assert response.status_code == 200
    session = response.json()["session"]
    assert session["id"] == "bps_test_123"
    assert session["url"] == "https://billing.stripe.test/session"
    assert posted["url"] == "https://api.stripe.test/v1/billing_portal/sessions"
    assert posted["auth"] == ("sk_test_123", "")
    assert posted["data"] == {
        "customer": "cus_portal",
        "return_url": "https://app.example/billing",
    }


def test_stripe_portal_rejects_missing_customer(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="portal-missing", name="Portal Missing", active=True)
    db_session.add(organization)
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)

    response = authed_client.post(
        "/api/v1/billing/stripe/portal",
        json={
            "organization_id": organization.id,
            "return_url": "https://app.example/billing",
        },
    )

    assert response.status_code == 400
    assert "Stripe customer" in response.json()["detail"]


def test_stripe_webhook_rejects_invalid_signature(authed_client: TestClient, monkeypatch):
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=b'{"id":"evt_bad"}',
        headers={"Stripe-Signature": "t=1,v1=bad"},
    )

    assert response.status_code == 400


def test_stripe_webhook_requires_configured_secret(authed_client: TestClient, monkeypatch):
    monkeypatch.setattr(
        "app.services.stripe_billing.get_settings",
        lambda: _stripe_settings(STRIPE_WEBHOOK_SECRET=None),
    )

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=b'{"id":"evt_unconfigured"}',
        headers={"Stripe-Signature": "t=1,v1=bad"},
    )

    assert response.status_code == 503


def test_stripe_webhook_rejects_invalid_json(authed_client: TestClient, monkeypatch):
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    timestamp = int(time.time())
    body = b"{not-json"
    digest = hmac.new(
        b"whsec_test",
        f"{timestamp}.{body.decode('utf-8')}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": f"t={timestamp},v1={digest}"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid Stripe webhook JSON"


def test_stripe_checkout_completed_webhook_materializes_subscription_and_entitlements(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="webhook", name="Webhook", active=True)
    db_session.add(organization)
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    event = {
        "id": "evt_checkout",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "customer": "cus_123",
                "subscription": "sub_123",
                "client_reference_id": str(organization.id),
                "metadata": {
                    "organization_id": str(organization.id),
                    "plan_code": STARTER_PLAN_CODE,
                },
            }
        },
    }
    body, signature = _stripe_signature(event)

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert response.status_code == 200
    assert response.json()["result"]["status"] == "applied"
    account = db_session.query(BillingAccount).filter_by(organization_id=organization.id).one()
    assert account.stripe_customer_id == "cus_123"
    assert account.billing_mode == BILLING_MODE_DIRECT_STRIPE
    assert account.status == "active"
    subscription = account.subscriptions[0]
    assert subscription.stripe_subscription_id == "sub_123"
    assert subscription.status == "active"
    assert subscription.plan.code == STARTER_PLAN_CODE
    entitlement_keys = {
        entitlement.key
        for entitlement in db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .all()
    }
    assert {"aggregate_reports", "dns_linting", "monitored_domains"} <= entitlement_keys
    event_row = db_session.query(BillingEvent).filter_by(external_event_id="evt_checkout").one()
    assert event_row.status == "applied"


def test_stripe_subscription_webhook_maps_price_to_plan_without_metadata(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="price-map", name="Price Map", active=True)
    db_session.add(organization)
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    event = {
        "id": "evt_price_map",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_price",
                "customer": "cus_price",
                "status": "trialing",
                "current_period_start": 1_717_200_000,
                "current_period_end": 1_719_792_000,
                "metadata": {"organization_id": str(organization.id)},
                "items": {"data": [{"price": {"id": "price_starter"}}]},
            }
        },
    }
    body, signature = _stripe_signature(event)

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert response.status_code == 200
    subscription = (
        db_session.query(Subscription).filter_by(stripe_subscription_id="sub_price").one()
    )
    assert subscription.status == "trialing"
    assert subscription.plan.code == STARTER_PLAN_CODE
    assert subscription.external_product_code == "price_starter"
    assert subscription.current_period_start is not None
    assert subscription.current_period_end is not None


def test_stripe_invoice_payment_failed_updates_existing_subscription_from_customer(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="invoice-failed", name="Invoice Failed", active=True)
    plan = Plan(code=STARTER_PLAN_CODE, name="Starter", billing_mode=BILLING_MODE_DIRECT_STRIPE)
    db_session.add_all([organization, plan])
    db_session.flush()
    account = BillingAccount(
        organization_id=organization.id,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        stripe_customer_id="cus_invoice",
    )
    subscription = Subscription(
        organization_id=organization.id,
        billing_account=account,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        plan=plan,
        stripe_subscription_id="sub_invoice",
        status="active",
    )
    db_session.add_all([account, subscription])
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    event = {
        "id": "evt_invoice_failed",
        "type": "invoice.payment_failed",
        "data": {"object": {"customer": "cus_invoice", "subscription": "sub_invoice"}},
    }
    body, signature = _stripe_signature(event)

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert response.status_code == 200
    db_session.refresh(subscription)
    assert subscription.status == "past_due"
    event_row = (
        db_session.query(BillingEvent).filter_by(external_event_id="evt_invoice_failed").one()
    )
    assert event_row.subscription_id == subscription.id


def test_stripe_invoice_payment_succeeded_marks_existing_subscription_active(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="invoice-paid", name="Invoice Paid", active=True)
    plan = Plan(code=STARTER_PLAN_CODE, name="Starter", billing_mode=BILLING_MODE_DIRECT_STRIPE)
    db_session.add_all([organization, plan])
    db_session.flush()
    account = BillingAccount(
        organization_id=organization.id,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        stripe_customer_id="cus_paid",
    )
    subscription = Subscription(
        organization_id=organization.id,
        billing_account=account,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        plan=plan,
        stripe_subscription_id="sub_paid",
        status="past_due",
    )
    db_session.add_all([account, subscription])
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    event = {
        "id": "evt_invoice_paid",
        "type": "invoice.payment_succeeded",
        "data": {"object": {"customer": "cus_paid", "subscription": "sub_paid"}},
    }
    body, signature = _stripe_signature(event)

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert response.status_code == 200
    db_session.refresh(subscription)
    assert subscription.status == "active"


def test_stripe_active_subscription_materializes_custom_plan_entitlements(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="custom-plan", name="Custom Plan", active=True)
    plan = Plan(
        code="scale",
        name="Scale",
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        included_sending_domains=25,
        included_message_volume=250000,
        included_users=10,
        retention_days=180,
        features="alerts, api_access",
    )
    db_session.add_all([organization, plan])
    db_session.commit()
    monkeypatch.setattr(
        "app.services.stripe_billing.get_settings",
        lambda: _stripe_settings(STRIPE_PRICE_PLAN_MAP=json.dumps({"price_scale": "scale"})),
    )
    event = {
        "id": "evt_custom_plan",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_custom",
                "customer": "cus_custom",
                "status": "active",
                "metadata": {"organization_id": str(organization.id), "plan_code": "scale"},
                "items": {"data": [{"price": {"id": "price_scale"}}]},
            }
        },
    }
    body, signature = _stripe_signature(event)

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert response.status_code == 200
    entitlements = {
        entitlement.key: entitlement.value
        for entitlement in db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .all()
    }
    assert entitlements["sending_domains"] == "25"
    assert entitlements["aggregate_messages"] == "250000"
    assert entitlements["users"] == "10"
    assert entitlements["retention_days"] == "180"
    assert entitlements["alerts"] == "true"
    assert entitlements["api_access"] == "true"


def test_stripe_canceled_subscription_disables_entitlements(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="cancelled", name="Cancelled", active=True)
    db_session.add(organization)
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    active_event = {
        "id": "evt_cancel_setup",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_cancel",
                "subscription": "sub_cancel",
                "client_reference_id": str(organization.id),
                "metadata": {
                    "organization_id": str(organization.id),
                    "plan_code": STARTER_PLAN_CODE,
                },
            }
        },
    }
    body, signature = _stripe_signature(active_event)
    assert (
        authed_client.post(
            "/api/v1/billing/stripe/webhook",
            content=body,
            headers={"Stripe-Signature": signature},
        ).status_code
        == 200
    )
    canceled_event = {
        "id": "evt_cancelled",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_cancel",
                "customer": "cus_cancel",
                "status": "canceled",
                "canceled_at": 1_717_200_000,
                "metadata": {
                    "organization_id": str(organization.id),
                    "plan_code": STARTER_PLAN_CODE,
                },
            }
        },
    }
    body, signature = _stripe_signature(canceled_event)

    response = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert response.status_code == 200
    subscription = (
        db_session.query(Subscription).filter_by(stripe_subscription_id="sub_cancel").one()
    )
    assert subscription.status == "canceled"
    assert subscription.canceled_at is not None
    assert all(not entitlement.active for entitlement in subscription.entitlements)


def test_stripe_webhook_records_unmatched_and_ignored_events(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    organization = Organization(slug="ignored", name="Ignored", active=True)
    db_session.add(organization)
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    unmatched_event = {
        "id": "evt_unmatched",
        "type": "customer.subscription.updated",
        "data": {"object": {"id": "sub_missing", "customer": "cus_missing"}},
    }
    body, signature = _stripe_signature(unmatched_event)

    unmatched = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    ignored_event = {
        "id": "evt_ignored",
        "type": "customer.created",
        "data": {
            "object": {
                "id": "cus_ignored",
                "metadata": {"organization_id": str(organization.id)},
            }
        },
    }
    body, signature = _stripe_signature(ignored_event)
    ignored = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert unmatched.status_code == 200
    assert unmatched.json()["result"]["status"] == "unmatched"
    assert ignored.status_code == 200
    assert ignored.json()["result"]["status"] == "ignored"
    assert db_session.query(BillingEvent).filter_by(external_event_id="evt_unmatched").one().status
    assert db_session.query(BillingEvent).filter_by(external_event_id="evt_ignored").one().status


def test_stripe_subscription_webhook_is_idempotent(
    authed_client: TestClient, db_session, monkeypatch
):
    organization = Organization(slug="idempotent", name="Idempotent", active=True)
    plan = Plan(code=STARTER_PLAN_CODE, name="Starter", billing_mode=BILLING_MODE_DIRECT_STRIPE)
    db_session.add_all([organization, plan])
    db_session.flush()
    account = BillingAccount(
        organization_id=organization.id,
        billing_mode=BILLING_MODE_DIRECT_STRIPE,
        stripe_customer_id="cus_456",
    )
    db_session.add(account)
    db_session.commit()
    monkeypatch.setattr("app.services.stripe_billing.get_settings", _stripe_settings)
    event = {
        "id": "evt_sub",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_456",
                "customer": "cus_456",
                "status": "past_due",
                "metadata": {
                    "organization_id": str(organization.id),
                    "plan_code": STARTER_PLAN_CODE,
                },
            }
        },
    }
    body, signature = _stripe_signature(event)

    first = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )
    second = authed_client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": signature},
    )

    assert first.status_code == 200
    assert first.json()["result"]["status"] == "applied"
    assert second.status_code == 200
    assert second.json()["result"]["status"] == "duplicate"
    assert db_session.query(BillingEvent).filter_by(external_event_id="evt_sub").count() == 1
    assert account.subscriptions[0].status == "past_due"
