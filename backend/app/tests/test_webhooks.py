import hmac
import json

from fastapi.testclient import TestClient

from app.models.organization import BillingAccount, Organization
from app.models.webhook import WebhookDelivery
from app.models.workspace import Workspace
from app.services.organizations import (
    BILLING_MODE_MANUAL_CONTRACT,
    STARTER_PLAN_ENTITLEMENTS,
    ensure_entitlements,
    ensure_subscription,
    get_or_create_starter_plan,
)
from app.services.webhook_events import (
    DELIVERY_ABANDONED,
    DELIVERY_DELIVERED,
    DELIVERY_FAILED,
    DELIVERY_PENDING,
    EVENT_ALERT_CREATED,
    EVENT_REPORTS_MISSING,
    EVENT_WEBHOOK_TEST,
    DeliveryAttemptResult,
    create_webhook_endpoint,
    deliver_due_webhooks,
    deliver_webhook_delivery,
    endpoint_to_dict,
    enqueue_webhook_event,
    normalize_event_types,
    queue_test_webhook,
    sign_delivery,
    update_webhook_endpoint,
    validate_webhook_url,
)
from app.services.workspaces import get_or_create_default_workspace


def test_webhook_event_delivery_signs_and_records_success(db_session):
    """Webhook deliveries include replay-resistant metadata and mark success."""
    endpoint, secret = create_webhook_endpoint(
        db_session,
        name="receiver",
        url="https://receiver.example/webhook?token=hidden",
        event_types=[EVENT_ALERT_CREATED],
    )
    deliveries = enqueue_webhook_event(
        db_session,
        event_type=EVENT_ALERT_CREATED,
        payload={"domain": "example.com", "detail": "alert"},
        idempotency_key="alert-example",
    )
    assert len(deliveries) == 1

    seen = {}

    def sender(url, body, headers, timeout_seconds):
        seen["url"] = url
        seen["body"] = body
        seen["headers"] = headers
        seen["timeout_seconds"] = timeout_seconds
        expected = sign_delivery(
            secret,
            deliveries[0],
            int(headers["X-DMARQ-Timestamp"]),
            body,
        )
        assert hmac.compare_digest(headers["X-DMARQ-Signature"], expected)
        assert headers["X-DMARQ-Event"] == EVENT_ALERT_CREATED
        assert headers["X-DMARQ-Idempotency-Key"] == "alert-example"
        return DeliveryAttemptResult(status_code=204, body="")

    delivered = deliver_due_webhooks(db_session, sender=sender)

    assert delivered[0].status == DELIVERY_DELIVERED
    assert json.loads(seen["body"])["data"]["domain"] == "example.com"
    assert seen["url"] == "https://receiver.example/webhook?token=hidden"
    db_session.refresh(endpoint)
    assert endpoint.last_success_at is not None
    assert endpoint.failure_count == 0


def test_webhook_delivery_retries_then_fails(db_session):
    """Transient failures remain pending with backoff, then fail at max attempts."""
    create_webhook_endpoint(
        db_session,
        name="receiver",
        url="https://receiver.example/webhook",
        event_types=[EVENT_ALERT_CREATED],
        max_attempts=2,
    )
    enqueue_webhook_event(
        db_session,
        event_type=EVENT_ALERT_CREATED,
        payload={"domain": "example.com"},
        idempotency_key="retry-example",
    )[0]

    def failing_sender(url, body, headers, timeout_seconds):
        return DeliveryAttemptResult(status_code=503, body="try later")

    first = deliver_due_webhooks(db_session, sender=failing_sender)[0]
    assert first.status == DELIVERY_PENDING
    assert first.attempt_count == 1
    assert first.next_attempt_at > first.last_attempt_at

    first.next_attempt_at = first.last_attempt_at
    db_session.commit()
    second = deliver_due_webhooks(db_session, sender=failing_sender)[0]
    assert second.status == DELIVERY_FAILED
    assert second.attempt_count == 2
    assert second.last_status_code == 503


def test_webhook_idempotency_skips_duplicate_deliveries(db_session):
    """Repeated events with the same idempotency key reuse the existing delivery."""
    create_webhook_endpoint(
        db_session,
        name="receiver",
        url="https://receiver.example/webhook",
        event_types=[EVENT_ALERT_CREATED],
    )
    first = enqueue_webhook_event(
        db_session,
        event_type=EVENT_ALERT_CREATED,
        payload={"domain": "example.com"},
        idempotency_key="same-key",
    )
    second = enqueue_webhook_event(
        db_session,
        event_type=EVENT_ALERT_CREATED,
        payload={"domain": "example.com"},
        idempotency_key="same-key",
    )

    assert first[0].id == second[0].id
    assert db_session.query(WebhookDelivery).count() == 1


def test_webhook_events_without_workspace_stay_in_default_workspace(db_session):
    default_endpoint, _ = create_webhook_endpoint(
        db_session,
        name="default receiver",
        url="https://default.example/webhook",
        event_types=[EVENT_ALERT_CREATED],
    )
    other_workspace = Workspace(slug="webhook-other", name="Webhook Other", active=True)
    db_session.add(other_workspace)
    db_session.flush()
    other_endpoint, _ = create_webhook_endpoint(
        db_session,
        workspace_id=other_workspace.id,
        name="other receiver",
        url="https://other.example/webhook",
        event_types=[EVENT_ALERT_CREATED],
    )

    deliveries = enqueue_webhook_event(
        db_session,
        event_type=EVENT_ALERT_CREATED,
        payload={"domain": "example.com"},
        idempotency_key="default-only",
    )

    assert default_endpoint.workspace_id is not None
    assert other_endpoint.workspace_id == other_workspace.id
    assert [delivery.endpoint_id for delivery in deliveries] == [default_endpoint.id]


def test_webhook_validation_update_and_abandoned_delivery(db_session):
    """Endpoint helpers validate input, update secrets, and abandon disabled endpoints."""
    assert normalize_event_types([]) == ["*"]
    assert normalize_event_types(["*", EVENT_ALERT_CREATED]) == ["*"]
    assert (
        validate_webhook_url(" https://receiver.example/hook ") == "https://receiver.example/hook"
    )

    for bad_events in [["bad.event"]]:
        try:
            normalize_event_types(bad_events)
        except ValueError as exc:
            assert "Unsupported webhook event type" in str(exc)
        else:  # pragma: no cover - defensive assertion shape
            raise AssertionError("invalid event type was accepted")

    for bad_url in ["ftp://receiver.example/hook", "not-a-url"]:
        try:
            validate_webhook_url(bad_url)
        except ValueError as exc:
            assert "absolute http or https URL" in str(exc)
        else:  # pragma: no cover - defensive assertion shape
            raise AssertionError("invalid webhook URL was accepted")

    endpoint, _secret = create_webhook_endpoint(
        db_session,
        name="receiver",
        url="https://receiver.example/webhook",
        event_types=[EVENT_ALERT_CREATED],
        max_attempts=50,
        timeout_seconds=50,
    )
    updated, returned_secret = update_webhook_endpoint(
        db_session,
        endpoint,
        name="receiver two",
        url="https://receiver.example/updated?secret=hidden",
        secret="a-new-secret-value",
        event_types=[EVENT_REPORTS_MISSING],
        enabled=False,
        max_attempts=20,
        timeout_seconds=40,
    )

    assert updated.name == "receiver two"
    assert returned_secret == "a-new-secret-value"
    assert updated.event_types == EVENT_REPORTS_MISSING
    assert updated.max_attempts == 10
    assert updated.timeout_seconds == 30
    assert endpoint_to_dict(updated)["url"] == "https://receiver.example/updated"

    delivery = queue_test_webhook(db_session, updated.id)
    result = deliver_webhook_delivery(db_session, delivery)
    assert result.status == DELIVERY_ABANDONED
    assert "disabled or missing" in result.last_error


def test_admin_webhook_endpoints_hide_secrets_and_show_delivery_status(
    authed_client: TestClient,
    monkeypatch,
):
    """Operators can create, inspect, and test webhooks without secret leakage."""
    created = authed_client.post(
        "/api/v1/webhooks",
        json={
            "name": "ops",
            "url": "https://ops.example/hooks/dmarq?secret=hidden",
            "event_types": [EVENT_WEBHOOK_TEST],
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["secret"]
    assert "hidden" not in body["url"]

    listed = authed_client.get("/api/v1/webhooks")
    assert listed.status_code == 200
    assert listed.json()["endpoints"][0]["url"] == "https://ops.example/hooks/dmarq"
    assert body["secret"] not in listed.text

    def fake_deliver_due_webhooks(db, endpoint_id=None, limit=25, workspace_id=None):
        delivery = (
            db.query(WebhookDelivery)
            .filter(WebhookDelivery.endpoint_id == endpoint_id)
            .order_by(WebhookDelivery.id.desc())
            .first()
        )
        delivery.status = DELIVERY_DELIVERED
        delivery.attempt_count = 1
        db.commit()
        db.refresh(delivery)
        return [delivery]

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.webhooks.deliver_due_webhooks",
        fake_deliver_due_webhooks,
    )

    tested = authed_client.post(f"/api/v1/webhooks/{body['id']}/test")
    assert tested.status_code == 200
    delivery = tested.json()["delivery"]
    assert delivery["event_type"] == EVENT_WEBHOOK_TEST
    assert delivery["status"] == DELIVERY_DELIVERED

    history = authed_client.get("/api/v1/webhooks/deliveries")
    assert history.status_code == 200
    assert history.json()["deliveries"][0]["event_type"] == EVENT_WEBHOOK_TEST


def test_admin_webhook_creation_respects_plan_entitlement(
    authed_client: TestClient,
    db_session,
):
    """Plans with webhooks disabled can inspect existing config but cannot create endpoints."""
    workspace = get_or_create_default_workspace(db_session)
    organization = Organization(slug="webhooks-disabled", name="Webhooks Disabled", active=True)
    workspace.organization = organization
    plan = get_or_create_starter_plan(db_session, commit=False)
    account = BillingAccount(
        organization=organization,
        billing_mode=BILLING_MODE_MANUAL_CONTRACT,
        status="active",
        invoice_delivery_mode="internal",
    )
    db_session.add_all([organization, account])
    db_session.flush()
    subscription = ensure_subscription(db_session, organization, plan, account, commit=False)
    ensure_entitlements(
        db_session,
        organization,
        subscription,
        STARTER_PLAN_ENTITLEMENTS,
        commit=False,
    )
    db_session.commit()

    listed = authed_client.get("/api/v1/webhooks")
    assert listed.status_code == 200
    endpoint, _secret = create_webhook_endpoint(
        db_session,
        workspace_id=workspace.id,
        name="existing",
        url="https://ops.example/existing",
    )
    db_session.commit()

    updated = authed_client.put(
        f"/api/v1/webhooks/{endpoint.id}",
        json={"name": "blocked"},
    )
    assert updated.status_code == 402
    assert updated.json()["detail"]["code"] == "feature_not_included"
    assert updated.json()["detail"]["feature"] == "webhooks"

    disabled = authed_client.delete(f"/api/v1/webhooks/{endpoint.id}")
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    created = authed_client.post(
        "/api/v1/webhooks",
        json={"name": "ops", "url": "https://ops.example/hooks/dmarq"},
    )

    assert created.status_code == 402
    assert created.json()["detail"]["code"] == "feature_not_included"
    assert created.json()["detail"]["feature"] == "webhooks"


def test_admin_webhook_update_disable_filter_and_process(
    authed_client: TestClient,
    monkeypatch,
):
    """Admin API covers update, filtering, due processing, and not-found paths."""
    created = authed_client.post(
        "/api/v1/webhooks",
        json={"name": "ops", "url": "https://ops.example/hooks/dmarq"},
    ).json()

    bad_create = authed_client.post(
        "/api/v1/webhooks",
        json={"name": "bad", "url": "ftp://ops.example/hooks/dmarq"},
    )
    assert bad_create.status_code == 400

    missing_update = authed_client.put("/api/v1/webhooks/9999", json={"name": "missing"})
    assert missing_update.status_code == 404

    bad_update = authed_client.put(
        f"/api/v1/webhooks/{created['id']}",
        json={"event_types": ["not.supported"]},
    )
    assert bad_update.status_code == 400

    updated = authed_client.put(
        f"/api/v1/webhooks/{created['id']}",
        json={
            "name": "ops updated",
            "event_types": [EVENT_REPORTS_MISSING],
            "max_attempts": 2,
            "timeout_seconds": 3,
        },
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "ops updated"
    assert updated.json()["event_types"] == [EVENT_REPORTS_MISSING]

    missing_test = authed_client.post("/api/v1/webhooks/9999/test")
    assert missing_test.status_code == 404

    def fake_process(db, endpoint_id=None, limit=25, workspace_id=None):
        delivery = queue_test_webhook(db, created["id"])
        delivery.status = DELIVERY_DELIVERED
        delivery.attempt_count = 1
        db.commit()
        db.refresh(delivery)
        return [delivery]

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.webhooks.deliver_due_webhooks",
        fake_process,
    )

    processed = authed_client.post("/api/v1/webhooks/deliveries/process?limit=500")
    assert processed.status_code == 200
    assert processed.json()["deliveries"][0]["status"] == DELIVERY_DELIVERED

    endpoint_filtered = authed_client.get(
        f"/api/v1/webhooks/deliveries?endpoint_id={created['id']}&status={DELIVERY_DELIVERED}"
    )
    assert endpoint_filtered.status_code == 200
    assert len(endpoint_filtered.json()["deliveries"]) == 1

    disabled = authed_client.delete(f"/api/v1/webhooks/{created['id']}")
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    missing_delete = authed_client.delete("/api/v1/webhooks/9999")
    assert missing_delete.status_code == 404


def test_admin_webhook_endpoints_respect_selected_workspace_header(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    """Webhook endpoints and deliveries stay inside the selected workspace."""
    selected_workspace = Workspace(
        slug="selected-webhooks",
        name="Selected Webhooks",
        active=True,
    )
    db_session.add(selected_workspace)
    db_session.flush()
    selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

    default_created = authed_client.post(
        "/api/v1/webhooks",
        json={"name": "default hook", "url": "https://default.example/hooks/dmarq"},
    ).json()
    assert default_created["workspace_id"] is not None
    selected_created = authed_client.post(
        "/api/v1/webhooks",
        headers=selected_header,
        json={"name": "selected hook", "url": "https://selected.example/hooks/dmarq"},
    )
    assert selected_created.status_code == 200
    selected_body = selected_created.json()
    assert selected_body["workspace_id"] == selected_workspace.id

    default_list = authed_client.get("/api/v1/webhooks")
    selected_list = authed_client.get("/api/v1/webhooks", headers=selected_header)
    assert [item["name"] for item in default_list.json()["endpoints"]] == ["default hook"]
    assert [item["name"] for item in selected_list.json()["endpoints"]] == ["selected hook"]

    default_update = authed_client.put(
        f"/api/v1/webhooks/{selected_body['id']}",
        json={"name": "wrong workspace"},
    )
    assert default_update.status_code == 404

    def fake_deliver_due_webhooks(db, endpoint_id=None, limit=25, workspace_id=None):
        query = db.query(WebhookDelivery)
        if endpoint_id is not None:
            query = query.filter(WebhookDelivery.endpoint_id == endpoint_id)
        delivery = query.order_by(WebhookDelivery.id.desc()).first()
        delivery.status = DELIVERY_DELIVERED
        delivery.attempt_count = 1
        db.commit()
        db.refresh(delivery)
        return [delivery]

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.webhooks.deliver_due_webhooks",
        fake_deliver_due_webhooks,
    )
    selected_test = authed_client.post(
        f"/api/v1/webhooks/{selected_body['id']}/test",
        headers=selected_header,
    )
    assert selected_test.status_code == 200

    default_history = authed_client.get("/api/v1/webhooks/deliveries")
    selected_history = authed_client.get("/api/v1/webhooks/deliveries", headers=selected_header)
    assert default_history.json()["deliveries"] == []
    assert len(selected_history.json()["deliveries"]) == 1

    default_disable = authed_client.delete(f"/api/v1/webhooks/{selected_body['id']}")
    selected_disable = authed_client.delete(
        f"/api/v1/webhooks/{selected_body['id']}",
        headers=selected_header,
    )
    assert default_disable.status_code == 404
    assert selected_disable.status_code == 200
    assert selected_disable.json()["enabled"] is False
