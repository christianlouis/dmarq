from contextlib import contextmanager
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.organization import BillingAccount, BillingEvent, Organization, Plan, Subscription
from app.models.report import DMARCReport, ForensicReport, ReportRecord
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.organizations import (
    BILLING_MODE_PROVIDER_RESALE,
    MAX_PROVIDER_PAYLOAD_SUMMARY_LENGTH,
    bootstrap_default_commercial_foundation,
    build_usage_export,
    update_external_subscription_state,
)
from app.services.workspace_access import ROLE_AUDITOR, ROLE_WORKSPACE_OWNER


@contextmanager
def _client_as_user(test_app, db_session: Session, user: User):
    async def mock_admin_auth():
        return {"auth_type": "session", "user_id": user.id}

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    original_overrides = dict(test_app.dependency_overrides)
    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    try:
        with TestClient(test_app) as client:
            yield client
    finally:
        test_app.dependency_overrides = original_overrides


def _add_provider_customer(
    db_session: Session,
    *,
    slug: str,
    external_customer_id: str,
    external_subscription_id: str,
):
    organization = Organization(slug=slug, name=slug.title(), active=True)
    plan = Plan(
        code=f"{slug}-plan",
        name=f"{slug.title()} Plan",
        billing_mode=BILLING_MODE_PROVIDER_RESALE,
        active=True,
    )
    db_session.add_all([organization, plan])
    db_session.flush()
    workspace = Workspace(
        slug=f"{slug}-workspace",
        name=f"{slug.title()} Workspace",
        organization_id=organization.id,
        active=True,
    )
    account = BillingAccount(
        organization_id=organization.id,
        billing_mode=BILLING_MODE_PROVIDER_RESALE,
        status="active",
        external_customer_id=external_customer_id,
    )
    subscription = Subscription(
        organization_id=organization.id,
        plan_id=plan.id,
        billing_mode=BILLING_MODE_PROVIDER_RESALE,
        billing_account=account,
        status="active",
        external_subscription_id=external_subscription_id,
    )
    db_session.add_all([workspace, account, subscription])
    db_session.flush()
    return organization, workspace, subscription


def test_provider_usage_export_computes_monthly_metrics(db_session: Session):
    workspace = Workspace(slug="client", name="Client", active=True)
    db_session.add(workspace)
    db_session.flush()
    organization = bootstrap_default_commercial_foundation(db_session)
    workspace.organization_id = organization.id
    billing_account = (
        db_session.query(BillingAccount)
        .filter(BillingAccount.organization_id == organization.id)
        .one()
    )
    billing_account.external_customer_id = "cust-123"
    domain = Domain(workspace_id=workspace.id, name="client.example", active=True)
    db_session.add(domain)
    db_session.flush()
    report = DMARCReport(
        domain_id=domain.id,
        report_id="june-report",
        org_name="Reporter",
        begin_date=1,
        end_date=2,
        processed_at=datetime(2026, 6, 12, 12, 0, 0),
    )
    db_session.add(report)
    db_session.flush()
    db_session.add_all(
        [
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.10",
                count=42,
                disposition="none",
                dkim="pass",
                spf="pass",
                header_from="client.example",
            ),
            ForensicReport(
                domain_id=domain.id,
                report_id="forensic-june",
                processed_at=datetime(2026, 6, 13, 12, 0, 0),
            ),
        ]
    )
    db_session.commit()

    usage = build_usage_export(
        db_session,
        period="2026-06",
        external_customer_id="cust-123",
    )

    exported = usage["organizations"][0]
    metrics = {item["metric"]: item for item in exported["metrics"]}
    assert exported["billing_account"]["external_customer_id"] == "cust-123"
    assert metrics["monitored_domains"]["quantity"] == 1
    assert metrics["aggregate_reports"]["quantity"] == 1
    assert metrics["aggregate_messages"]["quantity"] == 42
    assert metrics["forensic_reports"]["quantity"] == 1
    assert metrics["aggregate_messages"]["idempotency_key"].startswith(
        f"computed:{organization.id}:org:aggregate_messages"
    )


def test_provider_usage_endpoint_rejects_bad_period(authed_client: TestClient):
    response = authed_client.get("/api/v1/provider/billing/usage?period=2026")

    assert response.status_code == 400
    assert "YYYY-MM" in response.json()["detail"]


def test_provider_usage_endpoint_is_scoped_to_accessible_organizations(
    test_app,
    db_session: Session,
):
    allowed_org, allowed_workspace, _ = _add_provider_customer(
        db_session,
        slug="allowed-provider",
        external_customer_id="cust-allowed",
        external_subscription_id="sub-allowed",
    )
    _add_provider_customer(
        db_session,
        slug="hidden-provider",
        external_customer_id="cust-hidden",
        external_subscription_id="sub-hidden",
    )
    user = User(email="provider-auditor@example.com", is_active=True, is_verified=True)
    db_session.add(user)
    db_session.flush()
    db_session.add(
        WorkspaceMembership(
            workspace_id=allowed_workspace.id,
            user_id=user.id,
            role=ROLE_AUDITOR,
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, user) as client:
        response = client.get("/api/v1/provider/billing/usage?period=2026-06")
        assert response.status_code == 200
        organizations = response.json()["usage"]["organizations"]
        assert [item["organization"]["id"] for item in organizations] == [allowed_org.id]

        hidden = client.get("/api/v1/provider/billing/accounts/cust-hidden/usage?period=2026-06")
        assert hidden.status_code == 200
        assert hidden.json()["usage"]["organizations"] == []


def test_provider_subscription_state_update_records_billing_event(db_session: Session):
    organization = bootstrap_default_commercial_foundation(db_session)
    subscription = (
        db_session.query(Subscription).filter(Subscription.organization_id == organization.id).one()
    )
    subscription.external_subscription_id = "sub-provider-123"
    db_session.commit()

    result = update_external_subscription_state(
        db_session,
        external_subscription_id="sub-provider-123",
        status="suspended",
        provider_id="isp-demo",
        external_event_id="evt-1",
        payload_summary="provider reported overdue invoice",
    )

    db_session.refresh(subscription)
    event = db_session.query(BillingEvent).one()
    assert result["old_status"] == "active"
    assert result["new_status"] == "suspended"
    assert subscription.status == "suspended"
    assert event.event_type == "provider.subscription_state_updated"
    assert event.external_event_id == "evt-1"


def test_provider_subscription_state_endpoint_requires_org_admin_access(
    test_app,
    db_session: Session,
):
    _, allowed_workspace, allowed_subscription = _add_provider_customer(
        db_session,
        slug="updatable-provider",
        external_customer_id="cust-updatable",
        external_subscription_id="sub-updatable",
    )
    _, _, hidden_subscription = _add_provider_customer(
        db_session,
        slug="blocked-provider",
        external_customer_id="cust-blocked",
        external_subscription_id="sub-blocked",
    )
    auditor = User(email="provider-state-auditor@example.com", is_active=True, is_verified=True)
    owner = User(email="provider-state-owner@example.com", is_active=True, is_verified=True)
    db_session.add_all([auditor, owner])
    db_session.flush()
    db_session.add_all(
        [
            WorkspaceMembership(
                workspace_id=allowed_workspace.id,
                user_id=auditor.id,
                role=ROLE_AUDITOR,
                active=True,
            ),
            WorkspaceMembership(
                workspace_id=allowed_workspace.id,
                user_id=owner.id,
                role=ROLE_WORKSPACE_OWNER,
                active=True,
            ),
        ]
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, auditor) as client:
        denied = client.post(
            "/api/v1/provider/subscriptions/sub-updatable/state",
            json={"status": "suspended"},
        )
        assert denied.status_code == 404

    with _client_as_user(test_app, db_session, owner) as client:
        updated = client.post(
            "/api/v1/provider/subscriptions/sub-updatable/state",
            json={"status": "suspended"},
        )
        assert updated.status_code == 200
        blocked = client.post(
            "/api/v1/provider/subscriptions/sub-blocked/state",
            json={"status": "suspended"},
        )
        assert blocked.status_code == 404

    db_session.refresh(allowed_subscription)
    db_session.refresh(hidden_subscription)
    assert allowed_subscription.status == "suspended"
    assert hidden_subscription.status == "active"


def test_provider_subscription_state_update_sanitizes_payload_summary(db_session: Session):
    organization = bootstrap_default_commercial_foundation(db_session)
    subscription = (
        db_session.query(Subscription).filter(Subscription.organization_id == organization.id).one()
    )
    subscription.external_subscription_id = "sub-provider-unsafe"
    db_session.commit()

    update_external_subscription_state(
        db_session,
        external_subscription_id="sub-provider-unsafe",
        status="suspended",
        provider_id="isp-demo",
        external_event_id="evt-unsafe",
        payload_summary=" <script>alert(1)</script>\n provider update ",
    )

    event = db_session.query(BillingEvent).filter_by(external_event_id="evt-unsafe").one()
    assert event.payload_summary == "&lt;script&gt;alert(1)&lt;/script&gt; provider update"


def test_provider_subscription_state_update_drops_blank_payload_summary(db_session: Session):
    organization = bootstrap_default_commercial_foundation(db_session)
    subscription = (
        db_session.query(Subscription).filter(Subscription.organization_id == organization.id).one()
    )
    subscription.external_subscription_id = "sub-provider-blank"
    db_session.commit()

    update_external_subscription_state(
        db_session,
        external_subscription_id="sub-provider-blank",
        status="suspended",
        provider_id="isp-demo",
        external_event_id="evt-blank",
        payload_summary=" \n\t ",
    )

    event = db_session.query(BillingEvent).filter_by(external_event_id="evt-blank").one()
    assert event.payload_summary is None


def test_provider_subscription_state_update_truncates_payload_summary(db_session: Session):
    organization = bootstrap_default_commercial_foundation(db_session)
    subscription = (
        db_session.query(Subscription).filter(Subscription.organization_id == organization.id).one()
    )
    subscription.external_subscription_id = "sub-provider-long"
    db_session.commit()

    update_external_subscription_state(
        db_session,
        external_subscription_id="sub-provider-long",
        status="suspended",
        provider_id="isp-demo",
        external_event_id="evt-long",
        payload_summary="a" * (MAX_PROVIDER_PAYLOAD_SUMMARY_LENGTH + 10),
    )

    event = db_session.query(BillingEvent).filter_by(external_event_id="evt-long").one()
    assert len(event.payload_summary) == MAX_PROVIDER_PAYLOAD_SUMMARY_LENGTH
