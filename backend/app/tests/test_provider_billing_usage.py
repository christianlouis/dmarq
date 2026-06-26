from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.organization import BillingAccount, BillingEvent, Subscription
from app.models.report import DMARCReport, ForensicReport, ReportRecord
from app.models.workspace import Workspace
from app.services.organizations import (
    bootstrap_default_commercial_foundation,
    build_usage_export,
    update_external_subscription_state,
)


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
