from contextlib import contextmanager
from datetime import date, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.api_token import APIToken
from app.models.domain import Domain
from app.models.organization import (
    BillingAccount,
    Entitlement,
    Organization,
    OrganizationMembership,
    Plan,
    Subscription,
)
from app.models.report import DMARCReport, ReportRecord
from app.models.user import User
from app.models.webhook import WebhookEndpoint
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.organizations import (
    BILLING_MODE_DIRECT_STRIPE,
    BILLING_MODE_MANUAL_CONTRACT,
    BILLING_MODE_PROVIDER_RESALE,
    BILLING_MODE_PROVIDER_TMF,
    BILLING_MODE_PROVIDER_WHMCS,
    BILLING_MODE_SELF_HOSTED,
    DEFAULT_ORGANIZATION_SLUG,
    SELF_HOSTED_PLAN_CODE,
    STARTER_PLAN_CODE,
    OrganizationPlanLimitError,
    account_state_for_subscriptions,
    bootstrap_default_commercial_foundation,
    ensure_entitlements,
    get_or_create_starter_plan,
    list_organization_summaries,
    organization_plan_limit,
    organization_summary,
    organization_user_has_active_seat,
    require_organization_feature,
    require_organization_plan_limit,
    require_organization_retention_limit,
)
from app.services.report_persistence import save_parsed_report
from app.services.workspace_access import (
    PERMISSION_DOMAINS_WRITE,
    PERMISSION_REPORTS_READ,
    ROLE_AUDITOR,
    ROLE_WORKSPACE_OWNER,
    require_workspace_permission,
)


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


def test_bootstrap_default_commercial_foundation_keeps_self_hosted_install_working(
    db_session: Session,
):
    workspace = Workspace(slug="default", name="Default Workspace", active=True)
    db_session.add(workspace)
    db_session.commit()

    organization = bootstrap_default_commercial_foundation(db_session)

    db_session.refresh(workspace)
    assert organization.slug == DEFAULT_ORGANIZATION_SLUG
    assert workspace.organization_id == organization.id
    assert (
        db_session.query(Plan).filter(Plan.code == SELF_HOSTED_PLAN_CODE).one().billing_mode
        == BILLING_MODE_SELF_HOSTED
    )
    assert (
        db_session.query(BillingAccount)
        .filter(BillingAccount.organization_id == organization.id)
        .one()
        .billing_mode
        == BILLING_MODE_SELF_HOSTED
    )
    assert (
        db_session.query(Subscription)
        .filter(Subscription.organization_id == organization.id)
        .one()
        .status
        == "active"
    )
    entitlement_keys = {
        entitlement.key
        for entitlement in db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .all()
    }
    assert {"aggregate_reports", "forensic_reports", "dns_linting"} <= entitlement_keys


def test_bootstrap_default_commercial_foundation_is_idempotent(db_session: Session):
    bootstrap_default_commercial_foundation(db_session)
    bootstrap_default_commercial_foundation(db_session)

    assert db_session.query(Organization).count() == 1
    assert db_session.query(Plan).count() == 1
    assert db_session.query(BillingAccount).count() == 1
    assert db_session.query(Subscription).count() == 1


def test_get_or_create_starter_plan_commits_public_saas_plan(db_session: Session):
    plan = get_or_create_starter_plan(db_session)

    assert plan.code == STARTER_PLAN_CODE
    assert plan.public is True
    assert plan.retention_days == 90
    assert db_session.query(Plan).filter(Plan.code == STARTER_PLAN_CODE).one().id == plan.id


def test_list_organization_summaries_materializes_account_state(db_session: Session):
    bootstrap_default_commercial_foundation(db_session)

    summaries = list_organization_summaries(db_session)

    assert summaries[0]["slug"] == DEFAULT_ORGANIZATION_SLUG
    assert summaries[0]["billing_accounts"][0]["billing_mode"] == BILLING_MODE_SELF_HOSTED
    assert summaries[0]["subscriptions"][0]["plan"]["code"] == SELF_HOSTED_PLAN_CODE
    assert summaries[0]["billing_owner"]["billing_mode"] == BILLING_MODE_SELF_HOSTED
    assert summaries[0]["billing_owner"]["owner_type"] == "self_hosted"
    assert summaries[0]["entitlements"]["aggregate_reports"]["value"] == "true"
    assert summaries[0]["account_state"]["status"] == "active"
    assert summaries[0]["account_state"]["can_mutate"] is True
    assert summaries[0]["account_state"]["can_export"] is True
    assert "plan_limits" in summaries[0]


def test_list_organization_summaries_batches_queries_across_tenants(
    db_session: Session,
    monkeypatch,
):
    bootstrap_default_commercial_foundation(db_session)
    plan = get_or_create_starter_plan(db_session)
    organizations = []
    for index in range(6):
        organization = Organization(
            slug=f"batch-{index}",
            name=f"Batch {index}",
            active=True,
        )
        workspace = Workspace(
            slug=f"batch-{index}-main",
            name=f"Batch {index} Main",
            organization=organization,
        )
        billing_account = BillingAccount(
            organization=organization,
            billing_mode=BILLING_MODE_PROVIDER_RESALE,
            status="active",
            invoice_delivery_mode="provider_invoice",
        )
        subscription = Subscription(
            organization=organization,
            billing_account=billing_account,
            plan=plan,
            billing_mode=BILLING_MODE_PROVIDER_RESALE,
            status="active",
        )
        user = User(
            workspace=workspace,
            email=f"batch-{index}@example.test",
            is_active=True,
            is_verified=True,
        )
        db_session.add_all(
            [
                organization,
                workspace,
                billing_account,
                subscription,
                user,
                Entitlement(
                    organization=organization,
                    subscription=subscription,
                    key="users",
                    value="5",
                    source="plan",
                    active=True,
                ),
                Entitlement(
                    organization=organization,
                    subscription=subscription,
                    key="retention_days",
                    value="90",
                    source="plan",
                    active=True,
                ),
            ]
        )
        organizations.append(organization)
    db_session.commit()

    monkeypatch.setattr(
        "app.services.organizations.bootstrap_default_commercial_foundation",
        lambda _db: organizations[0],
    )
    statements = []

    def record_statement(*_args):
        statements.append(1)

    event.listen(db_session.bind, "before_cursor_execute", record_statement)
    try:
        summaries = list_organization_summaries(db_session)
    finally:
        event.remove(db_session.bind, "before_cursor_execute", record_statement)

    batch_summaries = [summary for summary in summaries if summary["slug"].startswith("batch-")]
    assert len(batch_summaries) == 6
    assert all(summary["metrics"]["user_count"] == 1 for summary in batch_summaries)
    assert all(summary["plan_limits"]["users"]["current"] == 1 for summary in batch_summaries)
    assert all(
        summary["plan_limits"]["retention_days"]["limit"] == 90 for summary in batch_summaries
    )
    assert len(statements) <= 12


def test_organization_summary_preserves_period_metric_override(db_session: Session, monkeypatch):
    organization = Organization(slug="period-override", name="Period Override", active=True)
    workspace = Workspace(
        slug="period-override-main",
        name="Period Override Main",
        organization=organization,
    )
    entitlement = Entitlement(
        organization=organization,
        key="aggregate_messages",
        value="100",
        source="plan",
        active=True,
    )
    db_session.add_all([organization, workspace, entitlement])
    db_session.commit()

    def fail_if_queried(*_args, **_kwargs):
        raise AssertionError("aggregate usage must not be queried when an override is supplied")

    monkeypatch.setattr(
        "app.services.organizations._aggregate_messages_for_period",
        fail_if_queried,
    )

    limits = organization_summary(
        db_session,
        organization,
        plan_limit_current_values={"aggregate_messages": 42},
    )["plan_limits"]

    assert limits["aggregate_messages"]["current"] == 42
    assert limits["aggregate_messages"]["limit"] == 100
    today = date.today()
    assert limits["aggregate_messages"]["period"] == f"{today.year:04d}-{today.month:02d}"


def test_organization_summary_exposes_plan_limit_usage(db_session: Session):
    organization = Organization(slug="limits", name="Limits", active=True)
    workspace = Workspace(slug="limits-main", name="Limits Main", organization=organization)
    domain = Domain(workspace=workspace, name="example.com", active=True)
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="1",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization=organization,
                key="api_tokens",
                value="false",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization=organization,
                key="webhooks",
                value="false",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization=organization,
                key="users",
                value="3",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization=organization,
                key="aggregate_messages",
                value="100",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    active_user = User(email="active-seat@example.com", is_active=True, is_verified=True)
    organization_user = User(
        email="organization-seat@example.com",
        is_active=True,
        is_verified=True,
    )
    inactive_user = User(email="inactive-seat@example.com", is_active=False, is_verified=True)
    legacy_user = User(
        workspace_id=workspace.id,
        email="legacy-seat@example.com",
        is_active=True,
        is_verified=True,
    )
    db_session.add_all(
        [
            active_user,
            organization_user,
            inactive_user,
            legacy_user,
            domain,
            APIToken(
                workspace_id=workspace.id,
                name="existing",
                key_hash="hash",
                key_prefix="dmarq_existing",
                scopes="reports:read",
                active=True,
            ),
            WebhookEndpoint(
                workspace_id=workspace.id,
                name="hook",
                url="https://hooks.example/dmarq",
                secret="stored",  # noqa: S106 - test fixture value, not a real secret
                event_types="*",
                enabled=True,
            ),
        ]
    )
    db_session.flush()
    today = date.today()
    current_period_start = datetime(today.year, today.month, 1, 12, 0, 0)
    prior_period = current_period_start - timedelta(days=1)
    current_report = DMARCReport(
        domain_id=domain.id,
        report_id="current-message-volume",
        org_name="Reporter",
        begin_date=1,
        end_date=2,
        processed_at=current_period_start,
    )
    prior_report = DMARCReport(
        domain_id=domain.id,
        report_id="prior-message-volume",
        org_name="Reporter",
        begin_date=1,
        end_date=2,
        processed_at=prior_period,
    )
    db_session.add_all([current_report, prior_report])
    db_session.flush()
    db_session.add_all(
        [
            ReportRecord(
                report_id=current_report.id,
                source_ip="203.0.113.10",
                count=80,
                disposition="none",
                dkim="pass",
                spf="pass",
                header_from="example.com",
            ),
            ReportRecord(
                report_id=current_report.id,
                source_ip="203.0.113.12",
                count=-500,
                disposition="none",
                dkim="fail",
                spf="fail",
                header_from="example.com",
            ),
            ReportRecord(
                report_id=prior_report.id,
                source_ip="203.0.113.11",
                count=50,
                disposition="none",
                dkim="pass",
                spf="pass",
                header_from="example.com",
            ),
        ]
    )
    db_session.add_all(
        [
            WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=active_user.id,
                role=ROLE_WORKSPACE_OWNER,
                active=True,
            ),
            WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=inactive_user.id,
                role=ROLE_WORKSPACE_OWNER,
                active=True,
            ),
            OrganizationMembership(
                organization_id=organization.id,
                user_id=organization_user.id,
                role="organization_auditor",
                active=True,
            ),
        ]
    )
    db_session.commit()

    limits = organization_summary(db_session, organization)["plan_limits"]

    assert limits["monitored_domains"]["current"] == 1
    assert limits["monitored_domains"]["limit"] == 1
    assert limits["monitored_domains"]["status"] == "warning"
    assert limits["monitored_domains"]["enforced"] is True
    assert limits["monitored_domains"]["near_limit"] is True
    assert limits["monitored_domains"]["usage_percent"] == 100.0
    assert limits["monitored_domains"]["warning_threshold"] == 1
    assert "at the plan limit" in limits["monitored_domains"]["message"]
    assert limits["api_tokens"]["current"] == 1
    assert limits["api_tokens"]["limit"] == 0
    assert limits["api_tokens"]["status"] == "exceeded"
    assert limits["api_tokens"]["enforced"] is True
    assert limits["api_tokens"]["near_limit"] is True
    assert "over the plan limit" in limits["api_tokens"]["message"]
    assert "(1/0)" not in limits["api_tokens"]["message"]
    assert "1 used, limit 0" in limits["api_tokens"]["message"]
    assert limits["users"]["current"] == 3
    assert limits["users"]["limit"] == 3
    assert limits["users"]["enforced"] is True
    assert limits["users"]["message"] == "users are at the plan limit (3/3)."
    assert limits["webhooks"]["current"] == 1
    assert limits["webhooks"]["limit"] == 0
    assert limits["webhooks"]["enforced"] is True
    assert limits["aggregate_messages"]["current"] == 80
    assert limits["aggregate_messages"]["limit"] == 100
    assert limits["aggregate_messages"]["unit"] == "messages"
    assert limits["aggregate_messages"]["status"] == "warning"
    assert limits["aggregate_messages"]["enforced"] is True
    assert limits["aggregate_messages"]["period"] == f"{today.year:04d}-{today.month:02d}"
    assert "period_start" in limits["aggregate_messages"]
    assert "period_end" in limits["aggregate_messages"]

    list_summary = next(
        summary
        for summary in list_organization_summaries(db_session)
        if summary["slug"] == "limits"
    )
    assert list_summary["plan_limits"]["users"]["message"] == "users are at the plan limit (3/3)."
    assert list_summary["plan_limits"]["api_tokens"]["current"] == 1


def test_organization_user_has_active_seat_requires_active_user(db_session: Session):
    organization = Organization(slug="seat-detection", name="Seat Detection", active=True)
    workspace = Workspace(
        slug="seat-detection-main",
        name="Seat Detection Main",
        organization=organization,
    )
    active_user = User(email="seat-active@example.com", is_active=True, is_verified=True)
    inactive_user = User(email="seat-inactive@example.com", is_active=False, is_verified=True)
    db_session.add_all([organization, workspace, active_user, inactive_user])
    db_session.flush()
    db_session.add_all(
        [
            WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=active_user.id,
                role=ROLE_WORKSPACE_OWNER,
                active=True,
            ),
            WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=inactive_user.id,
                role=ROLE_WORKSPACE_OWNER,
                active=True,
            ),
        ]
    )
    db_session.commit()

    assert organization_user_has_active_seat(db_session, organization, active_user) is True
    assert organization_user_has_active_seat(db_session, organization, inactive_user) is False


def test_organization_plan_limit_warning_payload_is_actionable(db_session: Session):
    organization = Organization(slug="limit-warning", name="Limit Warning", active=True)
    workspace = Workspace(
        slug="limit-warning-main",
        name="Limit Warning Main",
        organization=organization,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="5",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    for index in range(4):
        db_session.add(
            Domain(
                workspace_id=workspace.id,
                name=f"warning-{index}.example",
                active=True,
            )
        )
    db_session.commit()

    limit = organization_plan_limit(db_session, organization, "monitored_domains")

    assert limit is not None
    assert limit["status"] == "warning"
    assert limit["near_limit"] is True
    assert limit["remaining"] == 1
    assert limit["usage_percent"] == 80.0
    assert limit["warning_threshold"] == 4
    assert limit["message"] == (
        "monitored domains are approaching the plan limit (4/5); 1 remaining."
    )


def test_organization_summary_uses_plural_retention_limit_message(db_session: Session):
    organization = Organization(slug="retention-limit", name="Retention Limit", active=True)
    workspace = Workspace(
        slug="retention-limit-main",
        name="Retention Limit Main",
        organization=organization,
        report_retention_days=90,
        forensic_retention_days=90,
        tls_report_retention_days=90,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="retention_days",
                value="90",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    limits = organization_summary(db_session, organization)["plan_limits"]

    assert limits["retention_days"]["status"] == "warning"
    assert limits["retention_days"]["message"] == "retention days are at the plan limit (90/90)."


def test_organization_plan_limit_returns_configured_metric(db_session: Session):
    organization = Organization(slug="single-limit", name="Single Limit", active=True)
    workspace = Workspace(
        slug="single-limit-main",
        name="Single Limit Main",
        organization=organization,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Domain(workspace=workspace, name="one.example", active=True),
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="2",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    limit = organization_plan_limit(db_session, organization, "monitored_domains")

    assert limit is not None
    assert limit["current"] == 1
    assert limit["limit"] == 2
    assert limit["remaining"] == 1
    assert limit["entitlement_key"] == "monitored_domains"


def test_require_organization_plan_limit_allows_unmetered_and_available_capacity(
    db_session: Session,
):
    organization = Organization(slug="limit-allowed", name="Limit Allowed", active=True)
    workspace = Workspace(
        slug="limit-allowed-main",
        name="Limit Allowed Main",
        organization=organization,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="2",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization=organization,
                key="retention_days",
                value="unlimited",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    require_organization_plan_limit(db_session, organization, "monitored_domains")
    require_organization_plan_limit(db_session, organization, "retention_days")
    require_organization_plan_limit(db_session, organization, "missing_metric")
    require_organization_plan_limit(db_session, organization, "monitored_domains", increment=0)


def test_require_organization_plan_limit_raises_with_api_safe_detail(db_session: Session):
    organization = Organization(slug="limit-blocked", name="Limit Blocked", active=True)
    workspace = Workspace(
        slug="limit-blocked-main",
        name="Limit Blocked Main",
        organization=organization,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Domain(workspace=workspace, name="one.example", active=True),
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="1",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    with pytest.raises(OrganizationPlanLimitError) as exc_info:
        require_organization_plan_limit(db_session, organization, "monitored_domains")

    assert exc_info.value.to_detail() == {
        "code": "plan_limit_exceeded",
        "metric": "monitored_domains",
        "current": 1,
        "limit": 1,
        "attempted": 1,
        "unit": "count",
        "entitlement_key": "monitored_domains",
        "can_export": True,
        "message": "Plan limit for monitored_domains would be exceeded "
        "(1 current + 1 requested > 1 count)",
    }


def test_organization_summary_handles_unbounded_and_missing_entitlements(
    db_session: Session,
):
    organization = Organization(slug="unbounded", name="Unbounded", active=True)
    workspace = Workspace(
        slug="unbounded-main",
        name="Unbounded Main",
        organization=organization,
        report_retention_days=365,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="retention_days",
                value="unlimited",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization=organization,
                key="mail_sources",
                value="not-metered",
                source="override",
                active=True,
            ),
        ]
    )
    db_session.commit()

    require_organization_feature(db_session, organization, "api_tokens")
    limits = organization_summary(db_session, organization)["plan_limits"]

    assert limits["retention_days"]["limit"] is None
    assert limits["retention_days"]["remaining"] is None
    assert limits["retention_days"]["status"] == "ok"
    assert limits["mail_sources"]["limit"] is None
    assert limits["mail_sources"]["source"] == "override"


def test_organization_summary_counts_largest_retention_window(db_session: Session):
    organization = Organization(slug="retention-window", name="Retention Window", active=True)
    workspace = Workspace(
        slug="retention-window-main",
        name="Retention Window Main",
        organization=organization,
        report_retention_days=30,
        forensic_retention_days=60,
        tls_report_retention_days=120,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="retention_days",
                value="90",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    limit = organization_plan_limit(db_session, organization, "retention_days")

    assert limit is not None
    assert limit["current"] == 120
    assert limit["limit"] == 90
    assert limit["remaining"] == 0
    assert limit["status"] == "exceeded"
    assert limit["enforced"] is True
    assert limit["unit"] == "days"
    assert "over the plan limit" in limit["message"]


def test_require_organization_plan_limit_allows_unconfigured_and_unlimited_limits(
    db_session: Session,
):
    organization = Organization(slug="quota-open", name="Quota Open", active=True)
    workspace = Workspace(slug="quota-open-main", name="Quota Open Main", organization=organization)
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="mail_sources",
                value="unlimited",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    assert organization_plan_limit(db_session, organization, "monitored_domains") is None
    require_organization_plan_limit(
        db_session,
        organization,
        "monitored_domains",
    )
    require_organization_plan_limit(
        db_session,
        organization,
        "mail_sources",
        increment=100,
    )
    require_organization_plan_limit(
        db_session,
        organization,
        "mail_sources",
        increment=0,
    )


def test_require_organization_retention_limit_allows_safe_requests(
    db_session: Session,
):
    unconfigured = Organization(
        slug="retention-unconfigured",
        name="Retention Unconfigured",
        active=True,
    )
    bounded = Organization(slug="retention-bounded", name="Retention Bounded", active=True)
    bounded_workspace = Workspace(
        slug="retention-bounded-main",
        name="Retention Bounded Main",
        organization=bounded,
        report_retention_days=30,
        forensic_retention_days=30,
        tls_report_retention_days=30,
    )
    unlimited = Organization(slug="retention-unlimited", name="Retention Unlimited", active=True)
    db_session.add_all(
        [
            unconfigured,
            bounded,
            bounded_workspace,
            unlimited,
            Entitlement(
                organization=bounded,
                key="retention_days",
                value="90",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization=unlimited,
                key="retention_days",
                value="unlimited",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    require_organization_retention_limit(db_session, unconfigured, 365)
    require_organization_retention_limit(db_session, bounded, 90)
    require_organization_retention_limit(db_session, unlimited, 3650)
    require_organization_retention_limit(db_session, bounded, 0)


def test_require_organization_retention_limit_raises_structured_limit_error(
    db_session: Session,
):
    organization = Organization(
        slug="retention-blocked",
        name="Retention Blocked",
        active=True,
    )
    workspace = Workspace(
        slug="retention-blocked-main",
        name="Retention Blocked Main",
        organization=organization,
        report_retention_days=30,
        forensic_retention_days=30,
        tls_report_retention_days=30,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="retention_days",
                value="90",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    with pytest.raises(OrganizationPlanLimitError) as exc_info:
        require_organization_retention_limit(db_session, organization, 120)

    assert str(exc_info.value) == (
        "Plan limit for retention_days would be exceeded " "(30 current + 90 requested > 90 days)"
    )
    assert exc_info.value.to_detail() == {
        "code": "plan_limit_exceeded",
        "metric": "retention_days",
        "current": 30,
        "limit": 90,
        "attempted": 90,
        "unit": "days",
        "entitlement_key": "retention_days",
        "can_export": True,
        "message": (
            "Plan limit for retention_days would be exceeded "
            "(30 current + 90 requested > 90 days)"
        ),
    }


def test_require_organization_plan_limit_raises_structured_limit_error(
    db_session: Session,
):
    organization = Organization(slug="quota-blocked", name="Quota Blocked", active=True)
    workspace = Workspace(
        slug="quota-blocked-main",
        name="Quota Blocked Main",
        organization=organization,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="2",
                source="plan",
                active=True,
            ),
            Domain(workspace=workspace, name="one.example", active=True),
            Domain(workspace=workspace, name="two.example", active=True),
        ]
    )
    db_session.commit()

    with pytest.raises(OrganizationPlanLimitError) as exc_info:
        require_organization_plan_limit(
            db_session,
            organization,
            "monitored_domains",
        )

    assert str(exc_info.value) == (
        "Plan limit for monitored_domains would be exceeded " "(2 current + 1 requested > 2 count)"
    )
    assert exc_info.value.to_detail() == {
        "code": "plan_limit_exceeded",
        "metric": "monitored_domains",
        "current": 2,
        "limit": 2,
        "attempted": 1,
        "unit": "count",
        "entitlement_key": "monitored_domains",
        "can_export": True,
        "message": (
            "Plan limit for monitored_domains would be exceeded "
            "(2 current + 1 requested > 2 count)"
        ),
    }


def test_require_organization_plan_limit_allows_within_limit_increment(
    db_session: Session,
):
    organization = Organization(slug="quota-room", name="Quota Room", active=True)
    workspace = Workspace(slug="quota-room-main", name="Quota Room Main", organization=organization)
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="2",
                source="plan",
                active=True,
            ),
            Domain(workspace=workspace, name="one.example", active=True),
        ]
    )
    db_session.commit()

    limit = organization_plan_limit(db_session, organization, "monitored_domains")

    assert limit is not None
    assert limit["current"] == 1
    assert limit["remaining"] == 1
    require_organization_plan_limit(
        db_session,
        organization,
        "monitored_domains",
    )


def test_save_parsed_report_enforces_aggregate_message_volume_limit(
    db_session: Session,
):
    organization = Organization(slug="message-volume", name="Message Volume", active=True)
    workspace = Workspace(
        slug="message-volume-main",
        name="Message Volume Main",
        organization=organization,
    )
    domain = Domain(workspace=workspace, name="volume.example", active=True)
    db_session.add_all(
        [
            organization,
            workspace,
            domain,
            Entitlement(
                organization=organization,
                key="aggregate_messages",
                value="100",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    today = date.today()
    existing_report = DMARCReport(
        domain_id=domain.id,
        report_id="existing-volume",
        org_name="Reporter",
        begin_date=1,
        end_date=2,
        processed_at=datetime(today.year, today.month, 1, 12, 0, 0),
    )
    db_session.add(existing_report)
    db_session.flush()
    db_session.add(
        ReportRecord(
            report_id=existing_report.id,
            source_ip="203.0.113.10",
            count=80,
            disposition="none",
            dkim="pass",
            spf="pass",
            header_from="volume.example",
        )
    )
    db_session.commit()

    with pytest.raises(OrganizationPlanLimitError) as exc_info:
        save_parsed_report(
            db_session,
            {
                "domain": "volume.example",
                "report_id": "new-volume",
                "org_name": "Reporter",
                "policy": {"p": "none", "pct": "100"},
                "records": [
                    {
                        "source_ip": "203.0.113.20",
                        "count": 25,
                        "disposition": "none",
                        "dkim_result": "pass",
                        "spf_result": "pass",
                        "header_from": "volume.example",
                    }
                ],
            },
            workspace_id=workspace.id,
        )

    assert exc_info.value.to_detail() == {
        "code": "plan_limit_exceeded",
        "metric": "aggregate_messages",
        "current": 80,
        "limit": 100,
        "attempted": 25,
        "unit": "messages",
        "entitlement_key": "aggregate_messages",
        "can_export": True,
        "message": (
            "Plan limit for aggregate_messages would be exceeded "
            "(80 current + 25 requested > 100 messages)"
        ),
    }
    assert (
        db_session.query(DMARCReport).filter(DMARCReport.report_id == "new-volume").first() is None
    )


@pytest.mark.parametrize(
    ("count", "message"),
    [
        (-1, "DMARC record count cannot be negative"),
        ("not-a-number", "DMARC record count must be an integer"),
    ],
)
def test_save_parsed_report_rejects_invalid_aggregate_message_counts(
    db_session: Session,
    count,
    message,
):
    organization = Organization(slug="negative-volume", name="Negative Volume", active=True)
    workspace = Workspace(
        slug="negative-volume-main",
        name="Negative Volume Main",
        organization=organization,
    )
    domain = Domain(workspace=workspace, name="negative.example", active=True)
    db_session.add_all([organization, workspace, domain])
    db_session.flush()

    with pytest.raises(ValueError, match=message):
        save_parsed_report(
            db_session,
            {
                "domain": "negative.example",
                "report_id": "negative-volume",
                "org_name": "Reporter",
                "policy": {"p": "none", "pct": "100"},
                "records": [
                    {
                        "source_ip": "203.0.113.30",
                        "count": count,
                        "disposition": "none",
                        "dkim_result": "fail",
                        "spf_result": "fail",
                        "header_from": "negative.example",
                    }
                ],
            },
            workspace_id=workspace.id,
        )

    assert (
        db_session.query(DMARCReport).filter(DMARCReport.report_id == "negative-volume").first()
        is None
    )


def test_duplicate_active_entitlements_use_latest_row(db_session: Session):
    organization = Organization(slug="duplicate-entitlements", name="Duplicate Entitlements")
    db_session.add(organization)
    db_session.flush()
    db_session.add_all(
        [
            Entitlement(
                organization_id=organization.id,
                key="webhooks",
                value="false",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization_id=organization.id,
                key="webhooks",
                value="true",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    require_organization_feature(db_session, organization, "webhooks")

    summary = organization_summary(db_session, organization)
    assert summary["entitlements"]["webhooks"]["value"] == "true"


def test_ensure_entitlements_deactivates_stale_plan_grants(db_session: Session):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="stale-plan-entitlements", name="Stale Plan Entitlements")
    db_session.add(organization)
    db_session.flush()
    subscription = Subscription(
        organization_id=organization.id,
        plan_id=plan.id,
        billing_mode=BILLING_MODE_PROVIDER_RESALE,
        status="active",
        current_period_start=datetime.utcnow(),
    )
    db_session.add(subscription)
    db_session.flush()
    db_session.add_all(
        [
            Entitlement(
                organization_id=organization.id,
                subscription_id=subscription.id,
                key="old_plan_feature",
                value="true",
                source="plan",
                active=True,
            ),
            Entitlement(
                organization_id=organization.id,
                key="manual_override",
                value="true",
                source="manual",
                active=True,
            ),
        ]
    )
    db_session.commit()

    ensure_entitlements(
        db_session,
        organization,
        subscription,
        {"new_plan_feature": "true"},
    )

    old_plan_feature = (
        db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .filter(Entitlement.key == "old_plan_feature")
        .one()
    )
    manual_override = (
        db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .filter(Entitlement.key == "manual_override")
        .one()
    )
    assert old_plan_feature.active is False
    assert manual_override.active is True
    assert (
        db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .filter(Entitlement.key == "new_plan_feature", Entitlement.active.is_(True))
        .count()
        == 1
    )


def test_account_state_reports_provider_grace_without_blocking(db_session: Session):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="grace", name="Grace", active=True)
    account = BillingAccount(
        organization=organization,
        billing_mode="provider_resale",
        status="active",
        invoice_delivery_mode="provider_invoice",
    )
    subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode="provider_resale",
        status="past_due_provider_reported",
    )
    db_session.add_all([organization, account, subscription])
    db_session.commit()

    state = account_state_for_subscriptions([subscription])

    assert state["status"] == "past_due_provider_reported"
    assert state["grace_period"] is True
    assert state["read_only"] is False
    assert state["can_mutate"] is True


def test_organization_summary_exposes_billing_ownership(db_session: Session):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="provider-owner", name="Provider Owner", active=True)
    account = BillingAccount(
        organization=organization,
        billing_mode=BILLING_MODE_PROVIDER_WHMCS,
        status="active",
        provider_id="whmcs-demo",
        external_customer_id="cust-42",
        invoice_delivery_mode="provider_invoice",
    )
    subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode=BILLING_MODE_PROVIDER_WHMCS,
        status="active",
        external_subscription_id="sub-42",
    )
    db_session.add_all([organization, account, subscription])
    db_session.commit()

    summary = organization_summary(db_session, organization)

    assert summary["billing_owner"]["billing_mode"] == BILLING_MODE_PROVIDER_WHMCS
    assert summary["billing_owner"]["billing_mode_label"] == "WHMCS provider"
    assert summary["billing_owner"]["owner_type"] == "provider"
    assert summary["billing_owner"]["owner"] == "Hosting provider billing system"
    assert summary["billing_owner"]["invoice_delivery_mode"] == "provider_invoice"
    assert summary["billing_owner"]["invoice_delivery_label"] == "Provider WHMCS invoice"
    assert summary["billing_owner"]["provider_id"] == "whmcs-demo"
    assert summary["billing_owner"]["external_customer_id"] == "cust-42"
    assert summary["billing_owner"]["subscription_status"] == "active"
    assert summary["billing_owner"]["plan_code"] == STARTER_PLAN_CODE
    assert summary["billing_owner"]["can_manage_in_app"] is False


@pytest.mark.parametrize(
    ("billing_mode", "expected_label", "expected_owner_type", "expected_in_app"),
    [
        (BILLING_MODE_DIRECT_STRIPE, "Direct Stripe", "dmarq", True),
        ("stripe", "Direct Stripe", "dmarq", True),
        (BILLING_MODE_MANUAL_CONTRACT, "Manual contract", "dmarq", False),
        (BILLING_MODE_PROVIDER_RESALE, "Provider resale", "provider", False),
        (BILLING_MODE_PROVIDER_TMF, "TM Forum provider", "provider", False),
        (BILLING_MODE_SELF_HOSTED, "Self-hosted license", "self_hosted", False),
        ("partner_portal", "Partner Portal", "external", False),
    ],
)
def test_organization_summary_labels_billing_owner_modes(
    db_session: Session,
    billing_mode: str,
    expected_label: str,
    expected_owner_type: str,
    expected_in_app: bool,
):
    plan = get_or_create_starter_plan(db_session)
    safe_slug = billing_mode.replace("_", "-")
    organization = Organization(slug=f"billing-{safe_slug}", name=f"Billing {billing_mode}")
    account = BillingAccount(
        organization=organization,
        billing_mode=billing_mode,
        status="trialing",
        invoice_delivery_mode="internal",
    )
    subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode=billing_mode,
        status="trialing",
    )
    db_session.add_all([organization, account, subscription])
    db_session.commit()

    owner = organization_summary(db_session, organization)["billing_owner"]

    assert owner["billing_mode"] == billing_mode
    assert owner["billing_mode_label"] == expected_label
    assert owner["owner_type"] == expected_owner_type
    assert owner["status"] == "trialing"
    assert owner["subscription_status"] == "trialing"
    assert owner["can_manage_in_app"] is expected_in_app


def test_organization_summary_reports_unconfigured_billing_owner(db_session: Session):
    organization = Organization(slug="billing-unconfigured", name="Billing Unconfigured")
    db_session.add(organization)
    db_session.commit()

    owner = organization_summary(db_session, organization)["billing_owner"]

    assert owner["billing_mode"] == "unconfigured"
    assert owner["billing_mode_label"] == "Unconfigured"
    assert owner["owner_type"] == "unconfigured"
    assert owner["owner"] == "No billing owner configured"
    assert owner["status"] == "unconfigured"
    assert owner["invoice_delivery_mode"] is None
    assert owner["subscription_status"] is None
    assert owner["plan_code"] is None
    assert owner["can_manage_in_app"] is False


def test_account_state_reports_unclassified_status_without_active_reason(
    db_session: Session,
):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="past-due", name="Past Due", active=True)
    account = BillingAccount(
        organization=organization,
        billing_mode="stripe",
        status="active",
        invoice_delivery_mode="stripe_invoice",
    )
    subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode="stripe",
        status="past_due",
    )
    db_session.add_all([organization, account, subscription])
    db_session.commit()

    state = account_state_for_subscriptions([subscription], include_plan_code=False)

    assert state["status"] == "past_due"
    assert state["plan_code"] is None
    assert state["read_only"] is False
    assert state["can_mutate"] is True
    assert "not classified as read-only" in state["reason"]
    assert "normal workspace changes" not in state["reason"]


def test_account_state_reports_suspended_as_read_only(db_session: Session):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="suspended", name="Suspended", active=True)
    account = BillingAccount(
        organization=organization,
        billing_mode="provider_resale",
        status="active",
        invoice_delivery_mode="provider_invoice",
    )
    subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode="provider_resale",
        status="suspended",
    )
    db_session.add_all([organization, account, subscription])
    db_session.commit()

    summary = organization_summary(db_session, organization)

    assert summary["account_state"]["status"] == "suspended"
    assert summary["account_state"]["read_only"] is True
    assert summary["account_state"]["can_mutate"] is False
    assert summary["account_state"]["can_export"] is True


def test_workspace_write_permission_blocks_read_only_subscription(db_session: Session):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="locked", name="Locked", active=True)
    workspace = Workspace(slug="locked-main", name="Locked Main", organization=organization)
    account = BillingAccount(
        organization=organization,
        billing_mode="provider_resale",
        status="active",
        invoice_delivery_mode="provider_invoice",
    )
    subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode="provider_resale",
        status="terminated",
    )
    db_session.add_all([organization, workspace, account, subscription])
    db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        require_workspace_permission(
            {"auth_type": "api_key"},
            PERMISSION_DOMAINS_WRITE,
            db_session,
            workspace,
        )

    assert exc_info.value.status_code == 402
    assert exc_info.value.detail["code"] == "account_read_only"
    assert exc_info.value.detail["subscription_status"] == "terminated"
    assert exc_info.value.detail["can_export"] is True


def test_workspace_write_permission_uses_primary_subscription_priority(
    db_session: Session,
):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="mixed", name="Mixed", active=True)
    workspace = Workspace(slug="mixed-main", name="Mixed Main", organization=organization)
    account = BillingAccount(
        organization=organization,
        billing_mode="provider_resale",
        status="active",
        invoice_delivery_mode="provider_invoice",
    )
    active_subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode="provider_resale",
        status="active",
    )
    terminated_subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode="provider_resale",
        status="terminated",
    )
    db_session.add_all(
        [
            organization,
            workspace,
            account,
            active_subscription,
            terminated_subscription,
        ]
    )
    db_session.commit()

    require_workspace_permission(
        {"auth_type": "api_key"},
        PERMISSION_DOMAINS_WRITE,
        db_session,
        workspace,
    )


def test_workspace_read_permission_allows_read_only_subscription(db_session: Session):
    plan = get_or_create_starter_plan(db_session)
    organization = Organization(slug="readable", name="Readable", active=True)
    workspace = Workspace(slug="readable-main", name="Readable Main", organization=organization)
    account = BillingAccount(
        organization=organization,
        billing_mode="provider_resale",
        status="active",
        invoice_delivery_mode="provider_invoice",
    )
    subscription = Subscription(
        organization=organization,
        billing_account=account,
        plan=plan,
        billing_mode="provider_resale",
        status="suspended",
    )
    db_session.add_all([organization, workspace, account, subscription])
    db_session.commit()

    require_workspace_permission(
        {"auth_type": "api_key"},
        PERMISSION_REPORTS_READ,
        db_session,
        workspace,
    )


def test_organization_endpoints_are_scoped_to_accessible_tenants(test_app, db_session: Session):
    allowed_org = Organization(slug="allowed", name="Allowed", active=True)
    hidden_org = Organization(slug="hidden", name="Hidden", active=True)
    db_session.add_all([allowed_org, hidden_org])
    db_session.flush()
    allowed_workspace = Workspace(
        slug="allowed-workspace",
        name="Allowed Workspace",
        organization_id=allowed_org.id,
        active=True,
    )
    hidden_workspace = Workspace(
        slug="hidden-workspace",
        name="Hidden Workspace",
        organization_id=hidden_org.id,
        active=True,
    )
    user = User(email="auditor-org@example.com", is_active=True, is_verified=True)
    db_session.add_all([allowed_workspace, hidden_workspace, user])
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
        listed = client.get("/api/v1/organizations")
        assert listed.status_code == 200
        slugs = {item["slug"] for item in listed.json()["organizations"]}
        assert slugs == {"allowed"}

        allowed = client.get(f"/api/v1/organizations/{allowed_org.id}")
        assert allowed.status_code == 200
        assert allowed.json()["organization"]["slug"] == "allowed"

        hidden = client.get(f"/api/v1/organizations/{hidden_org.id}")
        assert hidden.status_code == 403
