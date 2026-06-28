from contextlib import contextmanager

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
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
from app.models.user import User
from app.models.webhook import WebhookEndpoint
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.organizations import (
    BILLING_MODE_SELF_HOSTED,
    DEFAULT_ORGANIZATION_SLUG,
    SELF_HOSTED_PLAN_CODE,
    STARTER_PLAN_CODE,
    OrganizationPlanLimitError,
    account_state_for_subscriptions,
    bootstrap_default_commercial_foundation,
    get_or_create_starter_plan,
    list_organization_summaries,
    organization_plan_limit,
    organization_summary,
    organization_user_has_active_seat,
    require_organization_feature,
    require_organization_plan_limit,
)
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
    assert summaries[0]["entitlements"]["aggregate_reports"]["value"] == "true"
    assert summaries[0]["account_state"]["status"] == "active"
    assert summaries[0]["account_state"]["can_mutate"] is True
    assert summaries[0]["account_state"]["can_export"] is True
    assert "plan_limits" in summaries[0]
    assert summaries[0]["plan_limits"]["retention_days"]["status"] == "ok"


def test_organization_summary_exposes_plan_limit_usage(db_session: Session):
    organization = Organization(slug="limits", name="Limits", active=True)
    workspace = Workspace(slug="limits-main", name="Limits Main", organization=organization)
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
            Domain(workspace_id=workspace.id, name="example.com", active=True),
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
