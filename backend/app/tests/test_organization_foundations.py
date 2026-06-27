from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import (
    BillingAccount,
    Entitlement,
    Organization,
    Plan,
    Subscription,
)
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.organizations import (
    BILLING_MODE_SELF_HOSTED,
    DEFAULT_ORGANIZATION_SLUG,
    SELF_HOSTED_PLAN_CODE,
    STARTER_PLAN_CODE,
    bootstrap_default_commercial_foundation,
    get_or_create_starter_plan,
    list_organization_summaries,
)
from app.services.workspace_access import ROLE_AUDITOR


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
