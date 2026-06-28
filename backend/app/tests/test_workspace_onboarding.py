from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.organization import (
    Entitlement,
    Organization,
    OrganizationMembership,
    Plan,
    Subscription,
)
from app.models.setting import Setting
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.organizations import STARTER_PLAN_CODE
from app.services.workspace_access import ROLE_WORKSPACE_OWNER
from app.services.workspace_onboarding import apply_onboarding_plan, build_onboarding_plan


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


def _standard_payload(**overrides):
    payload = {
        "template_id": "standard_monitoring",
        "workspace": {
            "slug": "Client One",
            "name": "Client One",
            "description": "Managed client workspace",
        },
        "variables": {
            "domain": "Example.COM",
            "dns_provider": "Cloudflare",
            "report_mailbox": "dmarc@example.com",
            "imap_server": "imap.example.com",
            "imap_password": "super-secret-password",
        },
    }
    payload.update(overrides)
    return payload


def test_onboarding_templates_are_available(authed_client: TestClient):
    """Operators can discover the versioned onboarding template bundle."""
    response = authed_client.get("/api/v1/onboarding/templates")

    assert response.status_code == 200
    templates = response.json()["templates"]
    assert {template["id"] for template in templates} >= {
        "standard_monitoring",
        "dns_only_assessment",
    }
    standard = next(template for template in templates if template["id"] == "standard_monitoring")
    assert standard["domains"]
    assert standard["mail_sources"]
    assert standard["notification_defaults"]
    assert standard["checklist"]


def test_onboarding_preview_renders_without_persisting(
    authed_client: TestClient,
    db_session: Session,
):
    """Preview renders a safe plan and leaves the database unchanged."""
    response = authed_client.post("/api/v1/onboarding/preview", json=_standard_payload())

    assert response.status_code == 200
    plan = response.json()["plan"]
    assert plan["organization"]["slug"] == "client-one"
    assert plan["workspace"]["slug"] == "client-one"
    assert plan["domains"][0]["name"] == "example.com"
    assert plan["mail_sources"][0]["password"] == "[redacted]"
    assert plan["tasks"][0]["href"] == "/domains/example.com"
    assert plan["tasks"][0]["target"]["requires_verification"] is True
    assert "super-secret-password" not in str(plan)
    assert db_session.query(Organization).count() == 0
    assert db_session.query(Workspace).count() == 0
    assert db_session.query(Domain).count() == 0


def test_onboarding_rejects_invalid_domain(authed_client: TestClient):
    """Invalid rendered domains fail before any apply attempt."""
    payload = _standard_payload(variables={"domain": "bad domain"})

    response = authed_client.post("/api/v1/onboarding/preview", json=payload)

    assert response.status_code == 422
    assert "invalid domain" in str(response.json()["detail"])


def test_dns_only_onboarding_tasks_document_future_report_inbox(authed_client: TestClient):
    """DNS-only onboarding still returns actionable setup tasks."""
    response = authed_client.post(
        "/api/v1/onboarding/preview",
        json={
            "template_id": "dns_only_assessment",
            "workspace": {"name": "DNS Client"},
            "variables": {
                "domain": "dns-client.example",
                "dns_provider": "Route 53",
            },
        },
    )

    assert response.status_code == 200
    task_ids = {task["id"] for task in response.json()["plan"]["tasks"]}
    assert "verify-domain-dns:dns-client.example" in task_ids
    assert "document-report-inbox" in task_ids


def test_apply_onboarding_creates_workspace_assets_and_audit(
    authed_client: TestClient,
    db_session: Session,
):
    """Applying a template creates the workspace, assets, defaults, and audit event."""
    response = authed_client.post(
        "/api/v1/onboarding/apply",
        json=_standard_payload(),
        headers={"x-real-ip": "198.51.100.25"},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["applied"] is True
    assert result["organization"]["slug"] == "client-one"
    assert result["workspace"]["slug"] == "client-one"
    assert result["owner"]["status"] == "skipped"
    assert result["subscription"]["plan_code"] == STARTER_PLAN_CODE
    assert result["entitlements"]["monitored_domains"] == "1"
    assert result["results"]["domains"][0]["status"] == "created"
    assert result["results"]["mail_sources"][0]["status"] == "created"
    assert result["tasks"][0]["href"] == "/domains/example.com"
    assert "super-secret-password" not in str(result)

    organization = db_session.query(Organization).filter(Organization.slug == "client-one").one()
    workspace = db_session.query(Workspace).filter(Workspace.slug == "client-one").one()
    domain = db_session.query(Domain).filter(Domain.name == "example.com").one()
    source = db_session.query(MailSource).filter(MailSource.name == "Client One DMARC inbox").one()
    starter_plan = db_session.query(Plan).filter(Plan.code == STARTER_PLAN_CODE).one()
    subscription = (
        db_session.query(Subscription).filter(Subscription.organization_id == organization.id).one()
    )
    entitlement_keys = {
        entitlement.key
        for entitlement in db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .all()
    }
    setting = (
        db_session.query(Setting)
        .filter(Setting.key == "notifications.alert_missing_reports_enabled")
        .one()
    )
    audit = (
        db_session.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.action == "workspace.onboarding_applied")
        .one()
    )

    assert workspace.organization_id == organization.id
    assert subscription.plan_id == starter_plan.id
    assert {"aggregate_reports", "dns_linting", "monitored_domains"} <= entitlement_keys
    assert domain.workspace_id == workspace.id
    assert domain.dkim_selectors == "google,selector1"
    assert source.workspace_id == workspace.id
    assert source.server == "imap.example.com"
    assert source.enabled is False
    assert source.password == "super-secret-password"
    assert setting.value == "true"
    assert audit.workspace_id == workspace.id
    assert audit.ip_address == "198.51.100.25"
    assert "super-secret-password" not in (audit.details or "")


def test_apply_onboarding_respects_monitored_domain_plan_limit(
    authed_client: TestClient,
    db_session: Session,
):
    """Starter onboarding cannot create more monitored domains than the plan allows."""
    response = authed_client.post(
        "/api/v1/onboarding/apply",
        json=_standard_payload(
            domains=[
                {"name": "one.example", "description": "Primary domain"},
                {"name": "two.example", "description": "Second domain"},
            ]
        ),
    )

    assert response.status_code == 402
    detail = response.json()["detail"]
    assert detail["code"] == "plan_limit_exceeded"
    assert detail["metric"] == "monitored_domains"
    assert detail["current"] == 1
    assert detail["limit"] == 1
    assert detail["attempted"] == 1
    assert detail["can_export"] is True
    assert db_session.query(Organization).filter(Organization.slug == "client-one").count() == 0
    assert db_session.query(Workspace).filter(Workspace.slug == "client-one").count() == 0
    assert (
        db_session.query(Domain).filter(Domain.name.in_(["one.example", "two.example"])).count()
        == 0
    )


def test_apply_onboarding_is_idempotent_for_existing_assets(
    authed_client: TestClient,
    db_session: Session,
):
    """Applying the same template again reports existing assets instead of duplicating them."""
    first = authed_client.post("/api/v1/onboarding/apply", json=_standard_payload())
    second = authed_client.post("/api/v1/onboarding/apply", json=_standard_payload())

    assert first.status_code == 200
    assert second.status_code == 200
    result = second.json()["result"]
    assert result["workspace"]["status"] == "existing"
    assert result["results"]["domains"][0]["status"] == "existing"
    assert result["results"]["mail_sources"][0]["status"] == "existing"
    assert db_session.query(Workspace).count() == 1
    assert db_session.query(Organization).count() == 1
    assert db_session.query(Subscription).count() == 1
    assert db_session.query(Domain).count() == 1
    assert db_session.query(MailSource).count() == 1


def test_apply_onboarding_bootstraps_owner_memberships(test_app, db_session: Session):
    """Session users become owners of the new organization and workspace."""
    user = User(email="owner@example.com", is_active=True, is_verified=True)
    db_session.add(user)
    db_session.commit()

    payload = _standard_payload(
        organization={
            "slug": "acme",
            "name": "Acme Inc",
            "description": "Managed customer account",
        }
    )
    with _client_as_user(test_app, db_session, user) as client:
        first = client.post("/api/v1/onboarding/apply", json=payload)
        second = client.post("/api/v1/onboarding/apply", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    result = first.json()["result"]
    assert result["organization"]["slug"] == "acme"
    assert result["owner"]["status"] == "ready"
    assert result["owner"]["email"] == "owner@example.com"
    assert result["owner"]["organization_membership"] == "created"
    assert result["owner"]["workspace_membership"] == "created"

    organization = db_session.query(Organization).filter(Organization.slug == "acme").one()
    workspace = db_session.query(Workspace).filter(Workspace.slug == "client-one").one()
    db_session.refresh(user)
    assert user.workspace_id == workspace.id
    assert (
        db_session.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.role == "organization_owner",
            OrganizationMembership.active.is_(True),
        )
        .count()
        == 1
    )
    assert (
        db_session.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.role == ROLE_WORKSPACE_OWNER,
            WorkspaceMembership.active.is_(True),
        )
        .count()
        == 1
    )
    assert db_session.query(OrganizationMembership).count() == 1
    assert db_session.query(WorkspaceMembership).count() == 1


def test_apply_onboarding_repairs_existing_inactive_owner_memberships(
    test_app,
    db_session: Session,
):
    """Existing non-owner inactive memberships are promoted back to owner access."""
    organization = Organization(slug="acme", name="Acme", active=True)
    workspace = Workspace(
        slug="client-one",
        name="Client One",
        organization=organization,
        active=True,
    )
    user = User(email="owner@example.com", is_active=True, is_verified=True)
    db_session.add_all([organization, workspace, user])
    db_session.flush()
    db_session.add_all(
        [
            OrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                role="organization_auditor",
                active=False,
            ),
            WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=user.id,
                role="auditor",
                active=False,
            ),
        ]
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, user) as client:
        response = client.post(
            "/api/v1/onboarding/apply",
            json=_standard_payload(organization={"slug": "acme", "name": "Acme"}),
        )

    assert response.status_code == 200
    owner = response.json()["result"]["owner"]
    assert owner["organization_membership"] == "reactivated"
    assert owner["workspace_membership"] == "reactivated"
    org_membership = db_session.query(OrganizationMembership).one()
    workspace_membership = db_session.query(WorkspaceMembership).one()
    assert org_membership.role == "organization_owner"
    assert org_membership.active is True
    assert workspace_membership.role == ROLE_WORKSPACE_OWNER
    assert workspace_membership.active is True


def test_apply_onboarding_rejects_workspace_owned_by_another_organization(
    authed_client: TestClient,
    db_session: Session,
):
    """Onboarding does not attach an existing workspace across tenant boundaries."""
    organization = Organization(slug="other", name="Other", active=True)
    db_session.add(organization)
    db_session.flush()
    db_session.add(
        Workspace(
            slug="client-one",
            name="Client One",
            organization_id=organization.id,
            active=True,
        )
    )
    db_session.commit()

    response = authed_client.post(
        "/api/v1/onboarding/apply",
        json=_standard_payload(organization={"slug": "new-owner", "name": "New Owner"}),
    )

    assert response.status_code == 409
    assert "already attached" in response.json()["detail"]


def test_apply_onboarding_links_existing_unscoped_workspace(
    authed_client: TestClient,
    db_session: Session,
):
    """Older unscoped workspaces can be adopted by the requested organization."""
    db_session.add(Workspace(slug="client-one", name="Client One", active=True))
    db_session.commit()

    response = authed_client.post("/api/v1/onboarding/apply", json=_standard_payload())

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["workspace"]["status"] == "linked_existing"
    organization = db_session.query(Organization).filter(Organization.slug == "client-one").one()
    workspace = db_session.query(Workspace).filter(Workspace.slug == "client-one").one()
    assert workspace.organization_id == organization.id


def test_apply_onboarding_rolls_back_on_domain_conflict(
    authed_client: TestClient,
    db_session: Session,
):
    """Domain ownership conflicts leave no partial starter organization behind."""
    organization = Organization(slug="other", name="Other", active=True)
    workspace = Workspace(slug="other", name="Other", organization=organization, active=True)
    db_session.add_all([organization, workspace])
    db_session.flush()
    db_session.add(Domain(workspace_id=workspace.id, name="example.com", active=True))
    db_session.commit()

    response = authed_client.post("/api/v1/onboarding/apply", json=_standard_payload())

    assert response.status_code == 409
    assert "Domain is already owned by another workspace" in str(response.json()["detail"])
    assert db_session.query(Organization).filter(Organization.slug == "client-one").count() == 0
    assert db_session.query(Workspace).filter(Workspace.slug == "client-one").count() == 0


def test_apply_onboarding_rejects_invalid_service_plan(db_session: Session):
    """The service refuses invalid plans before writing any account state."""
    plan = build_onboarding_plan(
        template_id="standard_monitoring",
        workspace={"name": ""},
        variables={"domain": "example.com"},
    )

    assert "workspace.name is required" in plan["errors"]
    try:
        apply_onboarding_plan(db_session, plan=plan, auth_context={"auth_type": "api_key"})
    except ValueError as exc:
        assert "invalid onboarding plan" in str(exc)
    else:
        raise AssertionError("invalid onboarding plan was applied")
    assert db_session.query(Organization).count() == 0


def test_onboarding_notification_overwrite_is_explicit(
    authed_client: TestClient,
    db_session: Session,
):
    """Existing notification settings are preserved unless overwrite_existing is true."""
    db_session.add(
        Setting(
            key="notifications.summary_weekly_enabled",
            value="false",
            description="Existing setting",
            value_type="boolean",
            category="notifications",
        )
    )
    db_session.commit()

    response = authed_client.post("/api/v1/onboarding/apply", json=_standard_payload())
    assert response.status_code == 200
    row = (
        db_session.query(Setting)
        .filter(Setting.key == "notifications.summary_weekly_enabled")
        .one()
    )
    assert row.value == "false"

    overwrite_payload = _standard_payload(overwrite_existing=True)
    response = authed_client.post("/api/v1/onboarding/apply", json=overwrite_payload)
    assert response.status_code == 200
    db_session.refresh(row)
    assert row.value == "true"
