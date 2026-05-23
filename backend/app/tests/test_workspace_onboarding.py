from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog


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
    assert plan["workspace"]["slug"] == "client-one"
    assert plan["domains"][0]["name"] == "example.com"
    assert plan["mail_sources"][0]["password"] == "[redacted]"
    assert "super-secret-password" not in str(plan)
    assert db_session.query(Workspace).count() == 0
    assert db_session.query(Domain).count() == 0


def test_onboarding_rejects_invalid_domain(authed_client: TestClient):
    """Invalid rendered domains fail before any apply attempt."""
    payload = _standard_payload(variables={"domain": "bad domain"})

    response = authed_client.post("/api/v1/onboarding/preview", json=payload)

    assert response.status_code == 422
    assert "invalid domain" in str(response.json()["detail"])


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
    assert result["workspace"]["slug"] == "client-one"
    assert result["results"]["domains"][0]["status"] == "created"
    assert result["results"]["mail_sources"][0]["status"] == "created"
    assert "super-secret-password" not in str(result)

    workspace = db_session.query(Workspace).filter(Workspace.slug == "client-one").one()
    domain = db_session.query(Domain).filter(Domain.name == "example.com").one()
    source = db_session.query(MailSource).filter(MailSource.name == "Client One DMARC inbox").one()
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
    assert db_session.query(Domain).count() == 1
    assert db_session.query(MailSource).count() == 1


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
