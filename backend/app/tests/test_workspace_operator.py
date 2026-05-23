from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.alert import AlertHistory
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.report import DMARCReport
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog


def _workspace(db_session: Session, slug: str, name: str) -> Workspace:
    workspace = Workspace(slug=slug, name=name, active=True)
    db_session.add(workspace)
    db_session.flush()
    return workspace


def test_operator_view_summarizes_each_workspace(
    authed_client: TestClient,
    db_session: Session,
):
    """MSP operators can see health, import, alert, drift, and retention summaries."""
    now = datetime.utcnow()
    alpha = _workspace(db_session, "alpha", "Alpha Client")
    beta = _workspace(db_session, "beta", "Beta Client")
    alpha_domain = Domain(
        workspace_id=alpha.id,
        name="alpha.example",
        active=True,
        verified=True,
    )
    beta_domain = Domain(
        workspace_id=beta.id,
        name="beta.example",
        active=True,
        verified=False,
    )
    alpha_source = MailSource(
        workspace_id=alpha.id,
        name="Alpha inbox",
        method="IMAP",
        enabled=True,
    )
    beta_source = MailSource(
        workspace_id=beta.id,
        name="Beta inbox",
        method="IMAP",
        enabled=False,
    )
    db_session.add_all([alpha_domain, beta_domain, alpha_source, beta_source])
    db_session.flush()
    db_session.add_all(
        [
            DMARCReport(
                domain_id=alpha_domain.id,
                report_id="alpha-report",
                org_name="Google",
                begin_date=1,
                end_date=2,
            ),
            MailSourceImport(
                mail_source_id=alpha_source.id,
                trigger="manual",
                status="success",
                finished_at=now,
            ),
            MailSourceImport(
                mail_source_id=beta_source.id,
                trigger="manual",
                status="failed",
                finished_at=now,
            ),
            AlertHistory(
                fingerprint="beta-alert",
                rule="missing_reports",
                severity="warning",
                domain="beta.example",
                title="Missing reports",
                detail="No reports received",
                is_active=True,
            ),
            WorkspaceAuditLog(
                workspace_id=beta.id,
                actor_type="api_key",
                action="mail_source.updated",
                entity_type="mail_source",
                entity_name="Beta inbox",
                created_at=now - timedelta(days=1),
            ),
        ]
    )
    db_session.commit()

    response = authed_client.get("/api/v1/operator/workspaces")

    assert response.status_code == 200
    by_slug = {item["workspace"]["slug"]: item for item in response.json()["workspaces"]}
    assert by_slug["alpha"]["health"]["status"] == "healthy"
    assert by_slug["alpha"]["reports"]["aggregate_total"] == 1
    assert by_slug["alpha"]["mail_sources"]["last_import_status"] == "success"
    assert by_slug["beta"]["health"]["status"] == "critical"
    assert by_slug["beta"]["health"]["active_alerts"] == 1
    assert by_slug["beta"]["health"]["failed_imports_7d"] == 1
    assert by_slug["beta"]["health"]["drift_events_7d"] == 1
    assert by_slug["beta"]["recent_drift"][0]["action"] == "mail_source.updated"


def test_operator_view_does_not_include_inactive_workspaces(
    authed_client: TestClient,
    db_session: Session,
):
    """Inactive workspaces are not listed in the cross-workspace operator view."""
    _workspace(db_session, "active", "Active Client")
    inactive = Workspace(slug="inactive", name="Inactive Client", active=False)
    db_session.add(inactive)
    db_session.commit()

    response = authed_client.get("/api/v1/operator/workspaces")

    assert response.status_code == 200
    slugs = {item["workspace"]["slug"] for item in response.json()["workspaces"]}
    assert slugs == {"active"}


def test_workspace_retention_update_is_audited(
    authed_client: TestClient,
    db_session: Session,
):
    """Operators can update workspace retention controls with an audit record."""
    workspace = _workspace(db_session, "client", "Client")
    db_session.commit()

    response = authed_client.put(
        f"/api/v1/operator/workspaces/{workspace.id}/retention",
        json={
            "aggregate_reports_days": 730,
            "forensic_reports_days": 120,
            "tls_reports_days": 365,
        },
        headers={"x-forwarded-for": "203.0.113.9"},
    )

    assert response.status_code == 200
    db_session.refresh(workspace)
    assert workspace.report_retention_days == 730
    assert workspace.forensic_retention_days == 120
    assert workspace.tls_report_retention_days == 365
    assert response.json()["retention"]["aggregate_reports_days"] == 730

    audit = (
        db_session.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.action == "workspace.retention_updated")
        .one()
    )
    assert audit.workspace_id == workspace.id
    assert audit.ip_address == "203.0.113.9"
    assert "730" in (audit.details or "")
