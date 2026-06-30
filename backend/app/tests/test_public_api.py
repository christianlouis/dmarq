from datetime import date
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.core.security import require_api_token_any_scope
from app.models.alert import AlertHistory
from app.models.api_token import APIToken
from app.models.domain import Domain
from app.models.organization import BillingAccount, Organization
from app.models.workspace import Workspace
from app.services.api_tokens import (
    MCP_READ_SCOPE,
    READ_POSTURE_SCOPE,
    READ_REPORTS_SCOPE,
    READ_TLS_SCOPE,
    create_api_token,
)
from app.services.health_score_snapshots import upsert_health_score_snapshot
from app.services.organizations import (
    BILLING_MODE_MANUAL_CONTRACT,
    STARTER_PLAN_ENTITLEMENTS,
    ensure_entitlements,
    ensure_subscription,
    get_or_create_starter_plan,
)
from app.services.report_persistence import save_parsed_report
from app.services.report_store import ReportStore
from app.services.workspace_access import (
    ROLE_ANALYST,
    ROLE_WORKSPACE_OWNER,
    role_for_workspace,
)
from app.services.workspaces import get_or_create_default_workspace

DOMAIN = "example.com"

MINIMAL_REPORT = {
    "domain": DOMAIN,
    "report_id": "public-api-001",
    "org_name": "Test Org",
    "policy": {"p": "none", "sp": "", "pct": "100"},
    "records": [
        {
            "source_ip": "1.2.3.4",
            "count": 5,
            "disposition": "none",
            "dkim_result": "pass",
            "spf_result": "pass",
            "dkim": [{"domain": DOMAIN, "result": "pass", "selector": "google"}],
            "spf": [{"domain": DOMAIN, "result": "pass"}],
        }
    ],
    "summary": {"total_count": 5, "passed_count": 5, "failed_count": 0, "pass_rate": 100.0},
}

FAILING_REPORT = {
    **MINIMAL_REPORT,
    "report_id": "public-api-failing-001",
    "records": [
        {
            "source_ip": "5.6.7.8",
            "count": 10,
            "disposition": "none",
            "dkim_result": "fail",
            "spf_result": "fail",
            "dkim": [{"domain": DOMAIN, "result": "fail", "selector": "legacy"}],
            "spf": [{"domain": DOMAIN, "result": "fail"}],
        }
    ],
    "summary": {"total_count": 10, "passed_count": 0, "failed_count": 10, "pass_rate": 0.0},
}


def _seed_report_store():
    ReportStore.get_instance().add_report(MINIMAL_REPORT)


def _persist_report(db_session):
    save_parsed_report(db_session, MINIMAL_REPORT)
    db_session.commit()


def _persist_failing_report(db_session, report=None, *, workspace_id=None):
    save_parsed_report(db_session, report or FAILING_REPORT, workspace_id=workspace_id)
    db_session.commit()


def test_public_reports_api_requires_scoped_token(client: TestClient, db_session):
    """Stable public report endpoints require scoped tokens and audit usage."""
    _seed_report_store()
    created = create_api_token(db_session, name="report bot", scopes=[READ_REPORTS_SCOPE])

    missing = client.get(f"/api/v1/public/domains/{DOMAIN}/reports")
    assert missing.status_code == 401

    invalid = client.get(
        f"/api/v1/public/domains/{DOMAIN}/reports",
        headers={"X-API-Key": "not-valid"},
    )
    assert invalid.status_code == 401

    response = client.get(
        f"/api/v1/public/domains/{DOMAIN}/reports",
        headers={"X-API-Key": created.secret},
    )
    assert response.status_code == 200
    assert response.json()["reports"][0]["id"] == "public-api-001"

    token = db_session.query(APIToken).filter(APIToken.id == created.token.id).one()
    assert token.usage_count == 1
    assert token.last_used_at is not None
    assert token.last_used_ip


def test_public_domains_summary_uses_scoped_token_context(client: TestClient, db_session):
    """Public domain summaries reuse workspace-aware domain authorization."""
    _persist_report(db_session)
    created = create_api_token(db_session, name="summary bot", scopes=[READ_REPORTS_SCOPE])

    response = client.get(
        "/api/v1/public/domains",
        headers={"X-API-Key": created.secret},
    )

    assert response.status_code == 200
    assert response.json()["domains"][0]["domain_name"] == DOMAIN


def test_public_export_catalog_lists_available_exports_and_token_usage(
    client: TestClient,
    db_session,
):
    """Public export catalog exposes stable routes without leaking token secrets."""
    _persist_report(db_session)
    created = create_api_token(
        db_session,
        name="catalog bot",
        scopes=[READ_REPORTS_SCOPE, READ_POSTURE_SCOPE],
    )

    response = client.get(
        "/api/v1/public/exports",
        headers={"X-API-Key": created.secret},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["workspace"]["domain_count"] == 1
    assert body["token"]["name"] == "catalog bot"
    assert body["token"]["usage_count"] == 1
    assert "secret" not in body["token"]
    endpoint_by_key = {endpoint["key"]: endpoint for endpoint in body["public_endpoints"]}
    assert endpoint_by_key["domain_reports"]["available"] is True
    assert endpoint_by_key["health_evidence_export"]["available"] is True
    assert endpoint_by_key["tls_report_summary"]["available"] is False
    assert body["domains"][0]["domain"] == DOMAIN
    assert (
        body["domains"][0]["exports"]["health_evidence_export"]["href"]
        == f"/api/v1/public/domains/{DOMAIN}/posture/evidence/export"
    )
    assert body["mcp"]["available"] is False
    assert "export_catalog" in {tool["name"] for tool in body["mcp"]["tools"]}


def test_public_export_catalog_accepts_tls_or_mcp_scope_without_domain_leak(
    client: TestClient,
    db_session,
):
    """Catalog is discoverable to read-only tokens but limits domain-specific links."""
    _persist_report(db_session)
    tls_token = create_api_token(db_session, name="tls bot", scopes=[READ_TLS_SCOPE])
    mcp_token = create_api_token(db_session, name="mcp bot", scopes=[MCP_READ_SCOPE])

    tls_response = client.get(
        "/api/v1/public/exports",
        headers={"X-API-Key": tls_token.secret},
    )
    mcp_response = client.get(
        "/api/v1/public/exports",
        headers={"X-API-Key": mcp_token.secret},
    )

    assert tls_response.status_code == 200
    tls_body = tls_response.json()
    assert tls_body["workspace"]["domain_count"] == 1
    assert tls_body["domains"] == []
    assert mcp_response.status_code == 200
    mcp_body = mcp_response.json()
    assert mcp_body["workspace"]["domain_count"] == 1
    assert mcp_body["domains"][0]["exports"]["domain_reports"]["available"] is False
    assert mcp_body["domains"][0]["exports"]["health_evidence_export"]["available"] is False


def test_require_api_token_any_scope_rejects_bare_string_scope():
    with pytest.raises(TypeError, match="not a string"):
        require_api_token_any_scope(READ_REPORTS_SCOPE)


def test_public_source_intelligence_endpoints_use_report_scope(client: TestClient, db_session):
    """Stable public API exposes source evidence without admin-session auth."""
    _persist_report(db_session)
    created = create_api_token(db_session, name="source bot", scopes=[READ_REPORTS_SCOPE])

    with patch(
        "app.api.api_v1.endpoints.domains._safe_ptr_lookup",
        new=AsyncMock(return_value="mail.example.net"),
    ):
        sources = client.get(
            f"/api/v1/public/domains/{DOMAIN}/sources?days=30",
            headers={"X-API-Key": created.secret},
        )
    intelligence = client.get(
        f"/api/v1/public/domains/{DOMAIN}/source-intelligence?days=30",
        headers={"X-API-Key": created.secret},
    )

    assert sources.status_code == 200
    source_row = sources.json()["sources"][0]
    assert source_row["ip"] == "1.2.3.4"
    assert source_row["hostname"] == "mail.example.net"
    assert "geo" in source_row
    assert "anomalies" in source_row
    assert intelligence.status_code == 200
    assert intelligence.json()["domain"] == DOMAIN
    assert "regions" in intelligence.json()
    assert "summary" in intelligence.json()


def test_public_api_rejects_token_without_required_scope(client: TestClient, db_session):
    """Tokens are least-privilege: reports scope cannot read posture payloads."""
    _seed_report_store()
    created = create_api_token(db_session, name="report bot", scopes=[READ_REPORTS_SCOPE])

    response = client.get(
        f"/api/v1/public/domains/{DOMAIN}/posture",
        headers={"X-API-Key": created.secret},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == f"API token requires scope: {READ_POSTURE_SCOPE}"


def test_public_action_proposals_use_posture_scope(client: TestClient, db_session):
    """Public action proposals are read-only and scoped to posture tokens."""
    _persist_failing_report(db_session)
    posture_token = create_api_token(
        db_session,
        name="posture bot",
        scopes=[READ_POSTURE_SCOPE],
    )
    reports_token = create_api_token(
        db_session,
        name="reports bot",
        scopes=[READ_REPORTS_SCOPE],
    )

    denied = client.get(
        f"/api/v1/public/domains/{DOMAIN}/action-proposals",
        headers={"X-API-Key": reports_token.secret},
    )
    response = client.get(
        f"/api/v1/public/domains/{DOMAIN}/action-proposals",
        headers={"X-API-Key": posture_token.secret},
    )

    assert denied.status_code == 403
    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == DOMAIN
    assert body["proposals"]
    assert body["proposals"][0]["mutates_state"] is False
    assert body["proposals"][0]["requires_human_confirmation"] is True


def test_public_action_proposals_are_workspace_scoped(client: TestClient, db_session):
    """Public action proposals cannot cross the API token workspace boundary."""
    get_or_create_default_workspace(db_session)
    other_workspace = Workspace(
        slug="public-actions-other",
        name="Public Actions Other",
        active=True,
    )
    db_session.add(other_workspace)
    db_session.commit()

    other_domain = "other-workspace.example"
    other_report = {
        **FAILING_REPORT,
        "domain": other_domain,
        "report_id": "public-api-other-workspace-001",
    }
    _persist_failing_report(db_session, other_report, workspace_id=other_workspace.id)
    default_token = create_api_token(
        db_session,
        name="default posture bot",
        scopes=[READ_POSTURE_SCOPE],
    )
    other_token = create_api_token(
        db_session,
        name="other posture bot",
        scopes=[READ_POSTURE_SCOPE],
        workspace_id=other_workspace.id,
    )

    denied = client.get(
        f"/api/v1/public/domains/{other_domain}/action-proposals",
        headers={"X-API-Key": default_token.secret},
    )
    allowed = client.get(
        f"/api/v1/public/domains/{other_domain}/action-proposals",
        headers={"X-API-Key": other_token.secret},
    )

    assert denied.status_code == 404
    assert allowed.status_code == 200
    assert allowed.json()["domain"] == other_domain


def test_public_alert_history_is_posture_scoped_and_sanitized(
    client: TestClient,
    db_session,
):
    """Public alert history is workspace-scoped and excludes raw alert payloads."""
    _persist_report(db_session)
    workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(slug="public-alerts-other", name="Public Alerts Other")
    db_session.add(other_workspace)
    db_session.flush()
    db_session.add(
        Domain(
            workspace_id=other_workspace.id,
            name="other-alerts.example",
            active=True,
            verified=True,
        )
    )
    db_session.add_all(
        [
            AlertHistory(
                fingerprint="public-alert-active",
                rule="new_sender_source",
                severity="warning",
                domain=DOMAIN,
                title="New sender",
                detail="192.0.2.1 first appeared.",
                payload=(
                    '{"source_ip":"192.0.2.1","message_count":12,' '"secret":"do-not-return"}'
                ),
                observed_count=2,
                is_active=True,
            ),
            AlertHistory(
                fingerprint="public-alert-resolved",
                rule="missing_reports",
                severity="warning",
                domain=DOMAIN,
                title="Resolved reports",
                detail="Already fixed.",
                observed_count=1,
                is_active=False,
            ),
            AlertHistory(
                fingerprint="public-alert-other-workspace",
                rule="missing_reports",
                severity="error",
                domain="other-alerts.example",
                title="Other alert",
                detail="Should not leak.",
                observed_count=1,
                is_active=True,
            ),
        ]
    )
    db_session.commit()
    posture_token = create_api_token(
        db_session,
        name="alert posture bot",
        scopes=[READ_POSTURE_SCOPE],
        workspace_id=workspace.id,
    )
    reports_token = create_api_token(
        db_session,
        name="alert reports bot",
        scopes=[READ_REPORTS_SCOPE],
        workspace_id=workspace.id,
    )

    denied = client.get(
        "/api/v1/public/alerts?active=true",
        headers={"X-API-Key": reports_token.secret},
    )
    response = client.get(
        "/api/v1/public/alerts?active=true&limit=10",
        headers={"X-API-Key": posture_token.secret},
    )

    assert denied.status_code == 403
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["active"] == 1
    assert body["summary"]["by_rule"] == {"new_sender_source": 1}
    assert [alert["domain"] for alert in body["alerts"]] == [DOMAIN]
    assert body["alerts"][0]["evidence"] == {
        "message_count": 12,
        "source_ip": "192.0.2.1",
    }
    assert "payload" not in body["alerts"][0]
    assert "do-not-return" not in response.text


def test_public_health_evidence_export_uses_posture_scope_without_capture(
    client: TestClient,
    db_session,
):
    """Stable public health evidence export is posture-scoped and read-only."""
    workspace = get_or_create_default_workspace(db_session)
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name=DOMAIN,
        health={
            "score": 72,
            "grade": "C",
            "status": "attention",
            "factors": {"dns_posture": 80, "policy_strength": 55, "report_confidence": 78},
            "actions": [{"title": "Move out of monitoring mode", "severity": "medium"}],
        },
        policy="none",
        compliance_rate=94,
        total_emails=500,
        failed_emails=30,
        report_count=5,
        snapshot_date=date(2026, 6, 3),
    )
    _persist_report(db_session)
    posture_token = create_api_token(
        db_session,
        name="health evidence bot",
        scopes=[READ_POSTURE_SCOPE],
    )
    reports_token = create_api_token(
        db_session,
        name="reports bot",
        scopes=[READ_REPORTS_SCOPE],
    )

    denied = client.get(
        f"/api/v1/public/domains/{DOMAIN}/posture/evidence/export",
        headers={"X-API-Key": reports_token.secret},
    )
    response = client.get(
        f"/api/v1/public/domains/{DOMAIN}/posture/evidence/export?format=json",
        headers={"X-API-Key": posture_token.secret},
    )

    assert denied.status_code == 403
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "domain"
    assert body["rows"][0]["domain"] == DOMAIN
    assert body["rows"][0]["score"] == 72
    assert body["rows"][0]["top_actions"] == "medium:Move out of monitoring mode"
    assert "message" not in response.text.lower()


def test_public_dns_guidance_uses_posture_scope_and_read_only_plans(
    client: TestClient,
    db_session,
):
    """Stable public DNS guidance is posture-scoped and never exposes write affordances."""
    _persist_report(db_session)
    posture_token = create_api_token(
        db_session,
        name="dns posture bot",
        scopes=[READ_POSTURE_SCOPE],
    )
    reports_token = create_api_token(
        db_session,
        name="reports bot",
        scopes=[READ_REPORTS_SCOPE],
    )
    lint_payload = domains_endpoint.DNSGuidanceResponse(
        domain=DOMAIN,
        status="attention",
        findings=[],
        target_records=[],
        change_plans=[],
    )
    change_payload = domains_endpoint.DNSChangePlanResponse(
        domain=DOMAIN,
        status="attention",
        read_only=False,
        provider_write_available=True,
        apply_endpoint=f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
        plans=[
            domains_endpoint.DNSChangePlanItemResponse(
                plan_id="dns-plan-1",
                finding_code="dmarc_missing",
                severity="error",
                operation="create",
                record_type="TXT",
                name=f"_dmarc.{DOMAIN}",
                proposed_value="v=DMARC1; p=none",
                current_values=[],
                rationale="Publish DMARC policy discovery.",
                risk="Low; validates syntax before enforcement.",
                rollback="Remove the new TXT record.",
                expected_health_impact="Expected to remove a DNS-health finding.",
                manual_steps=["Create the TXT record."],
                requires_approval=True,
                applies_automatically=True,
                provider_write_available=True,
            )
        ],
    )

    with (
        patch(
            "app.api.api_v1.endpoints.public.domains.get_domain_dns_lint",
            new=AsyncMock(return_value=lint_payload),
        ) as lint,
        patch(
            "app.api.api_v1.endpoints.public.domains.get_domain_dns_change_plan",
            new=AsyncMock(return_value=change_payload),
        ) as change_plan,
    ):
        denied = client.get(
            f"/api/v1/public/domains/{DOMAIN}/dns/lint",
            headers={"X-API-Key": reports_token.secret},
        )
        denied_plan = client.get(
            f"/api/v1/public/domains/{DOMAIN}/dns/change-plan",
            headers={"X-API-Key": reports_token.secret},
        )
        lint_response = client.get(
            f"/api/v1/public/domains/{DOMAIN}/dns/lint?refresh=true",
            headers={"X-API-Key": posture_token.secret},
        )
        plan_response = client.get(
            f"/api/v1/public/domains/{DOMAIN}/dns/change-plan",
            headers={"X-API-Key": posture_token.secret},
        )

    assert denied.status_code == 403
    assert denied_plan.status_code == 403
    assert lint_response.status_code == 200
    assert lint_response.json()["domain"] == DOMAIN
    assert plan_response.status_code == 200
    plan_body = plan_response.json()
    assert plan_body["read_only"] is True
    assert plan_body["provider_write_available"] is False
    assert plan_body["apply_endpoint"] is None
    assert plan_body["plans"][0]["provider_write_available"] is False
    assert plan_body["plans"][0]["applies_automatically"] is False
    lint.assert_awaited_once()
    change_plan.assert_awaited_once()


def test_admin_can_create_list_and_revoke_api_tokens(authed_client: TestClient, db_session):
    """Admin token management never returns stored hashes and revocation disables access."""
    _seed_report_store()
    created = authed_client.post(
        "/api/v1/api-tokens",
        json={"name": "automation", "scopes": [READ_REPORTS_SCOPE]},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["token"].startswith("dmarq_")
    assert body["metadata"]["scopes"] == [READ_REPORTS_SCOPE]
    assert body["metadata"]["workspace_id"] is not None
    assert "key_hash" not in body["metadata"]

    listed = authed_client.get("/api/v1/api-tokens")
    assert listed.status_code == 200
    assert listed.json()["tokens"][0]["name"] == "automation"
    assert "key_hash" not in listed.text

    allowed = authed_client.get(
        f"/api/v1/public/domains/{DOMAIN}/reports",
        headers={"X-API-Key": body["token"]},
    )
    assert allowed.status_code == 200

    revoked = authed_client.delete(f"/api/v1/api-tokens/{body['metadata']['id']}")
    assert revoked.status_code == 200

    denied = authed_client.get(
        f"/api/v1/public/domains/{DOMAIN}/reports",
        headers={"X-API-Key": body["token"]},
    )
    assert denied.status_code == 401


def test_admin_api_token_creation_respects_plan_entitlement(
    authed_client: TestClient,
    db_session,
):
    """Plans with API access disabled can still list tokens but cannot create new ones."""
    workspace = get_or_create_default_workspace(db_session)
    organization = Organization(slug="api-disabled", name="API Disabled", active=True)
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

    listed = authed_client.get("/api/v1/api-tokens")
    assert listed.status_code == 200

    created = authed_client.post(
        "/api/v1/api-tokens",
        json={"name": "automation", "scopes": [READ_REPORTS_SCOPE]},
    )

    assert created.status_code == 402
    assert created.json()["detail"]["code"] == "feature_not_included"
    assert created.json()["detail"]["feature"] == "api_tokens"


def test_admin_api_token_management_is_workspace_scoped(
    authed_client: TestClient,
    db_session,
):
    """Token list and revoke operations are limited to the authorized workspace."""
    default_workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(
        slug="other",
        name="Other Workspace",
        active=True,
    )
    db_session.add(other_workspace)
    db_session.flush()
    other_header = {"X-DMARQ-Workspace-ID": str(other_workspace.id)}
    other_token = create_api_token(
        db_session,
        name="other workspace token",
        scopes=[READ_REPORTS_SCOPE],
        workspace_id=other_workspace.id,
    )

    created = authed_client.post(
        "/api/v1/api-tokens",
        json={"name": "default workspace token", "scopes": [READ_REPORTS_SCOPE]},
    )
    assert created.status_code == 201
    assert created.json()["metadata"]["workspace_id"] == default_workspace.id

    listed = authed_client.get("/api/v1/api-tokens")
    assert listed.status_code == 200
    names = {row["name"] for row in listed.json()["tokens"]}
    assert names == {"default workspace token"}

    denied_revoke = authed_client.delete(f"/api/v1/api-tokens/{other_token.token.id}")
    assert denied_revoke.status_code == 404
    db_session.refresh(other_token.token)
    assert other_token.token.active is True

    other_listed = authed_client.get("/api/v1/api-tokens", headers=other_header)
    assert other_listed.status_code == 200
    assert [row["name"] for row in other_listed.json()["tokens"]] == ["other workspace token"]

    other_created = authed_client.post(
        "/api/v1/api-tokens",
        headers=other_header,
        json={"name": "selected workspace token", "scopes": [READ_REPORTS_SCOPE]},
    )
    assert other_created.status_code == 201
    assert other_created.json()["metadata"]["workspace_id"] == other_workspace.id

    selected_revoke = authed_client.delete(
        f"/api/v1/api-tokens/{other_token.token.id}",
        headers=other_header,
    )
    assert selected_revoke.status_code == 200
    db_session.refresh(other_token.token)
    assert other_token.token.active is False


def test_api_token_workspace_role_is_limited_to_matching_workspace(db_session):
    """Workspace-aware permission checks only trust tokens for their own tenant."""
    default_workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(
        slug="token-role-other",
        name="Token Role Other",
        active=True,
    )
    db_session.add(other_workspace)
    db_session.flush()

    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "api_token", "workspace_id": str(default_workspace.id)},
            default_workspace,
        )
        == ROLE_ANALYST
    )
    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "api_token", "workspace_id": other_workspace.id},
            default_workspace,
        )
        == ""
    )
    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "api_token", "workspace_id": "not-an-int"},
            default_workspace,
        )
        == ""
    )


def test_legacy_api_key_workspace_role_remains_owner(db_session):
    """Legacy admin API-key contexts retain owner access until fully migrated."""
    workspace = get_or_create_default_workspace(db_session)

    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "api_key"},
            workspace,
        )
        == ROLE_WORKSPACE_OWNER
    )
