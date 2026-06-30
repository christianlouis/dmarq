from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.models.api_token import APIToken
from app.models.organization import BillingAccount, Organization
from app.models.workspace import Workspace
from app.services.api_tokens import READ_POSTURE_SCOPE, READ_REPORTS_SCOPE, create_api_token
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
