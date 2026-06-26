from fastapi.testclient import TestClient

from app.models.api_token import APIToken
from app.models.workspace import Workspace
from app.services.api_tokens import READ_POSTURE_SCOPE, READ_REPORTS_SCOPE, create_api_token
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


def _seed_report_store():
    ReportStore.get_instance().add_report(MINIMAL_REPORT)


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
    _seed_report_store()
    created = create_api_token(db_session, name="summary bot", scopes=[READ_REPORTS_SCOPE])

    response = client.get(
        "/api/v1/public/domains",
        headers={"X-API-Key": created.secret},
    )

    assert response.status_code == 200
    assert response.json()["domains"][0]["domain_name"] == DOMAIN


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
