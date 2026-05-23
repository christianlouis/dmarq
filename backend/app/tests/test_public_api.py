from fastapi.testclient import TestClient

from app.models.api_token import APIToken
from app.services.api_tokens import READ_POSTURE_SCOPE, READ_REPORTS_SCOPE, create_api_token
from app.services.report_store import ReportStore

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
