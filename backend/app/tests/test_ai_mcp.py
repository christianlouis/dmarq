from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.setting import Setting
from app.services.api_tokens import MCP_READ_SCOPE, create_api_token
from app.services.report_store import ReportStore

DOMAIN = "example.com"

REPORT = {
    "domain": DOMAIN,
    "report_id": "ai-001",
    "org_name": "Receiver",
    "policy": {"p": "none", "pct": "100"},
    "records": [
        {
            "source_ip": "192.0.2.10",
            "count": 8,
            "disposition": "none",
            "dkim_result": "fail",
            "spf_result": "fail",
        },
        {
            "source_ip": "192.0.2.11",
            "count": 2,
            "disposition": "none",
            "dkim_result": "pass",
            "spf_result": "pass",
        },
    ],
    "summary": {"total_count": 10, "passed_count": 2, "failed_count": 8},
}


def _seed_report_store() -> None:
    ReportStore.get_instance().add_report(REPORT)


def _set_setting(db: Session, key: str, value: str, category: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None:
        row = Setting(key=key, value=value, category=category, value_type="string")
        db.add(row)
    else:
        row.value = value
    db.commit()


def test_ai_settings_are_seeded(authed_client: TestClient):
    response = authed_client.get("/api/v1/settings")
    assert response.status_code == 200
    keys = {row["key"] for row in response.json()}
    assert "ai.enabled" in keys
    assert "ai.provider" in keys
    assert "ai.action_tools_enabled" in keys
    assert "mcp.enabled" in keys


def test_ai_summary_requires_explicit_opt_in(authed_client: TestClient):
    _seed_report_store()
    response = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/summary")
    assert response.status_code == 403
    assert "AI assistance is disabled" in response.json()["detail"]


def test_ai_summary_is_evidence_first_and_redacted(
    authed_client: TestClient,
    db_session: Session,
):
    _seed_report_store()
    _set_setting(db_session, "ai.enabled", "true", "ai")
    _set_setting(db_session, "ai.redaction_mode", "strict", "ai")

    response = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/summary")

    assert response.status_code == 200
    body = response.json()["summary"]
    assert body["summary"]["domain"] == DOMAIN
    assert body["summary"]["failed_messages"] == 8
    assert body["recommendations"]
    assert body["recommendations"][0]["evidence"]
    assert "**redacted**" not in body["safe_context"]["domain"]


def test_action_proposals_are_reviewable_and_not_mutating(
    authed_client: TestClient,
    db_session: Session,
):
    _seed_report_store()
    _set_setting(db_session, "ai.enabled", "true", "ai")

    response = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/action-proposals")

    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == DOMAIN
    assert body["proposals"]
    proposal = body["proposals"][0]
    assert proposal["requires_human_confirmation"] is True
    assert proposal["mutates_state"] is False
    assert proposal["confirmation_text"] == proposal["proposal_id"]


def test_action_confirmation_requires_action_tools_enabled(
    authed_client: TestClient,
    db_session: Session,
):
    _seed_report_store()
    _set_setting(db_session, "ai.enabled", "true", "ai")
    proposal = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/action-proposals").json()[
        "proposals"
    ][0]

    denied = authed_client.post(
        f"/api/v1/ai/domains/{DOMAIN}/action-proposals/confirm",
        json={
            "proposal_id": proposal["proposal_id"],
            "confirmation_text": proposal["proposal_id"],
        },
    )
    assert denied.status_code == 403

    _set_setting(db_session, "ai.action_tools_enabled", "true", "ai")
    confirmed = authed_client.post(
        f"/api/v1/ai/domains/{DOMAIN}/action-proposals/confirm",
        json={
            "proposal_id": proposal["proposal_id"],
            "confirmation_text": proposal["proposal_id"],
            "note": "Reviewed by operator",
        },
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "confirmed"
    assert confirmed.json()["applied"] is False


def test_mcp_requires_enabled_scoped_token(client: TestClient, db_session: Session):
    _seed_report_store()
    token = create_api_token(db_session, name="mcp client", scopes=[MCP_READ_SCOPE])

    disabled = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert disabled.status_code == 403

    _set_setting(db_session, "mcp.enabled", "true", "mcp")
    listed = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert listed.status_code == 200
    assert listed.json()["result"]["tools"][0]["readOnlyHint"] is True

    called = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "domain_summary", "arguments": {"domain": DOMAIN}},
        },
    )
    assert called.status_code == 200
    result = called.json()["result"]["content"][0]["json"]
    assert result["summary"]["domain"] == DOMAIN
