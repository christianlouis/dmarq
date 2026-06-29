from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.organization import Entitlement, Organization
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.services import ai_assistance
from app.services.api_tokens import MCP_READ_SCOPE, create_api_token
from app.services.bimi import BIMIResult
from app.services.dns_resolver import DomainDNSResult
from app.services.mta_sts import MTAStsResult
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


def test_ai_remediation_plan_requires_explicit_opt_in(authed_client: TestClient):
    _seed_report_store()

    response = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/remediation-plan")

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


def test_ai_remediation_plan_uses_template_and_cache(
    authed_client: TestClient,
    db_session: Session,
):
    _seed_report_store()
    _set_setting(db_session, "ai.enabled", "true", "ai")
    _set_setting(db_session, "ai.remediation_cache_seconds", "86400", "ai")
    provider = AsyncMock()
    provider.check_domain = AsyncMock(
        return_value=DomainDNSResult(
            dmarc=True,
            dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
            spf=True,
            spf_record="v=spf1 -all",
            dkim=False,
            selectors_checked=["google"],
        )
    )
    provider.lookup_txt = AsyncMock(side_effect=LookupError("not found"))
    provider.lookup_cname = AsyncMock(return_value=None)

    with (
        patch("app.services.ai_assistance.get_default_provider", return_value=provider),
        patch(
            "app.services.ai_assistance.check_mta_sts_cached",
            new=AsyncMock(return_value=(MTAStsResult(status="pass"), False, None)),
        ),
        patch(
            "app.services.ai_assistance.check_bimi_cached",
            new=AsyncMock(return_value=(BIMIResult(status="pass"), False, None)),
        ),
    ):
        first = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/remediation-plan")
        second = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/remediation-plan")

    assert first.status_code == 200
    assert second.status_code == 200
    first_plan = first.json()["plan"]
    second_plan = second.json()["plan"]
    assert first_plan["provider"] == "template"
    assert first_plan["actions"]
    assert first_plan["actions"][0]["steps"]
    assert first_plan["safe_context"]["constraints"]["automatic_dns_changes"] is False
    assert second_plan["cached"] is True
    focused = first_plan["actions"][0]["finding_code"]

    with (
        patch("app.services.ai_assistance.get_default_provider", return_value=provider),
        patch(
            "app.services.ai_assistance.check_mta_sts_cached",
            new=AsyncMock(return_value=(MTAStsResult(status="pass"), False, None)),
        ),
        patch(
            "app.services.ai_assistance.check_bimi_cached",
            new=AsyncMock(return_value=(BIMIResult(status="pass"), False, None)),
        ),
    ):
        filtered = authed_client.get(
            f"/api/v1/ai/domains/{DOMAIN}/remediation-plan?finding_code={focused}"
        )

    assert filtered.status_code == 200
    filtered_actions = filtered.json()["plan"]["actions"]
    assert filtered_actions
    assert {action["finding_code"] for action in filtered_actions} == {focused}


def test_ai_remediation_cache_is_bounded():
    ai_assistance._REMEDIATION_CACHE.clear()
    for index in range(ai_assistance.REMEDIATION_CACHE_MAX_ENTRIES + 5):
        ai_assistance._cache_set(
            f"key-{index}",
            {"domain": f"example-{index}.test", "actions": []},
        )

    assert len(ai_assistance._REMEDIATION_CACHE) == ai_assistance.REMEDIATION_CACHE_MAX_ENTRIES
    assert "key-0" not in ai_assistance._REMEDIATION_CACHE
    ai_assistance._REMEDIATION_CACHE.clear()


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


def test_mcp_requires_advanced_integrations_entitlement(client: TestClient, db_session: Session):
    organization = Organization(slug="mcp-disabled", name="MCP Disabled", active=True)
    workspace = Workspace(
        slug="mcp-disabled-main",
        name="MCP Disabled Main",
        organization=organization,
        active=True,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="advanced_integrations",
                value="false",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    token = create_api_token(
        db_session,
        name="mcp disabled client",
        scopes=[MCP_READ_SCOPE],
        workspace_id=workspace.id,
    )
    _set_setting(db_session, "mcp.enabled", "true", "mcp")

    response = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )

    assert response.status_code == 402
    detail = response.json()["detail"]
    assert detail["code"] == "feature_not_included"
    assert detail["feature"] == "advanced_integrations"
    assert detail["can_export"] is True
