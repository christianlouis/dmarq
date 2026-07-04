import asyncio
import builtins
import sys
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints import ai as ai_endpoint
from app.api.api_v1.endpoints import mcp as mcp_endpoint
from app.api.api_v1.endpoints import settings as settings_endpoint
from app.core.credential_encryption import decrypt_secret, is_encrypted_secret
from app.models.alert import AlertHistory
from app.models.domain import Domain
from app.models.organization import Entitlement, Organization
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.services import ai_assistance
from app.services.ai_assistance import AssistanceConfig
from app.services.api_tokens import MCP_READ_SCOPE, create_api_token
from app.services.bimi import BIMIResult
from app.services.dns_resolver import DomainDNSResult
from app.services.mta_sts import MTAStsResult
from app.services.report_persistence import save_parsed_report
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


def _persist_report(db_session: Session) -> None:
    save_parsed_report(db_session, REPORT)
    db_session.commit()


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
    assert "ai.api_key" in keys
    assert "ai.action_tools_enabled" in keys
    assert "mcp.enabled" in keys


def test_ai_provider_profiles_are_exposed_to_settings(authed_client: TestClient):
    response = authed_client.get("/api/v1/settings/ai/provider-profiles")

    assert response.status_code == 200
    profiles = {item["id"]: item for item in response.json()}
    assert {"template", "openai", "litellm", "openai_compatible"}.issubset(profiles)
    assert profiles["openai"]["requires_api_key"] is True
    assert profiles["litellm"]["requires_base_url"] is True


def test_ai_setting_helpers_use_safe_defaults(db_session: Session):
    assert settings_endpoint._setting_plain_or_default(db_session, "missing.setting") == ""
    assert settings_endpoint._normalize_ai_base_url("openai", "", {}) == "https://api.openai.com/v1"


def test_ai_connection_template_profile_needs_no_secret(authed_client: TestClient):
    response = authed_client.post(
        "/api/v1/settings/ai/test",
        json={"provider": "template"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["provider"] == "template"


def test_ai_connection_requires_key_for_remote_provider(authed_client: TestClient):
    response = authed_client.post(
        "/api/v1/settings/ai/test",
        json={"provider": "openai", "base_url": "https://api.openai.com/v1"},
    )

    assert response.status_code == 400
    assert "API key" in response.json()["detail"]


def test_ai_connection_uses_openai_default_base_url(authed_client: TestClient):
    model_fetch = AsyncMock(return_value=["gpt-4.1-mini"])

    with patch.object(settings_endpoint, "_fetch_openai_compatible_models", model_fetch):
        response = authed_client.post(
            "/api/v1/settings/ai/test",
            json={"provider": "openai", "api_key": "sk-test"},
        )

    assert response.status_code == 200
    assert response.json()["selected_model"] == "gpt-4.1-mini"
    model_fetch.assert_awaited_once_with(
        base_url="https://api.openai.com/v1",
        api_key="sk-test",
    )


def test_ai_connection_requires_base_url_for_litellm(authed_client: TestClient):
    response = authed_client.post(
        "/api/v1/settings/ai/test",
        json={"provider": "litellm", "api_key": "sk-test"},
    )

    assert response.status_code == 400
    assert "base URL" in response.json()["detail"]


def test_ai_connection_reports_provider_http_status(authed_client: TestClient):
    request = httpx.Request("GET", "https://api.openai.com/v1/models")
    response = httpx.Response(401, request=request)
    model_fetch = AsyncMock(
        side_effect=httpx.HTTPStatusError(
            "unauthorized",
            request=request,
            response=response,
        )
    )

    with patch.object(settings_endpoint, "_fetch_openai_compatible_models", model_fetch):
        result = authed_client.post(
            "/api/v1/settings/ai/test",
            json={"provider": "openai", "api_key": "sk-test"},
        )

    assert result.status_code == 400
    assert "HTTP 401" in result.json()["detail"]


def test_ai_connection_reports_network_failure(authed_client: TestClient):
    request = httpx.Request("GET", "https://api.openai.com/v1/models")
    model_fetch = AsyncMock(side_effect=httpx.RequestError("timeout", request=request))

    with patch.object(settings_endpoint, "_fetch_openai_compatible_models", model_fetch):
        response = authed_client.post(
            "/api/v1/settings/ai/test",
            json={"provider": "openai", "api_key": "sk-test"},
        )

    assert response.status_code == 400
    assert "connection test failed" in response.json()["detail"]


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:4000/v1",
        "http://localhost:4000/v1",
        "http://user:pass@example.com/v1",
    ],
)
def test_ai_connection_rejects_unsafe_model_discovery_urls(
    authed_client: TestClient,
    base_url: str,
):
    response = authed_client.post(
        "/api/v1/settings/ai/test",
        json={"provider": "litellm", "base_url": base_url, "api_key": "sk-test"},
    )

    assert response.status_code == 400
    assert "AI base URL" in response.json()["detail"]


def test_ai_connection_rejects_invalid_model_discovery_url():
    with pytest.raises(Exception) as exc_info:
        settings_endpoint._validated_ai_base_url("not-a-url")

    assert "absolute HTTP(S) URL" in str(exc_info.value)


def test_ai_connection_rejects_unresolvable_model_discovery_url(monkeypatch):
    def fail_lookup(*_args, **_kwargs):
        raise settings_endpoint.socket.gaierror("not found")

    monkeypatch.setattr(settings_endpoint.socket, "getaddrinfo", fail_lookup)

    with pytest.raises(Exception) as exc_info:
        settings_endpoint._validated_ai_base_url("https://missing-ai.example/v1")

    assert "could not be resolved" in str(exc_info.value)


@pytest.mark.asyncio
async def test_fetch_openai_compatible_models_sorts_unique_models(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": [
                    {"id": "z-model"},
                    {"id": ""},
                    {"id": "a-model"},
                    {"id": "z-model"},
                ]
            }

    class FakeAsyncClient:
        def __init__(self, *, base_url: str, timeout: int):
            assert base_url == "https://ai.example/v1"
            assert timeout == 10

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, path: str, *, headers):
            assert path == "/models"
            assert headers == {"Authorization": "Bearer sk-test"}
            return FakeResponse()

    monkeypatch.setattr(
        settings_endpoint.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("8.8.8.8", 443))],
    )
    monkeypatch.setattr(settings_endpoint.httpx, "AsyncClient", FakeAsyncClient)

    models = await settings_endpoint._fetch_openai_compatible_models(
        base_url="https://ai.example/v1/",
        api_key="sk-test",
    )

    assert models == ["a-model", "z-model"]


def test_ai_connection_uses_saved_redacted_secret_and_discovers_models(
    authed_client: TestClient,
    db_session: Session,
):
    save_response = authed_client.post(
        "/api/v1/settings/bulk",
        json={
            "settings": {
                "ai.provider": "openai",
                "ai.remote_base_url": "https://api.openai.com/v1",
                "ai.api_key": "sk-test",
            }
        },
    )
    assert save_response.status_code == 200
    row = db_session.query(Setting).filter(Setting.key == "ai.api_key").one()
    assert is_encrypted_secret(row.value)
    assert decrypt_secret(row.value) == "sk-test"

    model_fetch = AsyncMock(return_value=["gpt-4.1-mini", "gpt-4.1"])
    with patch.object(settings_endpoint, "_fetch_openai_compatible_models", model_fetch):
        response = authed_client.post(
            "/api/v1/settings/ai/test",
            json={
                "provider": "openai",
                "base_url": "https://api.openai.com/v1",
                "api_key": "**redacted**",
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["models"] == ["gpt-4.1-mini", "gpt-4.1"]
    assert data["selected_model"] == "gpt-4.1-mini"
    model_fetch.assert_awaited_once_with(
        base_url="https://api.openai.com/v1",
        api_key="sk-test",
    )


def test_ai_summary_requires_explicit_opt_in(authed_client: TestClient):
    _seed_report_store()
    response = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/summary")
    assert response.status_code == 403
    assert "AI assistance is disabled" in response.json()["detail"]


def test_ai_context_requires_explicit_opt_in(authed_client: TestClient):
    _seed_report_store()

    response = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/context")

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
    _persist_report(db_session)
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


def test_ai_summary_returns_not_found_for_unknown_domain(
    authed_client: TestClient,
    db_session: Session,
):
    _set_setting(db_session, "ai.enabled", "true", "ai")

    response = authed_client.get("/api/v1/ai/domains/missing.example/summary")

    assert response.status_code == 404
    assert response.json()["detail"] == "Domain not found"


def test_ai_evidence_summary_handles_no_observed_volume(monkeypatch, db_session: Session):
    context = {
        "domain": DOMAIN,
        "summary": {
            "total_messages": 0,
            "failed_messages": 0,
            "compliance_rate": 0.0,
        },
        "evidence": [
            {"label": "Domain", "value": DOMAIN, "href": f"/domains/{DOMAIN}"},
        ],
        "top_sources": [],
        "config": {"provider": "template"},
    }

    monkeypatch.setattr(ai_assistance, "build_safe_context", lambda *_args, **_kwargs: context)

    summary = ai_assistance.build_evidence_summary(db_session, DOMAIN)

    assert summary["summary"]["headline"] == "No DMARC aggregate volume has been observed yet."
    assert summary["recommendations"][0]["title"] == "Confirm report ingestion"


def test_ai_headline_describes_healthy_and_mostly_healthy_posture():
    healthy = {"summary": {"total_messages": 100, "failed_messages": 0, "compliance_rate": 100.0}}
    mostly_healthy = {
        "summary": {"total_messages": 100, "failed_messages": 5, "compliance_rate": 95.0}
    }

    assert (
        ai_assistance._headline_for_context(healthy) == "Observed DMARC traffic is passing cleanly."
    )
    assert (
        ai_assistance._headline_for_context(mostly_healthy)
        == "DMARC posture is mostly healthy, with a small failure set to review."
    )


def test_ai_domain_selectors_from_db_returns_empty_for_unknown_domain(db_session: Session):
    assert ai_assistance._domain_selectors_from_db(db_session, "missing.example") == []


def test_ai_remediation_plan_uses_template_and_cache(
    authed_client: TestClient,
    db_session: Session,
):
    _persist_report(db_session)
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


def test_remediation_cache_prunes_expired_entries_and_oldest_entries():
    ai_assistance._REMEDIATION_CACHE.clear()
    ai_assistance._REMEDIATION_CACHE["expired"] = (time.time() - 120, {"stale": True})
    ai_assistance._cache_set("fresh", {"stale": False})

    assert ai_assistance._cache_get("expired", ttl_seconds=1) is None
    assert ai_assistance._cache_get("fresh", ttl_seconds=1)["stale"] is False

    ai_assistance._REMEDIATION_CACHE.clear()
    for index in range(ai_assistance.REMEDIATION_CACHE_MAX_ENTRIES + 3):
        ai_assistance._cache_set(f"key-{index}", {"index": index})

    assert len(ai_assistance._REMEDIATION_CACHE) <= ai_assistance.REMEDIATION_CACHE_MAX_ENTRIES
    assert "key-0" not in ai_assistance._REMEDIATION_CACHE

    ai_assistance._REMEDIATION_CACHE.clear()
    for index in range(ai_assistance.REMEDIATION_CACHE_MAX_ENTRIES + 2):
        ai_assistance._REMEDIATION_CACHE[f"raw-{index}"] = (index, {"index": index})

    ai_assistance._cache_prune(ttl_seconds=0)

    assert len(ai_assistance._REMEDIATION_CACHE) == ai_assistance.REMEDIATION_CACHE_MAX_ENTRIES
    assert "raw-0" not in ai_assistance._REMEDIATION_CACHE

    ai_assistance._REMEDIATION_CACHE["stale"] = (time.time() - 120, {"stale": True})
    assert ai_assistance._cache_get("stale", ttl_seconds=0) is None
    ai_assistance._REMEDIATION_CACHE.clear()


def test_ai_remediation_plan_returns_404_for_unknown_domain(
    authed_client: TestClient,
    db_session: Session,
):
    _set_setting(db_session, "ai.enabled", "true", "ai")

    response = authed_client.get("/api/v1/ai/domains/unknown.example/remediation-plan")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_litellm_remediation_plan_returns_valid_actions(monkeypatch):
    class FakeLiteLLM:
        drop_params = False

        @staticmethod
        async def acompletion(**_kwargs):
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"summary": "Review DNS posture.", "actions": '
                                '[{"finding_code": "dkim_selector_missing", '
                                '"title": "Publish selector", "priority": "high", '
                                '"summary": "Publish the missing selector.", '
                                '"steps": ["Create the TXT record."], '
                                '"evidence": [], "target_record": null, '
                                '"requires_human_change": true}]}'
                            )
                        }
                    }
                ]
            }

    monkeypatch.setitem(sys.modules, "litellm", FakeLiteLLM)
    config = AssistanceConfig(
        ai_enabled=True,
        provider="litellm",
        model="test-model",
        remote_base_url="https://litellm.example.test",
        redaction_mode="strict",
        action_tools_enabled=False,
        mcp_enabled=False,
        remediation_cache_seconds=60,
    )

    plan = await ai_assistance._litellm_remediation_plan(
        config,
        {
            "domain": DOMAIN,
            "dns_guidance": {"findings": []},
            "constraints": {"automatic_dns_changes": False},
        },
    )

    assert plan is not None
    assert plan["provider"] == "litellm"
    assert plan["model"] == "test-model"
    assert plan["actions"][0]["finding_code"] == "dkim_selector_missing"
    assert FakeLiteLLM.drop_params is True


@pytest.mark.asyncio
async def test_litellm_remediation_plan_parses_json_response(monkeypatch):
    async def fake_acompletion(**_kwargs):
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"summary":"Fix DKIM","actions":[{"finding_code":'
                            '"dkim_selector_missing","title":"Publish DKIM",'
                            '"priority":"warning","summary":"Publish selector",'
                            '"steps":["Copy provider record"],"evidence":[],'
                            '"target_record":null,"requires_human_change":true}]}'
                        )
                    }
                }
            ]
        }

    fake_litellm = SimpleNamespace(acompletion=fake_acompletion, drop_params=False)
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)
    config = AssistanceConfig(
        ai_enabled=True,
        provider="litellm",
        model="gpt-test",
        remote_base_url="https://llm.example.test/v1",
        redaction_mode="strict",
        action_tools_enabled=False,
        mcp_enabled=False,
        remediation_cache_seconds=86400,
    )

    plan = await ai_assistance._litellm_remediation_plan(
        config,
        {
            "domain": DOMAIN,
            "dns_guidance": {"findings": []},
            "constraints": {"automatic_dns_changes": False},
        },
    )

    assert plan is not None
    assert plan["provider"] == "litellm"
    assert plan["model"] == "gpt-test"
    assert plan["actions"][0]["finding_code"] == "dkim_selector_missing"


@pytest.mark.asyncio
async def test_litellm_remediation_plan_rejects_malformed_actions(monkeypatch):
    class FakeLiteLLM:
        drop_params = False

        @staticmethod
        async def acompletion(**_kwargs):
            return {"choices": [{"message": {"content": '{"summary": "No actions"}'}}]}

    monkeypatch.setitem(sys.modules, "litellm", FakeLiteLLM)
    config = AssistanceConfig(
        ai_enabled=True,
        provider="litellm",
        model="",
        remote_base_url="",
        redaction_mode="strict",
        action_tools_enabled=False,
        mcp_enabled=False,
        remediation_cache_seconds=60,
    )

    plan = await ai_assistance._litellm_remediation_plan(
        config,
        {
            "domain": DOMAIN,
            "dns_guidance": {"findings": []},
            "constraints": {"automatic_dns_changes": False},
        },
    )

    assert plan is None


@pytest.mark.asyncio
async def test_litellm_remediation_plan_returns_none_when_litellm_is_missing(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "litellm":
            raise ImportError("missing litellm")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    config = AssistanceConfig(
        ai_enabled=True,
        provider="litellm",
        model="",
        remote_base_url="",
        redaction_mode="strict",
        action_tools_enabled=False,
        mcp_enabled=False,
        remediation_cache_seconds=60,
    )

    plan = await ai_assistance._litellm_remediation_plan(
        config,
        {"domain": DOMAIN, "dns_guidance": {"findings": []}},
    )

    assert plan is None


@pytest.mark.asyncio
async def test_litellm_remediation_plan_returns_none_on_bad_json(monkeypatch):
    class FakeLiteLLM:
        drop_params = False

        @staticmethod
        async def acompletion(**_kwargs):
            return {"choices": [{"message": {"content": "not-json"}}]}

    monkeypatch.setitem(sys.modules, "litellm", FakeLiteLLM)
    config = AssistanceConfig(
        ai_enabled=True,
        provider="litellm",
        model="",
        remote_base_url="",
        redaction_mode="strict",
        action_tools_enabled=False,
        mcp_enabled=False,
        remediation_cache_seconds=60,
    )

    plan = await ai_assistance._litellm_remediation_plan(
        config,
        {"domain": DOMAIN, "dns_guidance": {"findings": []}},
    )

    assert plan is None


def test_ai_remediation_plan_returns_not_found_for_unknown_domain(
    authed_client: TestClient,
    db_session: Session,
):
    _set_setting(db_session, "ai.enabled", "true", "ai")

    response = authed_client.get("/api/v1/ai/domains/missing.example/remediation-plan")

    assert response.status_code == 404
    assert response.json()["detail"] == "Domain not found"


def test_ai_remediation_plan_can_use_litellm_provider(
    authed_client: TestClient,
    db_session: Session,
):
    _persist_report(db_session)
    _set_setting(db_session, "ai.enabled", "true", "ai")
    _set_setting(db_session, "ai.provider", "litellm", "ai")
    provider = AsyncMock()
    provider.check_domain = AsyncMock(
        return_value=DomainDNSResult(
            dmarc=True,
            dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
            spf=True,
            spf_record="v=spf1 -all",
            dkim=True,
            dkim_selectors=["google"],
            selectors_checked=["google"],
        )
    )
    provider.lookup_txt = AsyncMock(return_value=["v=spf1 -all"])
    provider.lookup_cname = AsyncMock(return_value=None)
    llm_plan = {
        "domain": DOMAIN,
        "provider": "litellm",
        "cached": False,
        "generated_at": "2026-06-29T10:00:00Z",
        "summary": "AI-generated plan.",
        "actions": [],
        "safe_context": {"domain": DOMAIN},
    }

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
        patch(
            "app.services.ai_assistance._litellm_remediation_plan",
            new=AsyncMock(return_value=llm_plan),
        ) as litellm_plan,
    ):
        response = authed_client.get(f"/api/v1/ai/domains/{DOMAIN}/remediation-plan")

    assert response.status_code == 200
    assert response.json()["plan"]["provider"] == "litellm"
    litellm_plan.assert_awaited_once()


def test_action_proposals_return_not_found_for_unknown_domain(
    authed_client: TestClient,
    db_session: Session,
):
    _set_setting(db_session, "ai.enabled", "true", "ai")

    response = authed_client.get("/api/v1/ai/domains/missing.example/action-proposals")

    assert response.status_code == 404
    assert response.json()["detail"] == "Domain not found"


def test_assistance_config_normalizes_invalid_settings(db_session: Session):
    _set_setting(db_session, "ai.provider", "surprise", "ai")
    _set_setting(db_session, "ai.redaction_mode", "unsafe", "ai")
    _set_setting(db_session, "ai.remediation_cache_seconds", "not-a-number", "ai")

    config = ai_assistance.get_assistance_config(db_session)

    assert config.provider == "template"
    assert config.redaction_mode == "strict"
    assert config.remediation_cache_seconds == 86400


def test_ai_redaction_mode_none_keeps_pii_but_redacts_secrets(db_session: Session):
    _set_setting(db_session, "ai.redaction_mode", "none", "ai")

    config = ai_assistance.get_assistance_config(db_session)
    redacted = ai_assistance.redact_safe_value(
        {
            "contact": "admin@example.com",
            "details": (
                "api_key=sk-test-secret "
                "opaque=abcdefghijklmnopqrstuvwxyz1234567890"
            ),
        },
        mode=config.redaction_mode,
    )

    assert config.redaction_mode == "none"
    assert redacted["contact"] == "admin@example.com"
    assert "api_key=**redacted**" in redacted["details"]
    assert "abcdefghijklmnopqrstuvwxyz1234567890" not in redacted["details"]
    rules = ai_assistance._redaction_rules("none")
    assert "email local-parts and domains are preserved" in rules
    assert "secret-like key/value fragments" in rules
    assert "no email local-part redaction" in ai_assistance._redaction_rules(
        "balanced"
    )


def test_report_selectors_ignore_malformed_entries():
    store = ReportStore.get_instance()
    store.add_report(
        {
            "domain": "selector.example",
            "report_id": "selector-report",
            "records": [
                {
                    "dkim": [
                        "not-a-dict",
                        {"selector": "alpha"},
                        {"selector": "alpha"},
                        {"selector": "beta"},
                    ]
                }
            ],
            "summary": {"total_count": 1, "passed_count": 0, "failed_count": 1},
        }
    )

    assert ai_assistance._selectors_from_reports(store, "selector.example") == [
        "alpha",
        "beta",
    ]


def test_build_safe_context_returns_not_found_for_unknown_domain(db_session: Session):
    with pytest.raises(ValueError, match="Domain not found"):
        ai_assistance.build_safe_context(db_session, "missing.example")


def test_ai_context_endpoint_honors_selected_workspace_header(
    monkeypatch: pytest.MonkeyPatch,
    db_session: Session,
):
    seen = {}

    def fake_authorized_workspace(auth_context, db, selected_workspace_id=None):
        seen["selected_workspace_id"] = selected_workspace_id
        return SimpleNamespace(id=456)

    monkeypatch.setattr(ai_endpoint, "_require_ai_enabled", lambda db: None)
    monkeypatch.setattr(ai_endpoint, "_authorized_ai_workspace", fake_authorized_workspace)
    monkeypatch.setattr(
        ai_endpoint,
        "build_safe_context",
        lambda db, domain, *, workspace_id: {
            "domain": domain,
            "workspace_id": workspace_id,
        },
    )

    response = asyncio.run(
        ai_endpoint.get_domain_safe_context(
            DOMAIN,
            selected_workspace="123",
            db=db_session,
            _auth={"auth_type": "jwt"},
        )
    )

    assert seen["selected_workspace_id"] == 123
    assert response["context"]["workspace_id"] == 456


def test_domain_exists_ignores_report_store_for_scoped_lookup(db_session: Session):
    store = ReportStore()
    store.add_report(
        {
            **REPORT,
            "domain": "store-only.example",
            "report_id": "store-only",
        }
    )

    assert (
        ai_assistance._domain_exists(
            db_session,
            store,
            "store-only.example",
            workspace_id=999,
        )
        is False
    )

    db_session.add(Domain(name="scoped-existing.example", workspace_id=999, active=True))
    db_session.commit()

    assert (
        ai_assistance._domain_exists(
            db_session,
            store,
            "scoped-existing.example",
            workspace_id=999,
        )
        is True
    )


def test_action_proposals_are_reviewable_and_not_mutating(
    authed_client: TestClient,
    db_session: Session,
):
    _persist_report(db_session)
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
    _persist_report(db_session)
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


@pytest.mark.asyncio
async def test_mcp_read_only_tool_dispatch_covers_new_domain_tools(db_session: Session):
    _seed_report_store()
    _persist_report(db_session)
    auth_context = {"auth_type": "disabled", "token_id": "test-token"}

    with (
        patch(
            "app.api.api_v1.endpoints.mcp.domains.get_domain_posture_dashboard",
            new=AsyncMock(return_value={"domain": DOMAIN, "grade": "A"}),
        ) as posture,
        patch(
            "app.api.api_v1.endpoints.mcp.domains.get_domain_sources",
            new=AsyncMock(return_value={"domain": DOMAIN, "sources": []}),
        ) as sources,
        patch(
            "app.api.api_v1.endpoints.mcp.domains.get_domain_dns_lint",
            new=AsyncMock(return_value={"domain": DOMAIN, "status": "attention"}),
        ) as dns_lint,
        patch(
            "app.api.api_v1.endpoints.mcp.domains.get_domain_dns_change_plan",
            new=AsyncMock(
                return_value={
                    "domain": DOMAIN,
                    "status": "attention",
                    "read_only": False,
                    "provider_write_available": True,
                    "apply_endpoint": f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
                    "plans": [
                        {
                            "plan_id": "dns-plan-1",
                            "finding_code": "dmarc_missing",
                            "severity": "error",
                            "operation": "create",
                            "record_type": "TXT",
                            "name": f"_dmarc.{DOMAIN}",
                            "proposed_value": "v=DMARC1; p=none",
                            "current_values": [],
                            "rationale": "Publish DMARC policy discovery.",
                            "risk": "Low; validates syntax before enforcement.",
                            "rollback": "Remove the new TXT record.",
                            "expected_health_impact": ("Expected to remove a DNS-health finding."),
                            "manual_steps": ["Create the TXT record."],
                            "requires_approval": True,
                            "applies_automatically": True,
                            "provider_write_available": True,
                        }
                    ],
                }
            ),
        ) as dns_change_plan,
        patch(
            "app.api.api_v1.endpoints.mcp.domains.get_domain_source_intelligence",
            new=AsyncMock(return_value={"domain": DOMAIN, "regions": []}),
        ) as intelligence,
        patch(
            "app.api.api_v1.endpoints.mcp.domains.build_domain_health_evidence_export_rows",
            new=AsyncMock(return_value=[{"domain": DOMAIN, "score": 72, "grade": "C"}]),
        ) as health_evidence,
    ):
        listed = await mcp_endpoint._call_read_only_tool(
            "list_domains",
            {},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        posture_result = await mcp_endpoint._call_read_only_tool(
            "domain_posture",
            {"domain": DOMAIN, "refresh": True},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        source_result = await mcp_endpoint._call_read_only_tool(
            "domain_sources",
            {"domain": DOMAIN, "days": "7"},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        dns_lint_result = await mcp_endpoint._call_read_only_tool(
            "dns_lint",
            {"domain": DOMAIN, "refresh": True},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        dns_plan_result = await mcp_endpoint._call_read_only_tool(
            "dns_change_plan",
            {"domain": DOMAIN},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        intelligence_result = await mcp_endpoint._call_read_only_tool(
            "source_intelligence",
            {"domain": DOMAIN},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        proposals = await mcp_endpoint._call_read_only_tool(
            "action_proposals",
            {"domain": DOMAIN},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        health_evidence_result = await mcp_endpoint._call_read_only_tool(
            "health_evidence_export",
            {"domain": DOMAIN, "start_date": "2026-06-01", "limit": "25"},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )
        usage_result = await mcp_endpoint._call_read_only_tool(
            "workspace_usage",
            {},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )

    assert listed["domains"][0]["domain"] == DOMAIN
    assert posture_result["grade"] == "A"
    assert source_result["sources"] == []
    assert dns_lint_result["status"] == "attention"
    assert dns_plan_result.read_only is True
    assert dns_plan_result.provider_write_available is False
    assert dns_plan_result.apply_endpoint is None
    assert dns_plan_result.plans[0].provider_write_available is False
    assert dns_plan_result.plans[0].applies_automatically is False
    assert intelligence_result["regions"] == []
    assert proposals["proposals"]
    assert health_evidence_result["scope"] == "domain"
    assert health_evidence_result["rows"][0]["score"] == 72
    assert usage_result["summary"]["domain_count"] == 1
    assert usage_result["summary"]["total_messages"] == 10
    posture.assert_awaited_once()
    sources.assert_awaited_once()
    dns_lint.assert_awaited_once()
    dns_change_plan.assert_awaited_once()
    intelligence.assert_awaited_once()
    health_evidence.assert_awaited_once()


@pytest.mark.asyncio
async def test_mcp_alert_history_returns_sanitized_workspace_alerts(
    db_session: Session,
):
    _persist_report(db_session)
    domain = db_session.query(Domain).filter(Domain.name == DOMAIN).one()
    db_session.add_all(
        [
            AlertHistory(
                fingerprint="mcp-alert-active",
                rule="dmarc_failures_above_threshold",
                severity="error",
                domain=DOMAIN,
                title="DMARC failures",
                detail="Failures exceeded threshold.",
                payload='{"failed_messages":42,"threshold":10,"secret":"hidden"}',
                observed_count=3,
                is_active=True,
            ),
            AlertHistory(
                fingerprint="mcp-alert-resolved",
                rule="missing_reports",
                severity="warning",
                domain=DOMAIN,
                title="Missing reports",
                detail="Resolved.",
                observed_count=1,
                is_active=False,
            ),
            AlertHistory(
                fingerprint="mcp-alert-malformed-payload",
                rule="new_sender_source",
                severity="warning",
                domain=DOMAIN,
                title="Malformed payload",
                detail="Payload should be ignored.",
                payload="{not-json",
                observed_count=1,
                is_active=True,
            ),
        ]
    )
    db_session.commit()

    result = await mcp_endpoint._call_read_only_tool(
        "alert_history",
        {"active": "true", "limit": "5"},
        db=db_session,
        auth_context={"token_id": "test-token"},
        workspace_id=domain.workspace_id,
    )
    resolved_result = await mcp_endpoint._call_read_only_tool(
        "alert_history",
        {"active": "off", "domain": DOMAIN, "limit": "10"},
        db=db_session,
        auth_context={"token_id": "test-token"},
        workspace_id=domain.workspace_id,
    )
    empty_result = await mcp_endpoint._call_read_only_tool(
        "alert_history",
        {"domain": "missing.example", "limit": 1},
        db=db_session,
        auth_context={"token_id": "test-token"},
        workspace_id=domain.workspace_id,
    )

    alerts_by_fingerprint = {alert["fingerprint"]: alert for alert in result["alerts"]}
    assert result["summary"]["active"] == 2
    assert result["filters"]["active"] is True
    assert alerts_by_fingerprint["mcp-alert-active"]["rule"] == "dmarc_failures_above_threshold"
    assert alerts_by_fingerprint["mcp-alert-active"]["evidence"] == {
        "failed_messages": 42,
        "threshold": 10,
    }
    assert "evidence" not in alerts_by_fingerprint["mcp-alert-malformed-payload"]
    assert "payload" not in alerts_by_fingerprint["mcp-alert-active"]
    assert resolved_result["summary"]["resolved"] == 1
    assert resolved_result["filters"]["active"] is False
    assert resolved_result["alerts"][0]["fingerprint"] == "mcp-alert-resolved"
    assert empty_result["alerts"] == []
    assert "hidden" not in str(result)


def test_mcp_export_catalog_returns_workspace_exports(
    client: TestClient,
    db_session: Session,
):
    _persist_report(db_session)
    domain = db_session.query(Domain).filter(Domain.name == DOMAIN).one()
    token = create_api_token(
        db_session,
        name="mcp catalog",
        scopes=[MCP_READ_SCOPE],
        workspace_id=domain.workspace_id,
    )
    _set_setting(db_session, "mcp.enabled", "true", "mcp")

    response = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "export_catalog", "arguments": {}},
        },
    )
    assert response.status_code == 200
    result = response.json()["result"]["content"][0]["json"]

    assert result["token"]["name"] == "mcp catalog"
    assert result["mcp"]["available"] is True
    assert result["workspace"]["domain_count"] == 1
    assert result["domains"][0]["domain"] == DOMAIN
    tool_names = {tool["name"] for tool in result["mcp"]["tools"]}
    assert "export_catalog" in tool_names
    assert "workspace_usage" in tool_names
    assert (
        result["domains"][0]["exports"]["domain_reports"]["href"]
        == f"/api/v1/public/domains/{DOMAIN}/reports"
    )


@pytest.mark.asyncio
async def test_mcp_read_only_tool_dispatch_rejects_invalid_tool_arguments(
    db_session: Session,
):
    auth_context = {"token_id": "test-token"}

    with pytest.raises(ValueError, match="domain is required"):
        await mcp_endpoint._call_read_only_tool(
            "domain_summary",
            {"domain": " "},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )

    with pytest.raises(ValueError, match="days must be an integer"):
        await mcp_endpoint._call_read_only_tool(
            "domain_sources",
            {"domain": DOMAIN, "days": "soon"},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )

    with pytest.raises(ValueError, match="start_date must be an ISO date"):
        await mcp_endpoint._call_read_only_tool(
            "health_evidence_export",
            {"domain": DOMAIN, "start_date": "next week"},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )

    with pytest.raises(ValueError, match="limit must be an integer"):
        await mcp_endpoint._call_read_only_tool(
            "health_evidence_export",
            {"domain": DOMAIN, "limit": 0},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )

    with pytest.raises(ValueError, match="limit must be an integer"):
        await mcp_endpoint._call_read_only_tool(
            "health_evidence_export",
            {"domain": DOMAIN, "limit": "many"},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )

    with pytest.raises(ValueError, match="active must be a boolean"):
        await mcp_endpoint._call_read_only_tool(
            "alert_history",
            {"active": "sometimes"},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )

    with pytest.raises(KeyError):
        await mcp_endpoint._call_read_only_tool(
            "unknown_tool",
            {},
            db=db_session,
            auth_context=auth_context,
            workspace_id=None,
        )


def test_mcp_requires_enabled_scoped_token(client: TestClient, db_session: Session):
    _persist_report(db_session)
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
    tools = listed.json()["result"]["tools"]
    assert tools[0]["readOnlyHint"] is True
    tool_names = {tool["name"] for tool in tools}
    assert {
        "domain_sources",
        "source_intelligence",
        "domain_posture",
        "dns_lint",
        "dns_change_plan",
        "health_evidence_export",
        "alert_history",
        "export_catalog",
        "workspace_usage",
    }.issubset(tool_names)

    initialized = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={"jsonrpc": "2.0", "id": 5, "method": "initialize"},
    )
    assert initialized.status_code == 200
    assert initialized.json()["result"]["serverInfo"]["name"] == "dmarq"

    unsupported_method = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={"jsonrpc": "2.0", "id": 6, "method": "resources/list"},
    )
    assert unsupported_method.status_code == 200
    assert unsupported_method.json()["error"]["code"] == -32601

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

    source_intelligence = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "source_intelligence", "arguments": {"domain": DOMAIN}},
        },
    )
    assert source_intelligence.status_code == 200
    source_result = source_intelligence.json()["result"]["content"][0]["json"]
    assert source_result["domain"] == DOMAIN
    assert "regions" in source_result

    invalid_window = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "source_intelligence", "arguments": {"domain": DOMAIN, "days": 0}},
        },
    )
    assert invalid_window.status_code == 200
    assert invalid_window.json()["error"]["code"] == -32004

    unsupported_tool = client.post(
        "/api/v1/mcp",
        headers={"X-API-Key": token.secret},
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "unknown_tool", "arguments": {}},
        },
    )
    assert unsupported_tool.status_code == 200
    assert unsupported_tool.json()["error"]["code"] == -32602


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
