from types import SimpleNamespace

from app.services import remediation_dispatch
from app.services.webhook_events import (
    EVENT_REMEDIATION_APPROVAL_REQUIRED,
    EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED,
)


def test_attach_remediation_dispatch_previews_reuses_request_context(monkeypatch):
    calls = {"settings": 0, "webhooks": 0}

    def fake_settings(_db):
        calls["settings"] += 1
        return {
            remediation_dispatch.DISPATCH_ENABLED_KEY: "true",
            remediation_dispatch.DISPATCH_REQUIRE_ACK_KEY: "false",
            remediation_dispatch.DISPATCH_CHANNEL_KEY: "webhook",
            remediation_dispatch.DISPATCH_EVENTS_KEY: EVENT_REMEDIATION_APPROVAL_REQUIRED,
        }

    def fake_enabled_webhook_endpoints(_db, *, workspace):
        calls["webhooks"] += 1
        assert workspace.id == 42
        return [SimpleNamespace(event_types="*")]

    monkeypatch.setattr(remediation_dispatch, "_settings", fake_settings)
    monkeypatch.setattr(
        remediation_dispatch,
        "_enabled_webhook_endpoints",
        fake_enabled_webhook_endpoints,
    )
    monkeypatch.setattr(
        remediation_dispatch,
        "_latest_lifecycle_marker",
        lambda *_args, **_kwargs: {"state": None, "recorded_at": None},
    )
    monkeypatch.setattr(
        remediation_dispatch,
        "_notification_histories",
        lambda *_args, **_kwargs: {},
    )

    queue = {
        "domain": "example.com",
        "items": [
            {
                "id": "dns:dmarc-missing",
                "notification": {"event": EVENT_REMEDIATION_APPROVAL_REQUIRED},
            },
            {
                "id": "health:low_compliance",
                "notification": {"event": EVENT_REMEDIATION_APPROVAL_REQUIRED},
            },
        ],
    }

    result = remediation_dispatch.attach_remediation_dispatch_previews(
        object(),
        workspace=SimpleNamespace(id=42),
        queue=queue,
    )

    assert calls == {"settings": 1, "webhooks": 1}
    dispatches = [item["notification"]["dispatch"] for item in result["items"]]
    assert [dispatch["webhook_endpoint_count"] for dispatch in dispatches] == [1, 1]
    assert [dispatch["eligible"] for dispatch in dispatches] == [True, True]
    assert result["summary"]["dispatch_ready"] == 2
    assert result["summary"]["dispatch_webhook_routes"] == 1


def test_attach_remediation_dispatch_previews_adds_dashboard_summary(monkeypatch):
    def fake_settings(_db):
        return {
            remediation_dispatch.DISPATCH_ENABLED_KEY: "true",
            remediation_dispatch.DISPATCH_REQUIRE_ACK_KEY: "true",
            remediation_dispatch.DISPATCH_CHANNEL_KEY: "webhook",
            remediation_dispatch.DISPATCH_EVENTS_KEY: EVENT_REMEDIATION_APPROVAL_REQUIRED,
        }

    def fake_enabled_webhook_endpoints(_db, *, workspace):
        assert workspace.id == 42
        return [SimpleNamespace(event_types=EVENT_REMEDIATION_APPROVAL_REQUIRED)]

    def fake_lifecycle(_db, *, workspace, domain, item_id):
        assert workspace.id == 42
        assert domain == "example.com"
        if item_id == "dns:dmarc-missing":
            return {"state": "acknowledged", "recorded_at": "2026-07-01T08:00:00"}
        return {"state": None, "recorded_at": None}

    monkeypatch.setattr(remediation_dispatch, "_settings", fake_settings)
    monkeypatch.setattr(
        remediation_dispatch,
        "_enabled_webhook_endpoints",
        fake_enabled_webhook_endpoints,
    )
    monkeypatch.setattr(remediation_dispatch, "_latest_lifecycle_marker", fake_lifecycle)
    monkeypatch.setattr(
        remediation_dispatch,
        "_notification_histories",
        lambda *_args, **_kwargs: {
            "dns:dmarc-missing": [
                {
                    "action": "remediation.notification_lifecycle_recorded",
                    "state": "acknowledged",
                    "created_at": "2026-07-01T08:00:00",
                }
            ],
            "health:spf-hardening": [],
        },
    )

    queue = {
        "domain": "example.com",
        "summary": {"total": 2, "approval_ready": 1, "manual_action": 1},
        "items": [
            {
                "id": "dns:dmarc-missing",
                "notification": {"event": EVENT_REMEDIATION_APPROVAL_REQUIRED},
            },
            {
                "id": "health:spf-hardening",
                "notification": {"event": EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED},
            },
        ],
    }

    result = remediation_dispatch.attach_remediation_dispatch_previews(
        object(),
        workspace=SimpleNamespace(id=42),
        queue=queue,
    )

    summary = result["summary"]
    assert summary["total"] == 2
    assert summary["dispatch_ready"] == 1
    assert summary["dispatch_blocked"] == 1
    assert summary["dispatch_disabled"] == 0
    assert summary["dispatch_awaiting_acknowledgement"] == 1
    assert summary["dispatch_webhook_routes"] == 1


def test_attach_remediation_dispatch_previews_skips_empty_queues(monkeypatch):
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("empty queues should not fetch dispatch context")

    monkeypatch.setattr(remediation_dispatch, "_settings", fail_if_called)
    monkeypatch.setattr(remediation_dispatch, "_enabled_webhook_endpoints", fail_if_called)

    queue = {"domain": "example.com", "items": []}

    result = remediation_dispatch.attach_remediation_dispatch_previews(
        object(),
        workspace=SimpleNamespace(id=42),
        queue=queue,
    )

    assert result is queue
    assert result["summary"] == {
        "dispatch_ready": 0,
        "dispatch_blocked": 0,
        "dispatch_disabled": 0,
        "dispatch_awaiting_acknowledgement": 0,
        "dispatch_webhook_routes": 0,
    }


def test_build_remediation_dispatch_preview_fetches_context_when_not_preloaded(monkeypatch):
    calls = {"settings": 0, "webhooks": 0}

    def fake_settings(_db):
        calls["settings"] += 1
        return {
            remediation_dispatch.DISPATCH_ENABLED_KEY: "true",
            remediation_dispatch.DISPATCH_REQUIRE_ACK_KEY: "false",
            remediation_dispatch.DISPATCH_CHANNEL_KEY: "webhook",
            remediation_dispatch.DISPATCH_EVENTS_KEY: EVENT_REMEDIATION_APPROVAL_REQUIRED,
        }

    def fake_enabled_webhook_endpoints(_db, *, workspace):
        calls["webhooks"] += 1
        assert workspace.id == 42
        return [SimpleNamespace(event_types=EVENT_REMEDIATION_APPROVAL_REQUIRED)]

    monkeypatch.setattr(remediation_dispatch, "_settings", fake_settings)
    monkeypatch.setattr(
        remediation_dispatch,
        "_enabled_webhook_endpoints",
        fake_enabled_webhook_endpoints,
    )
    monkeypatch.setattr(
        remediation_dispatch,
        "_latest_lifecycle_marker",
        lambda *_args, **_kwargs: {"state": None, "recorded_at": None},
    )

    preview = remediation_dispatch.build_remediation_dispatch_preview(
        object(),
        workspace=SimpleNamespace(id=42),
        domain="example.com",
        item={
            "id": "dns:dmarc-missing",
            "notification": {"event": EVENT_REMEDIATION_APPROVAL_REQUIRED},
        },
    )

    assert calls == {"settings": 1, "webhooks": 1}
    assert preview["webhook_endpoint_count"] == 1
    assert preview["eligible"] is True
