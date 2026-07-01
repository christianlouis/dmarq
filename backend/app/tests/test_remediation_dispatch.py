from types import SimpleNamespace

from app.services import remediation_dispatch
from app.services.webhook_events import EVENT_REMEDIATION_APPROVAL_REQUIRED


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
