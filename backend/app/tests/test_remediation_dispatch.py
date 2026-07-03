import json
from datetime import datetime
from types import SimpleNamespace

from app.models.workspace_access import WorkspaceAuditLog
from app.services import remediation_dispatch
from app.services.webhook_events import (
    EVENT_REMEDIATION_APPROVAL_REQUIRED,
    EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED,
)
from app.services.workspaces import get_or_create_default_workspace


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


def test_attach_remediation_dispatch_previews_counts_operator_held_items(monkeypatch):
    def fake_settings(_db):
        return {
            remediation_dispatch.DISPATCH_ENABLED_KEY: "true",
            remediation_dispatch.DISPATCH_REQUIRE_ACK_KEY: "true",
            remediation_dispatch.DISPATCH_CHANNEL_KEY: "webhook",
            remediation_dispatch.DISPATCH_EVENTS_KEY: EVENT_REMEDIATION_APPROVAL_REQUIRED,
        }

    monkeypatch.setattr(remediation_dispatch, "_settings", fake_settings)
    monkeypatch.setattr(
        remediation_dispatch,
        "_enabled_webhook_endpoints",
        lambda *_args, **_kwargs: [
            SimpleNamespace(event_types=EVENT_REMEDIATION_APPROVAL_REQUIRED)
        ],
    )
    monkeypatch.setattr(
        remediation_dispatch,
        "_latest_lifecycle_marker",
        lambda *_args, **_kwargs: {"state": "resolved", "recorded_at": "2026-07-01T08:00:00"},
    )
    monkeypatch.setattr(
        remediation_dispatch,
        "_notification_histories",
        lambda *_args, **_kwargs: {
            "dns:dmarc-missing": [
                {
                    "action": "remediation.notification_lifecycle_recorded",
                    "state": "resolved",
                    "created_at": "2026-07-01T08:00:00",
                }
            ]
        },
    )

    queue = {
        "domain": "example.com",
        "items": [
            {
                "id": "dns:dmarc-missing",
                "notification": {"event": EVENT_REMEDIATION_APPROVAL_REQUIRED},
            }
        ],
    }

    result = remediation_dispatch.attach_remediation_dispatch_previews(
        object(),
        workspace=SimpleNamespace(id=42),
        queue=queue,
    )

    dispatch = result["items"][0]["notification"]["dispatch"]
    assert dispatch["operator_hold"] is True
    assert dispatch["eligible"] is False
    assert dispatch["blocked_reasons"] == ["Operator marked this remediation item resolved."]
    assert dispatch["next_steps"] == [
        "Keep monitoring new reports; reopen the item only if the finding returns."
    ]
    assert result["summary"]["dispatch_blocked"] == 1
    assert result["summary"]["dispatch_awaiting_acknowledgement"] == 0
    assert result["summary"]["dispatch_resolved"] == 1
    assert result["summary"]["dispatch_rejected"] == 0
    assert result["summary"]["dispatch_snoozed"] == 0


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
        "dispatch_resolved": 0,
        "dispatch_rejected": 0,
        "dispatch_snoozed": 0,
    }


def test_notification_histories_return_sanitized_recent_audit_events(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="user",
                actor_id="operator-1",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:dmarc-missing",
                entity_name="example.com",
                details=json.dumps(
                    {
                        "lifecycle_state": "acknowledged",
                        "operator_note": "Reviewed with DNS owner",
                        "delivery_enqueued": False,
                        "dns_write_attempted": False,
                    }
                ),
                created_at=datetime(2026, 7, 1, 8, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="user",
                actor_id="operator-1",
                action="remediation.notification_dispatch_enqueued",
                entity_type="remediation_notification",
                entity_id="dns:dmarc-missing",
                entity_name="example.com",
                details=json.dumps(
                    {
                        "operator_note": "Route this to security",
                        "delivery_enqueued": True,
                        "delivery_count": "not-a-number",
                        "deliveries": [{"secret": "do-not-return"}],
                        "dns_write_attempted": False,
                        "sent": False,
                    }
                ),
                created_at=datetime(2026, 7, 1, 9, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="system",
                actor_id="legacy",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:dmarc-missing",
                entity_name="example.com",
                details="{broken-json",
                created_at=datetime(2026, 7, 1, 10, 0, 0),
            ),
        ]
    )
    db_session.commit()

    histories = remediation_dispatch._notification_histories(
        db_session,
        workspace=workspace,
        domain="example.com",
        item_ids=["dns:dmarc-missing"],
    )

    history = histories["dns:dmarc-missing"]
    assert [entry["action"] for entry in history] == [
        "remediation.notification_dispatch_enqueued",
        "remediation.notification_lifecycle_recorded",
    ]
    assert history[0]["label"] == "Dispatch enqueued"
    assert history[0]["state"] == "delivery_enqueued"
    assert history[0]["delivery_count"] == 0
    assert history[0]["operator_note"] == "Route this to security"
    assert history[0]["sent"] is False
    assert history[0]["dns_write_attempted"] is False
    assert "deliveries" not in history[0]
    assert "actor_id" not in history[0]
    assert history[1]["state"] == "acknowledged"
    assert history[1]["operator_note"] == "Reviewed with DNS owner"


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
