import json
from datetime import datetime, timedelta, timezone
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
    assert summary["dispatch_verified_fixed"] == 0
    assert summary["dispatch_verified_fixed_visible"] == 0
    assert summary["dispatch_verified_fixed_hidden"] == 0


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
    assert dispatch["verification"] == {
        "state": "still_observed",
        "verified": False,
        "label": "Still observed",
        "detail": (
            "An operator marked this remediation item resolved, but current "
            "domain evidence still produces the same finding."
        ),
        "recorded_at": "2026-07-01T08:00:00",
    }
    assert dispatch["blocked_reasons"] == ["Operator marked this remediation item resolved."]
    assert dispatch["next_steps"] == [
        "Keep monitoring new reports; reopen the item only if the finding returns."
    ]
    assert result["summary"]["dispatch_blocked"] == 1
    assert result["summary"]["dispatch_awaiting_acknowledgement"] == 0
    assert result["summary"]["dispatch_resolved"] == 1
    assert result["summary"]["dispatch_rejected"] == 0
    assert result["summary"]["dispatch_snoozed"] == 0
    assert result["summary"]["dispatch_verified_fixed"] == 0
    assert result["summary"]["dispatch_verified_fixed_visible"] == 0
    assert result["summary"]["dispatch_verified_fixed_hidden"] == 0


def test_verification_state_covers_lifecycle_branches():
    recorded_at = "2026-07-01T08:00:00"

    assert remediation_dispatch._verification_state("resolved", recorded_at) == {
        "state": "still_observed",
        "verified": False,
        "label": "Still observed",
        "detail": (
            "An operator marked this remediation item resolved, but current "
            "domain evidence still produces the same finding."
        ),
        "recorded_at": recorded_at,
    }
    assert remediation_dispatch._verification_state("rejected", recorded_at) == {
        "state": "operator_rejected",
        "verified": False,
        "label": "Rejected",
        "detail": "Operator hold is active; DMARQ will keep showing current evidence.",
        "recorded_at": recorded_at,
    }
    assert remediation_dispatch._verification_state("snoozed", recorded_at) == {
        "state": "operator_snoozed",
        "verified": False,
        "label": "Snoozed",
        "detail": "Operator hold is active; DMARQ will keep showing current evidence.",
        "recorded_at": recorded_at,
    }
    assert remediation_dispatch._verification_state("previewed", recorded_at) == {
        "state": "pending_operator_action",
        "verified": False,
        "label": "Pending action",
        "detail": "Operator reviewed this item; current evidence still needs remediation.",
        "recorded_at": recorded_at,
    }
    assert remediation_dispatch._verification_state("acknowledged", recorded_at) == {
        "state": "pending_operator_action",
        "verified": False,
        "label": "Pending action",
        "detail": "Operator reviewed this item; current evidence still needs remediation.",
        "recorded_at": recorded_at,
    }
    assert remediation_dispatch._verification_state(None, None) == {
        "state": "not_started",
        "verified": False,
        "label": "Not started",
        "detail": "No verification marker exists for this current remediation item.",
        "recorded_at": None,
    }


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
        "dispatch_verified_fixed": 0,
        "dispatch_verified_fixed_visible": 0,
        "dispatch_verified_fixed_hidden": 0,
    }
    assert result["verified_items"] == []
    assert result["verified_items_total"] == 0


def test_attach_remediation_dispatch_previews_reports_verified_fixed_items(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:dmarc-missing",
                entity_name=" .Example.COM. ",
                details=json.dumps(
                    {
                        "lifecycle_state": "resolved",
                        "operator_note": "Record is now visible after propagation.",
                    }
                ),
                created_at=datetime(2026, 7, 1, 8, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:still-present",
                entity_name="example.com",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=datetime(2026, 7, 1, 9, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:changed-after-resolved",
                entity_name="example.com",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=datetime(2026, 7, 1, 7, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:changed-after-resolved",
                entity_name="example.com",
                details=json.dumps({"lifecycle_state": "snoozed"}),
                created_at=datetime(2026, 7, 1, 10, 0, 0),
            ),
        ]
    )
    db_session.commit()
    queue = {
        "domain": "example.com",
        "summary": {"total": 1},
        "items": [
            {
                "id": "dns:still-present",
                "notification": {"event": EVENT_REMEDIATION_APPROVAL_REQUIRED},
            }
        ],
    }

    result = remediation_dispatch.attach_remediation_dispatch_previews(
        db_session,
        workspace=workspace,
        queue=queue,
    )

    assert result["summary"]["dispatch_verified_fixed"] == 1
    assert result["summary"]["dispatch_verified_fixed_visible"] == 1
    assert result["verified_items_total"] == 1
    assert result["verified_items"] == [
        {
            "item_id": "dns:dmarc-missing",
            "state": "verified_fixed",
            "verified": True,
            "label": "Verified fixed",
            "detail": (
                "This remediation item was marked resolved and no longer appears "
                "in the current remediation queue."
            ),
            "verification_status": "no_longer_observed",
            "verification_method": "current_queue_absence",
            "freshness_status": "current_queue_absence",
            "freshness_label": "Fresh queue absence",
            "closure_gate": (
                "Closed only while the latest remediation queue and imported evidence "
                "keep this finding absent."
            ),
            "next_check": (
                "Keep importing fresh DMARC reports and refresh DNS evidence; reopen "
                "the item if the same finding returns."
            ),
            "next_safe_action": (
                "Keep monitoring fresh reports and DNS evidence before treating this "
                "repair as permanently closed."
            ),
            "evidence_needed": [
                "The latest lifecycle marker for this item is resolved.",
                "The same item id is absent from the current remediation queue.",
            ],
            "recorded_at": "2026-07-01T08:00:00Z",
            "operator_note": "Record is now visible after propagation.",
            "actor_type": "operator",
        }
    ]


def test_verified_fixed_total_counts_beyond_visible_limit(db_session):
    workspace = get_or_create_default_workspace(db_session)
    base_time = datetime(2026, 7, 1, 8, 0, 0)
    db_session.add_all(
        [
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id=f"dns:fixed-{index}",
                entity_name="example.com",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=base_time + timedelta(minutes=index),
            )
            for index in range(45)
        ]
    )
    db_session.commit()

    result = remediation_dispatch.attach_remediation_dispatch_previews(
        db_session,
        workspace=workspace,
        queue={"domain": "example.com", "summary": {}, "items": []},
    )

    assert result["verified_items_total"] == 45
    assert result["summary"]["dispatch_verified_fixed"] == 45
    assert result["summary"]["dispatch_verified_fixed_visible"] == 5
    assert result["summary"]["dispatch_verified_fixed_hidden"] == 40
    assert len(result["verified_items"]) == 5
    assert result["verified_items"][0]["item_id"] == "dns:fixed-44"


def test_verified_fixed_ignores_items_with_newer_unresolved_lifecycle(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:flapped",
                entity_name="example.com",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=datetime(2026, 7, 1, 8, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:flapped",
                entity_name="example.com",
                details=json.dumps({"lifecycle_state": "acknowledged"}),
                created_at=datetime(2026, 7, 1, 9, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:fixed",
                entity_name="example.com",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=datetime(2026, 7, 1, 10, 0, 0),
            ),
        ]
    )
    db_session.commit()

    result = remediation_dispatch.attach_remediation_dispatch_previews(
        db_session,
        workspace=workspace,
        queue={"domain": "example.com", "summary": {}, "items": []},
    )

    assert result["verified_items_total"] == 1
    assert [item["item_id"] for item in result["verified_items"]] == ["dns:fixed"]


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
    assert history[1]["label"] == "Marked acknowledged"
    assert history[1]["operator_note"] == "Reviewed with DNS owner"


def test_summarize_remediation_activity_handles_empty_domain_inputs(db_session):
    workspace = get_or_create_default_workspace(db_session)

    activity = remediation_dispatch.summarize_remediation_activity(
        db_session,
        workspace=workspace,
        domains=["", " . "],
        row_limit=0,
    )

    assert activity == {
        "summary": {
            "domains_with_activity": 0,
            "dispatch_enqueued": 0,
            "resolved": 0,
            "verified_fixed": 0,
            "operator_holds": 0,
            "needs_operator_follow_up": 0,
            "delivery_count": 0,
        },
        "domains": {},
    }
    assert remediation_dispatch._audit_timestamp("not-a-datetime") is None


def test_summarize_remediation_activity_reports_status_variants(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:reviewed",
                entity_name=" Reviewed.Example. ",
                details=json.dumps({"lifecycle_state": "previewed"}),
                created_at=datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:hold",
                entity_name="Hold.Example.",
                details=json.dumps({"lifecycle_state": "rejected"}),
                created_at=datetime(2026, 7, 1, 9, 0, 0),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_dispatch_enqueued",
                entity_type="remediation_notification",
                entity_id="dns:dispatch-requested",
                entity_name="dispatch.example",
                details=json.dumps({"delivery_enqueued": False}),
                created_at=datetime(2026, 7, 1, 10, 0, 0),
            ),
        ]
    )
    db_session.commit()

    activity = remediation_dispatch.summarize_remediation_activity(
        db_session,
        workspace=workspace,
        domains=["reviewed.example", "hold.example", "dispatch.example"],
        row_limit=1,
    )

    reviewed = activity["domains"]["reviewed.example"]
    assert reviewed["status"] == "reviewed"
    assert reviewed["latest_state"] == "previewed"
    assert reviewed["latest_at"] == "2026-07-01T08:00:00Z"
    assert reviewed["needs_operator_follow_up"] is True

    hold = activity["domains"]["hold.example"]
    assert hold["status"] == "operator_hold"
    assert hold["latest_state"] == "rejected"
    assert hold["rejected"] == 1
    assert hold["needs_operator_follow_up"] is True

    dispatch_requested = activity["domains"]["dispatch.example"]
    assert dispatch_requested["status"] == "activity"
    assert dispatch_requested["latest_state"] == "dispatch_requested"
    assert dispatch_requested["latest_label"] == "Dispatch requested"
    assert activity["summary"]["domains_with_activity"] == 3
    assert activity["summary"]["operator_holds"] == 1
    assert activity["summary"]["needs_operator_follow_up"] == 2


def test_summarize_remediation_activity_counts_verified_fixed_items(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="health:missing_dkim",
                entity_name="Fixed.Example",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="health:low_compliance",
                entity_name="Fixed.Example",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc),
            ),
        ]
    )
    db_session.commit()

    activity = remediation_dispatch.summarize_remediation_activity(
        db_session,
        workspace=workspace,
        domains=["fixed.example"],
        active_item_ids_by_domain={"fixed.example": ["health:low_compliance"]},
    )

    domain = activity["domains"]["fixed.example"]
    assert domain["resolved"] == 2
    assert domain["verified_fixed"] == 1
    assert activity["summary"]["resolved"] == 2
    assert activity["summary"]["verified_fixed"] == 1
    assert activity["summary"]["needs_operator_follow_up"] == 0


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
