import json

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.workspace_access import WorkspaceAuditLog
from app.services.workspace_access import (
    PERMISSION_WORKSPACE_ADMIN,
    ROLE_DOMAIN_ADMIN,
    ROLE_WORKSPACE_OWNER,
    require_workspace_permission,
    role_for_auth_context,
)
from app.services.workspace_audit import (
    actor_from_auth,
    audit_log_to_dict,
    list_workspace_audit_logs,
    record_workspace_audit_log,
    sanitize_audit_details,
)
from app.services.workspaces import get_or_create_default_workspace


def test_workspace_roles_endpoint_lists_permissions(authed_client: TestClient):
    """Operators can discover the workspace RBAC vocabulary."""
    response = authed_client.get("/api/v1/audit/roles")

    assert response.status_code == 200
    roles = {item["role"]: set(item["permissions"]) for item in response.json()["roles"]}
    assert ROLE_WORKSPACE_OWNER in roles
    assert ROLE_DOMAIN_ADMIN in roles
    assert "workspace:admin" in roles[ROLE_WORKSPACE_OWNER]
    assert "mail_sources:write" in roles[ROLE_DOMAIN_ADMIN]


def test_audit_details_sanitize_secret_like_fields():
    """Audit helper redacts nested secret-shaped fields."""
    details = sanitize_audit_details(
        {
            "name": "mailbox",
            "password": "super-secret",
            "nested": {"refresh_token": "token-secret"},
        }
    )

    assert details["name"] == "mailbox"
    assert details["password"] == "[redacted]"
    assert details["nested"]["refresh_token"] == "[redacted]"
    assert "super-secret" not in json.dumps(details)
    assert "token-secret" not in json.dumps(details)


def test_workspace_permission_denial_and_actor_variants(db_session: Session):
    """RBAC and audit helpers cover fallback actors and denial paths."""
    workspace = get_or_create_default_workspace(db_session)

    assert role_for_auth_context({"auth_type": "unexpected"}) == "auditor"
    try:
        require_workspace_permission({"auth_type": "unexpected"}, PERMISSION_WORKSPACE_ADMIN)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        assert getattr(exc, "status_code", None) == 403
    else:
        raise AssertionError("permission denial was not raised")

    assert (
        actor_from_auth({"auth_type": "jwt", "payload": {"sub": "user-123"}})["actor_id"]
        == "user-123"
    )
    assert actor_from_auth({"auth_type": "api_token", "token_id": 42})["actor_id"] == "42"
    assert sanitize_audit_details({"object": object()})["object"].startswith("<object object")

    row = record_workspace_audit_log(
        db_session,
        workspace=workspace,
        action="workspace.test",
        entity_type="workspace",
        entity_id=workspace.id,
        details={"client_secret": "hidden"},
        auth_context={"auth_type": "jwt", "payload": {"sub": "user-123"}},
    )
    db_session.commit()
    db_session.refresh(row)
    assert audit_log_to_dict(row)["details"]["client_secret"] == "[redacted]"

    row.details = "{not-json"
    assert audit_log_to_dict(row)["details"] == {}
    filtered = list_workspace_audit_logs(
        db_session,
        workspace=workspace,
        action="workspace.test",
        entity_type="workspace",
    )
    assert filtered[0]["action"] == "workspace.test"


def test_mail_source_changes_create_workspace_audit_without_secret_values(
    authed_client: TestClient,
    db_session: Session,
):
    """Mail source create/update actions are auditable without leaking credentials."""
    created = authed_client.post(
        "/api/v1/mail-sources",
        json={
            "name": "DMARC Inbox",
            "method": "IMAP",
            "server": "imap.example.com",
            "username": "reports@example.com",
            "password": "super-secret-password",
        },
    )
    assert created.status_code == 201
    source_id = created.json()["id"]

    updated = authed_client.put(
        f"/api/v1/mail-sources/{source_id}",
        json={"password": "new-secret-password", "folder": "Reports"},
    )
    assert updated.status_code == 200
    toggled = authed_client.post(f"/api/v1/mail-sources/{source_id}/toggle")
    assert toggled.status_code == 200
    deleted = authed_client.delete(f"/api/v1/mail-sources/{source_id}")
    assert deleted.status_code == 204

    rows = (
        db_session.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.entity_type == "mail_source")
        .order_by(WorkspaceAuditLog.id)
        .all()
    )
    assert [row.action for row in rows] == [
        "mail_source.created",
        "mail_source.updated",
        "mail_source.toggled",
        "mail_source.deleted",
    ]
    serialized = "\n".join(row.details or "" for row in rows)
    assert "super-secret-password" not in serialized
    assert "new-secret-password" not in serialized
    assert "changed_fields" in serialized


def test_notification_setting_audit_is_workspace_scoped_and_redacted(
    authed_client: TestClient,
):
    """Notification setting changes appear in workspace audit logs with redacted secrets."""
    response = authed_client.put(
        "/api/v1/settings/notifications.apprise_urls",
        json={"value": "mailto://user:password@example.com"},
        headers={"x-forwarded-for": "203.0.113.5, 10.0.0.1"},
    )
    assert response.status_code == 200

    audit = authed_client.get("/api/v1/audit/logs?entity_type=setting")
    assert audit.status_code == 200
    events = audit.json()["audit"]
    assert events[0]["action"] == "setting.changed"
    assert events[0]["ip_address"] == "203.0.113.5"
    assert events[0]["details"]["new_value"] == "[redacted]"
    assert "password@example.com" not in str(events)


def test_api_token_create_and_revoke_are_audited_without_raw_token(
    authed_client: TestClient,
):
    """API token lifecycle records expose metadata but not raw secrets."""
    created = authed_client.post(
        "/api/v1/api-tokens",
        json={"name": "SIEM exporter", "scopes": ["reports:read"]},
    )
    assert created.status_code == 201
    body = created.json()
    token_id = body["metadata"]["id"]
    raw_token = body["token"]

    revoked = authed_client.delete(f"/api/v1/api-tokens/{token_id}")
    assert revoked.status_code == 200

    audit = authed_client.get("/api/v1/audit/logs?entity_type=api_token")
    assert audit.status_code == 200
    actions = [item["action"] for item in audit.json()["audit"]]
    assert actions[:2] == ["api_token.revoked", "api_token.created"]
    assert raw_token not in str(audit.json())


def test_webhook_changes_are_audited_without_signing_secret(authed_client: TestClient):
    """Webhook lifecycle changes write sanitized audit events."""
    created = authed_client.post(
        "/api/v1/webhooks",
        json={
            "name": "SIEM receiver",
            "url": "https://example.com/dmarq",
            "secret": "very-secret-webhook-signing-value",
        },
    )
    assert created.status_code == 200
    endpoint_id = created.json()["id"]

    updated = authed_client.put(
        f"/api/v1/webhooks/{endpoint_id}",
        json={"name": "Updated receiver", "secret": "another-secret-webhook-value"},
    )
    assert updated.status_code == 200
    disabled = authed_client.delete(f"/api/v1/webhooks/{endpoint_id}")
    assert disabled.status_code == 200

    audit = authed_client.get("/api/v1/audit/logs?entity_type=webhook_endpoint")
    assert audit.status_code == 200
    actions = [event["action"] for event in audit.json()["audit"]]
    assert actions[:3] == ["webhook.disabled", "webhook.updated", "webhook.created"]
    serialized = str(audit.json())
    assert "very-secret-webhook-signing-value" not in serialized
    assert "another-secret-webhook-value" not in serialized


def test_manual_selector_changes_are_audited(authed_client: TestClient):
    """Manual DKIM selector changes create audit entries."""
    created = authed_client.post(
        "/api/v1/domains/domains",
        json={"name": "selector-audit.example"},
    )
    assert created.status_code == 201

    added = authed_client.post(
        "/api/v1/domains/selector-audit.example/selectors",
        json={"selector": "s2026"},
    )
    assert added.status_code == 201
    removed = authed_client.delete("/api/v1/domains/selector-audit.example/selectors/s2026")
    assert removed.status_code == 200

    audit = authed_client.get("/api/v1/audit/logs?entity_type=domain")
    assert audit.status_code == 200
    actions = [event["action"] for event in audit.json()["audit"]]
    assert actions[:2] == ["domain.selector_removed", "domain.selector_added"]
