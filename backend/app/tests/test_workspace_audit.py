import json
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    PERMISSION_WORKSPACE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_DOMAIN_ADMIN,
    ROLE_WORKSPACE_OWNER,
    organization_ids_for_permission,
    require_workspace_permission,
    role_for_auth_context,
    role_for_organization,
    role_for_workspace,
)
from app.services.workspace_audit import (
    actor_from_auth,
    audit_log_to_dict,
    list_workspace_audit_logs,
    record_workspace_audit_log,
    sanitize_audit_details,
)
from app.services.workspaces import get_or_create_default_workspace


def _add_user(
    db_session: Session,
    email: str,
    workspace_id=None,
    is_superuser=False,
    logto_id=None,
):
    user = User(
        email=email,
        logto_id=logto_id,
        workspace_id=workspace_id,
        is_superuser=is_superuser,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


def _add_membership(db_session: Session, workspace: Workspace, user: User, role: str):
    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role=role,
        active=True,
    )
    db_session.add(membership)
    db_session.flush()
    return membership


@contextmanager
def _client_as_user(test_app, db_session: Session, user: User):
    async def mock_admin_auth():
        return {"auth_type": "session", "user_id": user.id}

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    original_overrides = dict(test_app.dependency_overrides)
    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    try:
        with TestClient(test_app) as client:
            yield client
    finally:
        test_app.dependency_overrides = original_overrides


@contextmanager
def _client_as_jwt(test_app, db_session: Session, subject: str, email: str | None = None):
    async def mock_admin_auth():
        payload = {"sub": subject}
        if email is not None:
            payload["email"] = email
        return {"auth_type": "jwt", "payload": payload}

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    original_overrides = dict(test_app.dependency_overrides)
    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    try:
        with TestClient(test_app) as client:
            yield client
    finally:
        test_app.dependency_overrides = original_overrides


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


def test_workspace_role_resolution_uses_membership(db_session: Session):
    """Workspace-aware RBAC resolves roles from active memberships."""
    workspace = get_or_create_default_workspace(db_session)
    auditor = _add_user(db_session, "auditor@example.com", logto_id="logto-auditor")
    analyst = _add_user(db_session, "analyst@example.com")
    outsider = _add_user(db_session, "outsider@example.com")
    conflicting_subject_user = _add_user(
        db_session,
        "logto-auditor",
        logto_id="other-logto-subject",
    )
    _add_membership(db_session, workspace, auditor, ROLE_AUDITOR)
    _add_membership(db_session, workspace, analyst, ROLE_ANALYST)
    _add_membership(db_session, workspace, conflicting_subject_user, ROLE_ANALYST)
    db_session.commit()

    assert (
        role_for_workspace(db_session, {"auth_type": "session", "user_id": auditor.id}, workspace)
        == ROLE_AUDITOR
    )
    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "jwt", "payload": {"sub": "logto-auditor"}},
            workspace,
        )
        == ROLE_AUDITOR
    )
    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "jwt", "payload": {"sub": "auditor@example.com"}},
            workspace,
        )
        == ROLE_AUDITOR
    )
    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "jwt", "payload": {"email": "logto-auditor"}},
            workspace,
        )
        == ROLE_ANALYST
    )
    assert (
        role_for_workspace(db_session, {"auth_type": "session", "user_id": analyst.id}, workspace)
        == ROLE_ANALYST
    )
    assert (
        role_for_workspace(db_session, {"auth_type": "session", "user_id": outsider.id}, workspace)
        == ""
    )


def test_organization_role_resolution_uses_org_workspace_and_superuser_paths(
    db_session: Session,
):
    """Organization RBAC accepts direct org, workspace, and legacy superuser grants."""
    organization = Organization(slug="rbac-org", name="RBAC Org", active=True)
    other_organization = Organization(slug="other-rbac-org", name="Other RBAC Org", active=True)
    db_session.add_all([organization, other_organization])
    db_session.flush()
    workspace = Workspace(
        slug="rbac-workspace",
        name="RBAC Workspace",
        organization_id=organization.id,
        active=True,
    )
    superuser_workspace = Workspace(
        slug="superuser-workspace",
        name="Superuser Workspace",
        organization_id=organization.id,
        active=True,
    )
    db_session.add_all([workspace, superuser_workspace])
    db_session.flush()
    org_auditor = _add_user(db_session, "org-auditor@example.com")
    workspace_owner = _add_user(db_session, "workspace-owner@example.com")
    superuser = _add_user(
        db_session,
        "org-superuser@example.com",
        workspace_id=superuser_workspace.id,
        is_superuser=True,
    )
    _add_membership(db_session, workspace, workspace_owner, ROLE_WORKSPACE_OWNER)
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=org_auditor.id,
            role="organization_auditor",
            active=True,
        )
    )
    db_session.commit()

    assert (
        role_for_organization(
            db_session,
            {"auth_type": "api_key"},
            organization,
            PERMISSION_WORKSPACE_ADMIN,
        )
        == ROLE_WORKSPACE_OWNER
    )
    assert (
        role_for_organization(
            db_session,
            {"auth_type": "session", "user_id": org_auditor.id},
            organization,
            PERMISSION_REPORTS_READ,
        )
        == ROLE_AUDITOR
    )
    assert (
        role_for_organization(
            db_session,
            {"auth_type": "session", "user_id": org_auditor.id},
            organization,
            PERMISSION_WORKSPACE_ADMIN,
        )
        == ""
    )
    assert (
        role_for_organization(
            db_session,
            {"auth_type": "session", "user_id": workspace_owner.id},
            organization,
            PERMISSION_WORKSPACE_ADMIN,
        )
        == ROLE_WORKSPACE_OWNER
    )
    assert (
        role_for_organization(
            db_session,
            {"auth_type": "session", "user_id": superuser.id},
            organization,
            PERMISSION_WORKSPACE_ADMIN,
        )
        == ROLE_WORKSPACE_OWNER
    )
    assert (
        role_for_organization(
            db_session,
            {"auth_type": "session", "user_id": superuser.id},
            other_organization,
            PERMISSION_WORKSPACE_ADMIN,
        )
        == ""
    )
    assert (
        role_for_organization(
            db_session,
            {"auth_type": "session", "user_id": 999999},
            organization,
            PERMISSION_REPORTS_READ,
        )
        == ""
    )

    assert (
        organization_ids_for_permission(
            db_session,
            {"auth_type": "api_key"},
            PERMISSION_WORKSPACE_ADMIN,
        )
        is None
    )
    assert (
        organization_ids_for_permission(
            db_session,
            {"auth_type": "session", "user_id": 999999},
            PERMISSION_WORKSPACE_ADMIN,
        )
        == []
    )
    assert organization_ids_for_permission(
        db_session,
        {"auth_type": "session", "user_id": org_auditor.id},
        PERMISSION_REPORTS_READ,
    ) == [organization.id]
    assert organization_ids_for_permission(
        db_session,
        {"auth_type": "session", "user_id": workspace_owner.id},
        PERMISSION_WORKSPACE_ADMIN,
    ) == [organization.id]
    assert organization_ids_for_permission(
        db_session,
        {"auth_type": "session", "user_id": superuser.id},
        PERMISSION_WORKSPACE_ADMIN,
    ) == [organization.id]


def test_workspace_operator_routes_enforce_membership_roles(test_app, db_session: Session):
    """Workspace-specific operator endpoints enforce membership permissions."""
    workspace = get_or_create_default_workspace(db_session)
    auditor = _add_user(db_session, "operator-auditor@example.com")
    analyst = _add_user(db_session, "operator-analyst@example.com")
    owner = _add_user(db_session, "operator-owner@example.com")
    outsider = _add_user(db_session, "operator-outsider@example.com")
    _add_membership(db_session, workspace, auditor, ROLE_AUDITOR)
    _add_membership(db_session, workspace, analyst, ROLE_ANALYST)
    _add_membership(db_session, workspace, owner, ROLE_WORKSPACE_OWNER)
    db_session.commit()

    with _client_as_user(test_app, db_session, auditor) as client:
        response = client.get(f"/api/v1/operator/workspaces/{workspace.id}")
        assert response.status_code == 200
        response = client.put(
            f"/api/v1/operator/workspaces/{workspace.id}/retention",
            json={
                "aggregate_reports_days": 400,
                "forensic_reports_days": 90,
                "tls_reports_days": 400,
            },
        )
        assert response.status_code == 403

    with _client_as_user(test_app, db_session, analyst) as client:
        response = client.get(f"/api/v1/operator/workspaces/{workspace.id}")
        assert response.status_code == 403

    with _client_as_user(test_app, db_session, outsider) as client:
        response = client.get(f"/api/v1/operator/workspaces/{workspace.id}")
        assert response.status_code == 403

    with _client_as_user(test_app, db_session, owner) as client:
        response = client.put(
            f"/api/v1/operator/workspaces/{workspace.id}/retention",
            json={
                "aggregate_reports_days": 365,
                "forensic_reports_days": 120,
                "tls_reports_days": 365,
            },
        )
        assert response.status_code == 200


def test_workspace_audit_logs_enforce_membership(test_app, db_session: Session):
    """Audit logs use the default workspace membership before returning data."""
    workspace = get_or_create_default_workspace(db_session)
    auditor = _add_user(db_session, "audit-member@example.com")
    outsider = _add_user(db_session, "audit-outsider@example.com")
    _add_membership(db_session, workspace, auditor, ROLE_AUDITOR)
    db_session.commit()

    with _client_as_user(test_app, db_session, auditor) as client:
        response = client.get("/api/v1/audit/logs")
        assert response.status_code == 200

    with _client_as_user(test_app, db_session, outsider) as client:
        response = client.get("/api/v1/audit/logs")
        assert response.status_code == 403


def test_workspace_audit_logs_respect_selected_workspace_header(
    authed_client: TestClient,
    db_session: Session,
):
    """Audit log reads only return events from the selected workspace."""
    default_workspace = get_or_create_default_workspace(db_session)
    selected_workspace = Workspace(
        slug="selected-audit-workspace",
        name="Selected Audit Workspace",
        active=True,
    )
    db_session.add(selected_workspace)
    db_session.flush()

    record_workspace_audit_log(
        db_session,
        workspace=default_workspace,
        action="default.event",
        entity_type="setting",
        entity_id="default",
        entity_name="Default",
        commit=False,
    )
    record_workspace_audit_log(
        db_session,
        workspace=selected_workspace,
        action="selected.event",
        entity_type="setting",
        entity_id="selected",
        entity_name="Selected",
        commit=True,
    )

    default_response = authed_client.get("/api/v1/audit/logs?entity_type=setting")
    selected_response = authed_client.get(
        "/api/v1/audit/logs?entity_type=setting",
        headers={"X-DMARQ-Workspace-ID": str(selected_workspace.id)},
    )

    assert default_response.status_code == 200
    assert [event["action"] for event in default_response.json()["audit"]] == ["default.event"]
    assert selected_response.status_code == 200
    assert [event["action"] for event in selected_response.json()["audit"]] == ["selected.event"]


def test_workspace_audit_logs_support_jwt_membership_and_defer_migration(
    test_app,
    db_session: Session,
):
    """Audit reads resolve JWT users and avoid migration side effects before authorization."""
    workspace = get_or_create_default_workspace(db_session)
    auditor = _add_user(db_session, "jwt-auditor@example.com", logto_id="jwt-auditor-sub")
    unscoped_domain = Domain(name="unscoped-audit.example", active=True)
    db_session.add(unscoped_domain)
    _add_membership(db_session, workspace, auditor, ROLE_AUDITOR)
    db_session.commit()
    db_session.refresh(unscoped_domain)

    with _client_as_jwt(test_app, db_session, "jwt-auditor-sub") as client:
        response = client.get("/api/v1/audit/logs")
        assert response.status_code == 200

    db_session.refresh(unscoped_domain)
    assert unscoped_domain.workspace_id == workspace.id

    unscoped_domain.workspace_id = None
    db_session.commit()

    with _client_as_jwt(test_app, db_session, "jwt-outsider-sub") as client:
        response = client.get("/api/v1/audit/logs")
        assert response.status_code == 403

    db_session.refresh(unscoped_domain)
    assert unscoped_domain.workspace_id is None


def test_workspace_audit_logs_deny_jwt_without_bootstrapping_default_workspace(
    test_app,
    db_session: Session,
):
    """JWT callers cannot create or migrate the default workspace before authorization."""
    unscoped_domain = Domain(name="unscoped-without-workspace.example", active=True)
    db_session.add(unscoped_domain)
    db_session.commit()

    with _client_as_jwt(test_app, db_session, "unknown-logto-sub") as client:
        response = client.get("/api/v1/audit/logs")
        assert response.status_code == 403

    assert db_session.query(Workspace).count() == 0
    db_session.refresh(unscoped_domain)
    assert unscoped_domain.workspace_id is None


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


def test_notification_setting_audit_respects_selected_workspace_header(
    authed_client: TestClient,
    db_session: Session,
):
    """Notification setting audit events land in the selected workspace."""
    get_or_create_default_workspace(db_session)
    selected_workspace = Workspace(
        slug="selected-setting-audit",
        name="Selected Setting Audit",
        active=True,
    )
    db_session.add(selected_workspace)
    db_session.commit()
    selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

    response = authed_client.put(
        "/api/v1/settings/notifications.apprise_enabled",
        json={"value": "true"},
        headers=selected_header,
    )
    default_audit = authed_client.get("/api/v1/audit/logs?entity_type=setting")
    selected_audit = authed_client.get(
        "/api/v1/audit/logs?entity_type=setting",
        headers=selected_header,
    )

    assert response.status_code == 200
    assert default_audit.status_code == 200
    assert default_audit.json()["audit"] == []
    assert selected_audit.status_code == 200
    assert [event["action"] for event in selected_audit.json()["audit"]] == ["setting.changed"]


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
