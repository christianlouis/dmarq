from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints import memberships as memberships_endpoint
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import Entitlement, Organization, OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.workspace_access import (
    PERMISSION_AUDIT_READ,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_OPERATOR,
    ROLE_WORKSPACE_OWNER,
    role_for_organization,
    role_for_workspace,
)
from app.services.workspaces import get_or_create_default_workspace


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


def _add_user(db_session: Session, email: str, logto_id: str | None = None) -> User:
    user = User(
        email=email,
        logto_id=logto_id,
        is_active=True,
        is_verified=True,
        is_superuser=False,
    )
    db_session.add(user)
    db_session.flush()
    return user


def _add_workspace_membership(
    db_session: Session,
    workspace: Workspace,
    user: User,
    role: str,
) -> WorkspaceMembership:
    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role=role,
        active=True,
    )
    db_session.add(membership)
    db_session.flush()
    return membership


def test_require_user_seat_capacity_skips_non_consuming_memberships(
    db_session: Session,
    monkeypatch,
):
    organization = Organization(slug="seat-helper", name="Seat Helper")
    user = User(email="seat-helper@example.com", is_active=True, is_verified=True)
    inactive_user = User(
        email="inactive-seat-helper@example.com",
        is_active=False,
        is_verified=True,
    )
    db_session.add_all([organization, user, inactive_user])
    db_session.flush()
    calls: list[tuple[int, str]] = []

    monkeypatch.setattr(
        memberships_endpoint,
        "organization_user_has_active_seat",
        lambda _db, _organization, _user: _user.id == user.id,
    )
    monkeypatch.setattr(
        memberships_endpoint,
        "require_organization_plan_limit",
        lambda _db, checked_organization, metric: calls.append((checked_organization.id, metric)),
    )

    memberships_endpoint._require_user_seat_capacity(db_session, None, user, active=True)
    memberships_endpoint._require_user_seat_capacity(
        db_session,
        organization,
        user,
        active=False,
    )
    memberships_endpoint._require_user_seat_capacity(
        db_session,
        organization,
        inactive_user,
        active=True,
    )
    memberships_endpoint._require_user_seat_capacity(
        db_session,
        organization,
        user,
        active=True,
    )

    assert calls == []

    memberships_endpoint._require_user_seat_capacity(
        db_session,
        organization,
        inactive_user,
        active=True,
        activate_user=True,
    )

    assert calls == [(organization.id, "users")]


def test_workspace_membership_api_invites_updates_and_deactivates(
    test_app,
    db_session: Session,
):
    workspace = get_or_create_default_workspace(db_session)
    owner = _add_user(db_session, "workspace-owner@example.com")
    analyst = _add_user(db_session, "workspace-analyst@example.com")
    target = _add_user(db_session, "workspace-target@example.com")
    _add_workspace_membership(db_session, workspace, owner, ROLE_WORKSPACE_OWNER)
    _add_workspace_membership(db_session, workspace, analyst, ROLE_ANALYST)
    db_session.commit()

    with _client_as_user(test_app, db_session, analyst) as analyst_client:
        denied = analyst_client.put(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/{target.id}",
            json={"user_id": target.id, "role": ROLE_OPERATOR},
        )
        assert denied.status_code == 403

    with _client_as_user(test_app, db_session, owner) as owner_client:
        invited = owner_client.post(
            f"/api/v1/memberships/workspaces/{workspace.id}/invites",
            json={"email": "New.Member@Example.com", "role": ROLE_ANALYST},
        )
        assert invited.status_code == 200
        assert invited.json()["user"]["email"] == "new.member@example.com"
        assert invited.json()["role"] == ROLE_ANALYST

        updated = owner_client.put(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/{target.id}",
            json={"user_id": target.id, "role": ROLE_OPERATOR},
        )
        assert updated.status_code == 200
        assert updated.json()["role"] == ROLE_OPERATOR

        listed = owner_client.get(f"/api/v1/memberships/workspaces/{workspace.id}")
        assert listed.status_code == 200
        emails = {row["user"]["email"] for row in listed.json()["memberships"]}
        assert {"workspace-owner@example.com", "new.member@example.com"} <= emails

        inactive_before_delete = owner_client.put(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/{target.id}",
            json={"user_id": target.id, "role": ROLE_AUDITOR, "active": False},
        )
        assert inactive_before_delete.status_code == 200
        assert inactive_before_delete.json()["active"] is False

        active_only = owner_client.get(f"/api/v1/memberships/workspaces/{workspace.id}")
        assert active_only.status_code == 200
        assert "workspace-target@example.com" not in {
            row["user"]["email"] for row in active_only.json()["memberships"]
        }

        with_inactive = owner_client.get(
            f"/api/v1/memberships/workspaces/{workspace.id}?include_inactive=true"
        )
        assert with_inactive.status_code == 200
        assert "workspace-target@example.com" in {
            row["user"]["email"] for row in with_inactive.json()["memberships"]
        }

        deactivated = owner_client.delete(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/{target.id}"
        )
        assert deactivated.status_code == 200
        assert deactivated.json()["active"] is False

        missing_membership = owner_client.delete(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/999999"
        )
        assert missing_membership.status_code == 404

    assert (
        role_for_workspace(
            db_session,
            {"auth_type": "session", "user_id": target.id},
            workspace,
        )
        == ""
    )
    audit_actions = {row.action for row in db_session.query(WorkspaceAuditLog).all()}
    assert "workspace.membership_upserted" in audit_actions
    assert "workspace.membership_deactivated" in audit_actions


def test_workspace_membership_api_validates_payload_and_invite_identity_conflicts(
    test_app,
    db_session: Session,
):
    workspace = get_or_create_default_workspace(db_session)
    owner = _add_user(db_session, "workspace-owner-conflict@example.com")
    email_user = _add_user(db_session, "conflict-email@example.com")
    logto_user = _add_user(db_session, "conflict-logto@example.com", logto_id="logto-conflict")
    _add_workspace_membership(db_session, workspace, owner, ROLE_WORKSPACE_OWNER)
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        mismatched_user = owner_client.put(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/{email_user.id}",
            json={"user_id": logto_user.id, "role": ROLE_ANALYST},
        )
        assert mismatched_user.status_code == 422

        invalid_role = owner_client.put(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/{email_user.id}",
            json={"user_id": email_user.id, "role": "root"},
        )
        assert invalid_role.status_code == 422

        conflict = owner_client.post(
            f"/api/v1/memberships/workspaces/{workspace.id}/invites",
            json={
                "email": "conflict-email@example.com",
                "role": ROLE_ANALYST,
                "logto_id": "logto-conflict",
            },
        )
        assert conflict.status_code == 409

        linked = owner_client.post(
            f"/api/v1/memberships/workspaces/{workspace.id}/invites",
            json={
                "email": "legacy-logto@example.com",
                "role": ROLE_ANALYST,
                "logto_id": "logto-conflict",
            },
        )
        assert linked.status_code == 200
        assert linked.json()["user"]["id"] == logto_user.id
        assert linked.json()["user"]["email"] == "legacy-logto@example.com"


def test_workspace_membership_invite_requires_sso_entitlement_for_logto_identity(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="workspace-sso-disabled", name="Workspace SSO Disabled")
    workspace = Workspace(
        slug="workspace-sso-disabled-main",
        name="Workspace SSO Disabled Main",
        organization=organization,
        active=True,
    )
    owner = _add_user(db_session, "workspace-sso-owner@example.com")
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="sso",
                value="false",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    _add_workspace_membership(db_session, workspace, owner, ROLE_WORKSPACE_OWNER)
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        blocked = owner_client.post(
            f"/api/v1/memberships/workspaces/{workspace.id}/invites",
            json={
                "email": "workspace-logto-disabled@example.com",
                "role": ROLE_ANALYST,
                "logto_id": "logto-workspace-disabled",
            },
        )
        assert blocked.status_code == 402
        detail = blocked.json()["detail"]
        assert detail["code"] == "feature_not_included"
        assert detail["feature"] == "sso"
        assert detail["can_export"] is True

        email_only = owner_client.post(
            f"/api/v1/memberships/workspaces/{workspace.id}/invites",
            json={
                "email": "workspace-email-only@example.com",
                "role": ROLE_ANALYST,
            },
        )
        assert email_only.status_code == 200
        assert email_only.json()["user"]["logto_id"] is None

    assert (
        db_session.query(User).filter(User.email == "workspace-logto-disabled@example.com").first()
        is None
    )
    assert db_session.query(User).filter(User.email == "workspace-email-only@example.com").first()


def test_workspace_membership_invite_respects_user_seat_plan_limit(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="workspace-seat-limit", name="Workspace Seat Limit")
    workspace = Workspace(
        slug="workspace-seat-limit-main",
        name="Workspace Seat Limit Main",
        organization=organization,
        active=True,
    )
    owner = _add_user(db_session, "workspace-seat-owner@example.com")
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="users",
                value="1",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    _add_workspace_membership(db_session, workspace, owner, ROLE_WORKSPACE_OWNER)
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        response = owner_client.post(
            f"/api/v1/memberships/workspaces/{workspace.id}/invites",
            json={"email": "workspace-seat-new@example.com", "role": ROLE_ANALYST},
        )

    assert response.status_code == 402
    detail = response.json()["detail"]
    assert detail["code"] == "plan_limit_exceeded"
    assert detail["metric"] == "users"
    assert detail["current"] == 1
    assert detail["limit"] == 1
    assert detail["can_export"] is True
    assert (
        db_session.query(User).filter(User.email == "workspace-seat-new@example.com").first()
        is None
    )
    assert db_session.query(WorkspaceMembership).count() == 1


def test_workspace_membership_allows_existing_active_seat_with_full_quota(
    test_app,
    db_session: Session,
):
    organization = Organization(
        slug="workspace-seat-reuse",
        name="Workspace Seat Reuse",
        active=True,
    )
    workspace = Workspace(
        slug="workspace-seat-reuse-main",
        name="Workspace Seat Reuse Main",
        organization=organization,
        active=True,
    )
    owner = _add_user(db_session, "workspace-seat-reuse-owner@example.com")
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="users",
                value="1",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    _add_workspace_membership(db_session, workspace, owner, ROLE_WORKSPACE_OWNER)
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        response = owner_client.put(
            f"/api/v1/memberships/workspaces/{workspace.id}/users/{owner.id}",
            json={"user_id": owner.id, "role": ROLE_ANALYST},
        )

    assert response.status_code == 200
    assert response.json()["role"] == ROLE_ANALYST
    assert db_session.query(WorkspaceMembership).count() == 1


def test_organization_membership_api_audits_and_deactivates(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="membership-org", name="Membership Org", active=True)
    db_session.add(organization)
    db_session.flush()
    workspace = Workspace(
        slug="membership-org-workspace",
        name="Membership Org Workspace",
        organization_id=organization.id,
        active=True,
    )
    owner = _add_user(db_session, "organization-owner@example.com")
    target = _add_user(db_session, "organization-target@example.com")
    db_session.add(workspace)
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        invited = owner_client.post(
            f"/api/v1/memberships/organizations/{organization.id}/invites",
            json={
                "email": "Org.Member@Example.com",
                "role": "organization_auditor",
                "logto_id": "logto-org-member",
            },
        )
        assert invited.status_code == 200
        assert invited.json()["user"]["logto_id"] == "logto-org-member"

        updated = owner_client.put(
            f"/api/v1/memberships/organizations/{organization.id}/users/{target.id}",
            json={"user_id": target.id, "role": "organization_auditor"},
        )
        assert updated.status_code == 200
        assert updated.json()["role"] == "organization_auditor"

        updated_again = owner_client.put(
            f"/api/v1/memberships/organizations/{organization.id}/users/{target.id}",
            json={"user_id": target.id, "role": "billing_admin"},
        )
        assert updated_again.status_code == 200
        assert updated_again.json()["role"] == "billing_admin"

        listed = owner_client.get(f"/api/v1/memberships/organizations/{organization.id}")
        assert listed.status_code == 200
        assert len(listed.json()["memberships"]) == 3

        deactivated = owner_client.delete(
            f"/api/v1/memberships/organizations/{organization.id}/users/{target.id}"
        )
        assert deactivated.status_code == 200
        assert deactivated.json()["active"] is False

    assert (
        role_for_organization(
            db_session,
            {"auth_type": "session", "user_id": target.id},
            organization,
            PERMISSION_AUDIT_READ,
        )
        == ""
    )
    audit_actions = {row.action for row in db_session.query(WorkspaceAuditLog).all()}
    assert "organization.membership_upserted" in audit_actions
    assert "organization.membership_deactivated" in audit_actions


def test_organization_membership_invite_requires_sso_entitlement_for_logto_identity(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="organization-sso-disabled", name="Organization SSO Disabled")
    workspace = Workspace(
        slug="organization-sso-disabled-workspace",
        name="Organization SSO Disabled Workspace",
        organization=organization,
        active=True,
    )
    owner = _add_user(db_session, "organization-sso-owner@example.com")
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="sso",
                value="false",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        blocked = owner_client.post(
            f"/api/v1/memberships/organizations/{organization.id}/invites",
            json={
                "email": "organization-logto-disabled@example.com",
                "role": "organization_auditor",
                "logto_id": "logto-organization-disabled",
            },
        )
        assert blocked.status_code == 402
        detail = blocked.json()["detail"]
        assert detail["code"] == "feature_not_included"
        assert detail["feature"] == "sso"
        assert detail["can_export"] is True

        email_only = owner_client.post(
            f"/api/v1/memberships/organizations/{organization.id}/invites",
            json={
                "email": "organization-email-only@example.com",
                "role": "organization_auditor",
            },
        )
        assert email_only.status_code == 200
        assert email_only.json()["user"]["logto_id"] is None

    assert (
        db_session.query(User)
        .filter(User.email == "organization-logto-disabled@example.com")
        .first()
        is None
    )
    assert (
        db_session.query(User).filter(User.email == "organization-email-only@example.com").first()
    )


def test_organization_membership_invite_respects_user_seat_plan_limit(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="organization-seat-limit", name="Organization Seat Limit")
    workspace = Workspace(
        slug="organization-seat-limit-workspace",
        name="Organization Seat Limit Workspace",
        organization=organization,
        active=True,
    )
    owner = _add_user(db_session, "organization-seat-owner@example.com")
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="users",
                value="1",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        response = owner_client.post(
            f"/api/v1/memberships/organizations/{organization.id}/invites",
            json={"email": "organization-seat-new@example.com", "role": "organization_auditor"},
        )

    assert response.status_code == 402
    detail = response.json()["detail"]
    assert detail["code"] == "plan_limit_exceeded"
    assert detail["metric"] == "users"
    assert detail["current"] == 1
    assert detail["limit"] == 1
    assert (
        db_session.query(User).filter(User.email == "organization-seat-new@example.com").first()
        is None
    )
    assert db_session.query(OrganizationMembership).count() == 1


def test_organization_invite_existing_inactive_user_respects_seat_limit(
    test_app,
    db_session: Session,
):
    organization = Organization(
        slug="organization-inactive-seat-limit",
        name="Organization Inactive Seat Limit",
    )
    workspace = Workspace(
        slug="organization-inactive-seat-limit-workspace",
        name="Organization Inactive Seat Limit Workspace",
        organization=organization,
        active=True,
    )
    owner = _add_user(db_session, "organization-inactive-seat-owner@example.com")
    inactive = User(
        email="organization-inactive-seat-user@example.com",
        is_active=False,
        is_verified=False,
        is_superuser=False,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            inactive,
            Entitlement(
                organization=organization,
                key="users",
                value="1",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        response = owner_client.post(
            f"/api/v1/memberships/organizations/{organization.id}/invites",
            json={
                "email": "organization-inactive-seat-user@example.com",
                "role": "organization_auditor",
                "logto_id": "logto-inactive-seat",
                "full_name": "Inactive Seat User",
            },
        )

    assert response.status_code == 402
    detail = response.json()["detail"]
    assert detail["code"] == "plan_limit_exceeded"
    assert detail["metric"] == "users"
    db_session.refresh(inactive)
    assert inactive.is_active is False
    assert inactive.logto_id is None
    assert inactive.full_name is None
    assert db_session.query(OrganizationMembership).count() == 1

    with _client_as_user(test_app, db_session, owner) as owner_client:
        direct_response = owner_client.put(
            f"/api/v1/memberships/organizations/{organization.id}/users/{inactive.id}",
            json={"user_id": inactive.id, "role": "organization_auditor"},
        )

    assert direct_response.status_code == 200
    db_session.refresh(inactive)
    assert inactive.is_active is False
    assert db_session.query(OrganizationMembership).count() == 2


def test_organization_membership_api_validates_payload_and_missing_membership(
    test_app,
    db_session: Session,
):
    organization = Organization(
        slug="organization-membership-validation",
        name="Organization Membership Validation",
        active=True,
    )
    workspace = Workspace(
        slug="organization-membership-validation-workspace",
        name="Organization Membership Validation Workspace",
        organization=organization,
        active=True,
    )
    owner = _add_user(db_session, "organization-validation-owner@example.com")
    target = _add_user(db_session, "organization-validation-target@example.com")
    db_session.add_all([organization, workspace])
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        mismatched_user = owner_client.put(
            f"/api/v1/memberships/organizations/{organization.id}/users/{target.id}",
            json={"user_id": owner.id, "role": "organization_auditor"},
        )
        assert mismatched_user.status_code == 422

        missing_membership = owner_client.delete(
            f"/api/v1/memberships/organizations/{organization.id}/users/{target.id}"
        )
        assert missing_membership.status_code == 404


def test_organization_membership_api_reuses_inactive_audit_workspace(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="inactive-audit-org", name="Inactive Audit Org", active=True)
    db_session.add(organization)
    db_session.flush()
    inactive_workspace = Workspace(
        slug="inactive-audit-workspace",
        name="Inactive Audit Workspace",
        organization_id=organization.id,
        active=False,
    )
    owner = _add_user(db_session, "inactive-audit-owner@example.com")
    target = _add_user(db_session, "inactive-audit-target@example.com")
    db_session.add(inactive_workspace)
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        updated = owner_client.put(
            f"/api/v1/memberships/organizations/{organization.id}/users/{target.id}",
            json={"user_id": target.id, "role": "organization_auditor"},
        )
        assert updated.status_code == 200

    assert (
        db_session.query(Workspace).filter(Workspace.organization_id == organization.id).count()
        == 1
    )
    audit = (
        db_session.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.action == "organization.membership_upserted")
        .one()
    )
    assert audit.workspace_id == inactive_workspace.id


def test_organization_membership_api_requires_audit_workspace(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="missing-audit-org", name="Missing Audit Org", active=True)
    db_session.add(organization)
    db_session.flush()
    owner = _add_user(db_session, "missing-audit-owner@example.com")
    target = _add_user(db_session, "missing-audit-target@example.com")
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
    )
    db_session.commit()

    with _client_as_user(test_app, db_session, owner) as owner_client:
        response = owner_client.put(
            f"/api/v1/memberships/organizations/{organization.id}/users/{target.id}",
            json={"user_id": target.id, "role": "organization_auditor"},
        )
        assert response.status_code == 409
