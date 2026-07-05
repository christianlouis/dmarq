import pytest
from fastapi.testclient import TestClient

from app.models.api_token import APIToken
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.api_tokens import (
    ALL_API_TOKEN_SCOPES,
    READ_REPORTS_SCOPE,
    SCIM_READ_SCOPE,
    SCIM_WRITE_SCOPE,
    create_api_token,
)
from app.services.workspaces import get_or_create_default_workspace


def _scim_token(db_session, *, scopes=None, workspace_id=None, global_token=False):
    workspace = get_or_create_default_workspace(db_session)
    if global_token:
        token_workspace_id = None
    else:
        token_workspace_id = workspace_id if workspace_id is not None else workspace.id
    return create_api_token(
        db_session,
        name="scim",
        scopes=scopes or [SCIM_WRITE_SCOPE],
        workspace_id=token_workspace_id,
        allowed_scopes=ALL_API_TOKEN_SCOPES,
        global_token=global_token,
    )


def test_scim_create_user_maps_workspace_role_and_audits(client: TestClient, db_session):
    """SCIM creates a local identity, assigns a workspace role, and writes audit evidence."""
    token = _scim_token(db_session)

    response = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={
            "userName": "SCIM.User@example.com",
            "externalId": "idp-user-123",
            "active": True,
            "name": {"formatted": "SCIM User"},
            "groups": [{"display": "operator"}],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["userName"] == "scim.user@example.com"
    assert body["externalId"] == "idp-user-123"
    assert body["groups"][0]["value"] == "operator"

    user = db_session.query(User).filter(User.email == "scim.user@example.com").one()
    assert user.logto_id == "idp-user-123"
    assert user.full_name == "SCIM User"
    assert user.is_active is True
    membership = db_session.query(WorkspaceMembership).filter_by(user_id=user.id).one()
    assert membership.role == "operator"
    assert membership.active is True
    audit = db_session.query(WorkspaceAuditLog).filter_by(action="scim.user_created").one()
    assert audit.entity_name == "scim.user@example.com"
    assert "idp-user-123" not in (audit.details or "")

    api_token = db_session.query(APIToken).filter_by(id=token.token.id).one()
    assert api_token.usage_count == 1


def test_scim_patch_and_delete_deactivate_workspace_membership(client: TestClient, db_session):
    """SCIM deprovisioning only deactivates the token workspace membership."""
    token = _scim_token(db_session)
    created = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={"userName": "deprovision@example.com", "groups": [{"value": "auditor"}]},
    )
    user_id = created.json()["id"]

    patched = client.patch(
        f"/api/v1/scim/v2/Users/{user_id}",
        headers={"X-API-Key": token.secret},
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
        },
    )

    assert patched.status_code == 200
    assert patched.json()["active"] is False
    user = db_session.query(User).filter(User.id == int(user_id)).one()
    membership = db_session.query(WorkspaceMembership).filter_by(user_id=user.id).one()
    assert user.is_active is True
    assert membership.active is False

    deleted = client.delete(
        f"/api/v1/scim/v2/Users/{user_id}",
        headers={"X-API-Key": token.secret},
    )

    assert deleted.status_code == 200
    actions = [row.action for row in db_session.query(WorkspaceAuditLog).all()]
    assert actions.count("scim.user_deactivated") == 2


def test_scim_create_existing_user_returns_ok(client: TestClient, db_session):
    """POST returns 200 when SCIM updates an existing workspace user."""
    token = _scim_token(db_session)
    created = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={"userName": "existing@example.com", "externalId": "existing-id"},
    )

    updated = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={
            "userName": "existing@example.com",
            "externalId": "existing-id",
            "name": {"formatted": "Existing User"},
            "groups": [{"value": "operator"}],
        },
    )

    assert created.status_code == 201
    assert updated.status_code == 200
    assert updated.json()["id"] == created.json()["id"]
    user = db_session.query(User).filter(User.email == "existing@example.com").one()
    membership = db_session.query(WorkspaceMembership).filter_by(user_id=user.id).one()
    assert user.full_name == "Existing User"
    assert membership.role == "operator"


def test_scim_create_does_not_update_user_from_another_workspace(
    client: TestClient, db_session
):
    """SCIM identity matching is scoped to the token workspace."""
    first = get_or_create_default_workspace(db_session)
    second = Workspace(slug="scim-second", name="SCIM Second")
    db_session.add(second)
    db_session.commit()
    first_token = _scim_token(db_session, workspace_id=first.id)
    second_token = _scim_token(db_session, workspace_id=second.id)
    created = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": first_token.secret},
        json={"userName": "shared@example.com", "externalId": "shared-id"},
    )

    conflicting = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": second_token.secret},
        json={"userName": "shared@example.com", "externalId": "shared-id"},
    )

    assert created.status_code == 201
    assert conflicting.status_code == 409
    user = db_session.query(User).filter(User.email == "shared@example.com").one()
    assert db_session.query(WorkspaceMembership).filter_by(user_id=user.id).count() == 1


def test_scim_read_scope_can_list_but_not_write(client: TestClient, db_session):
    """Read-only SCIM tokens can inspect directory state but cannot mutate users."""
    token = _scim_token(db_session, scopes=[SCIM_READ_SCOPE])

    list_response = client.get("/api/v1/scim/v2/Users", headers={"X-API-Key": token.secret})
    write_response = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={"userName": "readonly@example.com"},
    )

    assert list_response.status_code == 200
    assert write_response.status_code == 403


def test_scim_token_is_workspace_scoped(client: TestClient, db_session):
    """A SCIM token only exposes users in its own workspace."""
    organization = Organization(slug="scim-org", name="SCIM Org")
    db_session.add(organization)
    db_session.flush()
    first = get_or_create_default_workspace(db_session)
    first.organization_id = organization.id
    second = Workspace(slug="scim-other", name="SCIM Other", organization_id=organization.id)
    db_session.add(second)
    db_session.commit()
    first_token = _scim_token(db_session, workspace_id=first.id)
    second_token = _scim_token(db_session, workspace_id=second.id)

    client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": first_token.secret},
        json={"userName": "first@example.com", "groups": [{"display": "workspace_owner"}]},
    )

    first_list = client.get("/api/v1/scim/v2/Users", headers={"X-API-Key": first_token.secret})
    second_list = client.get("/api/v1/scim/v2/Users", headers={"X-API-Key": second_token.secret})

    assert first_list.json()["totalResults"] == 1
    assert second_list.json()["totalResults"] == 0


def test_scim_rejects_unscoped_api_token(client: TestClient, db_session):
    """SCIM requires an explicit workspace binding instead of migrating legacy rows."""
    token = _scim_token(db_session, workspace_id=None, global_token=True)

    response = client.get("/api/v1/scim/v2/Users", headers={"X-API-Key": token.secret})

    assert response.status_code == 403
    assert response.json()["detail"] == "SCIM token must be bound to a workspace"


def test_scim_workspace_role_does_not_create_organization_membership(
    client: TestClient, db_session
):
    """Workspace roles must not be written into organization membership rows."""
    organization = Organization(slug="scim-org-role", name="SCIM Org Role")
    db_session.add(organization)
    db_session.flush()
    workspace = get_or_create_default_workspace(db_session)
    workspace.organization_id = organization.id
    db_session.commit()
    token = _scim_token(db_session, workspace_id=workspace.id)

    response = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={"userName": "workspace-role@example.com", "groups": [{"display": "operator"}]},
    )

    assert response.status_code == 201
    user = db_session.query(User).filter(User.email == "workspace-role@example.com").one()
    assert db_session.query(OrganizationMembership).filter_by(user_id=user.id).first() is None


def test_scim_explicit_org_role_creates_organization_membership(client: TestClient, db_session):
    """Only explicit SCIM org role groups write organization membership rows."""
    organization = Organization(slug="scim-explicit-org", name="SCIM Explicit Org")
    db_session.add(organization)
    db_session.flush()
    workspace = get_or_create_default_workspace(db_session)
    workspace.organization_id = organization.id
    db_session.commit()
    token = _scim_token(db_session, workspace_id=workspace.id)

    response = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={
            "userName": "org-role@example.com",
            "groups": [{"display": "operator"}, {"display": "org:billing_admin"}],
        },
    )

    assert response.status_code == 201
    user = db_session.query(User).filter(User.email == "org-role@example.com").one()
    org_membership = db_session.query(OrganizationMembership).filter_by(user_id=user.id).one()
    assert org_membership.role == "billing_admin"


def test_scim_replace_rejects_payload_for_different_user(client: TestClient, db_session):
    """PUT /Users/{id} must not update a user selected by payload identifiers."""
    token = _scim_token(db_session)
    first = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={"userName": "path-user@example.com", "externalId": "path-user"},
    )
    second = client.post(
        "/api/v1/scim/v2/Users",
        headers={"X-API-Key": token.secret},
        json={"userName": "payload-user@example.com", "externalId": "payload-user"},
    )

    response = client.put(
        f"/api/v1/scim/v2/Users/{first.json()['id']}",
        headers={"X-API-Key": token.secret},
        json={
            "userName": "payload-user@example.com",
            "externalId": "payload-user",
            "active": True,
        },
    )

    assert second.status_code == 201
    assert response.status_code == 409


def test_scim_service_provider_config_documents_api_key_auth(client: TestClient):
    """The SCIM discovery metadata reflects the X-API-Key authentication contract."""
    response = client.get("/api/v1/scim/v2/ServiceProviderConfig")

    assert response.status_code == 200
    auth_scheme = response.json()["authenticationSchemes"][0]
    assert auth_scheme["type"] == "apikey"
    assert auth_scheme["name"] == "X-API-Key"


def test_scim_scopes_cannot_mix_with_public_scopes(db_session):
    """SCIM tokens must not share a credential with unrelated API scopes."""
    with pytest.raises(ValueError, match="SCIM API token scopes"):
        create_api_token(
            db_session,
            name="mixed-scim",
            scopes=[SCIM_READ_SCOPE, READ_REPORTS_SCOPE],
            allowed_scopes=ALL_API_TOKEN_SCOPES,
        )
