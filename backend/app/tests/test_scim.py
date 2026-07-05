from fastapi.testclient import TestClient

from app.models.api_token import APIToken
from app.models.organization import Organization
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.api_tokens import (
    ALL_API_TOKEN_SCOPES,
    SCIM_READ_SCOPE,
    SCIM_WRITE_SCOPE,
    create_api_token,
)
from app.services.workspaces import get_or_create_default_workspace


def _scim_token(db_session, *, scopes=None, workspace_id=None):
    workspace = get_or_create_default_workspace(db_session)
    return create_api_token(
        db_session,
        name="scim",
        scopes=scopes or [SCIM_WRITE_SCOPE],
        workspace_id=workspace_id if workspace_id is not None else workspace.id,
        allowed_scopes=ALL_API_TOKEN_SCOPES,
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


def test_scim_patch_and_delete_deactivate_user_and_membership(client: TestClient, db_session):
    """SCIM deprovisioning keeps history and marks the local account inactive."""
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
            "Operations": [{"op": "Replace", "path": "active", "value": False}],
        },
    )

    assert patched.status_code == 200
    assert patched.json()["active"] is False
    user = db_session.query(User).filter(User.id == int(user_id)).one()
    membership = db_session.query(WorkspaceMembership).filter_by(user_id=user.id).one()
    assert user.is_active is False
    assert membership.active is False

    deleted = client.delete(
        f"/api/v1/scim/v2/Users/{user_id}",
        headers={"X-API-Key": token.secret},
    )

    assert deleted.status_code == 200
    actions = [row.action for row in db_session.query(WorkspaceAuditLog).all()]
    assert actions.count("scim.user_deactivated") == 2


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
