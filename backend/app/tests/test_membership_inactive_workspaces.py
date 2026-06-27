from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspace_access import ROLE_WORKSPACE_OWNER


def _inactive_workspace(db_session: Session) -> Workspace:
    workspace = Workspace(
        slug="inactive-membership-workspace",
        name="Inactive Membership Workspace",
        active=False,
    )
    db_session.add(workspace)
    db_session.flush()
    return workspace


def _user(db_session: Session, email: str) -> User:
    user = User(email=email, is_active=True, is_verified=True)
    db_session.add(user)
    db_session.flush()
    return user


def test_workspace_membership_update_blocks_inactive_workspace_mutation(
    authed_client: TestClient,
    db_session: Session,
):
    workspace = _inactive_workspace(db_session)
    user = _user(db_session, "inactive-update@example.com")
    db_session.commit()

    response = authed_client.put(
        f"/api/v1/memberships/workspaces/{workspace.id}/users/{user.id}",
        json={"user_id": user.id, "role": ROLE_WORKSPACE_OWNER, "active": True},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Inactive workspace cannot be modified"
    assert db_session.query(WorkspaceMembership).count() == 0


def test_workspace_membership_invite_blocks_inactive_workspace_mutation(
    authed_client: TestClient,
    db_session: Session,
):
    workspace = _inactive_workspace(db_session)
    db_session.commit()

    response = authed_client.post(
        f"/api/v1/memberships/workspaces/{workspace.id}/invites",
        json={"email": "inactive-invite@example.com", "role": ROLE_WORKSPACE_OWNER},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Inactive workspace cannot be modified"
    assert (
        db_session.query(User).filter(User.email == "inactive-invite@example.com").first() is None
    )


def test_workspace_membership_deactivate_blocks_inactive_workspace_mutation(
    authed_client: TestClient,
    db_session: Session,
):
    workspace = _inactive_workspace(db_session)
    user = _user(db_session, "inactive-deactivate@example.com")
    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role=ROLE_WORKSPACE_OWNER,
        active=True,
    )
    db_session.add(membership)
    db_session.commit()

    response = authed_client.delete(
        f"/api/v1/memberships/workspaces/{workspace.id}/users/{user.id}",
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Inactive workspace cannot be modified"
    db_session.refresh(membership)
    assert membership.active is True


def test_workspace_membership_list_allows_inactive_workspace_read(
    authed_client: TestClient,
    db_session: Session,
):
    workspace = _inactive_workspace(db_session)
    user = _user(db_session, "inactive-list@example.com")
    db_session.add(
        WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role=ROLE_WORKSPACE_OWNER,
            active=True,
        )
    )
    db_session.commit()

    response = authed_client.get(f"/api/v1/memberships/workspaces/{workspace.id}")

    assert response.status_code == 200
    assert response.json()["memberships"][0]["user"]["email"] == user.email
