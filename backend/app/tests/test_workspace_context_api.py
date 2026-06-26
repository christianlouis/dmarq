from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import Organization
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspace_access import ROLE_ANALYST, ROLE_WORKSPACE_OWNER


@contextmanager
def _client_as_auth(test_app, db_session: Session, auth_context: dict):
    async def mock_admin_auth():
        return auth_context

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


def _add_workspace(
    db_session: Session,
    slug: str,
    organization: Organization,
    *,
    active: bool = True,
) -> Workspace:
    workspace = Workspace(
        slug=slug,
        name=slug.replace("-", " ").title(),
        organization_id=organization.id,
        active=active,
    )
    db_session.add(workspace)
    db_session.flush()
    return workspace


def _add_membership(
    db_session: Session,
    workspace: Workspace,
    user: User,
    role: str,
) -> None:
    db_session.add(
        WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role=role,
            active=True,
        )
    )
    db_session.flush()


def test_workspace_context_lists_only_user_visible_workspaces(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="context-org", name="Context Org", active=True)
    db_session.add(organization)
    db_session.flush()
    owned = _add_workspace(db_session, "owned-workspace", organization)
    audited = _add_workspace(db_session, "audited-workspace", organization)
    hidden = _add_workspace(db_session, "hidden-workspace", organization)
    user = User(email="context-user@example.com", is_active=True, is_verified=True)
    db_session.add(user)
    db_session.flush()
    _add_membership(db_session, owned, user, ROLE_WORKSPACE_OWNER)
    _add_membership(db_session, audited, user, ROLE_ANALYST)
    db_session.commit()

    with _client_as_auth(
        test_app,
        db_session,
        {"auth_type": "session", "user_id": user.id},
    ) as client:
        response = client.get("/api/v1/workspaces")

    assert response.status_code == 200
    data = response.json()
    slugs = [workspace["slug"] for workspace in data["workspaces"]]
    assert slugs == ["audited-workspace", "owned-workspace"]
    assert hidden.slug not in slugs
    roles = {workspace["slug"]: workspace["effective_role"] for workspace in data["workspaces"]}
    assert roles["owned-workspace"] == ROLE_WORKSPACE_OWNER
    assert roles["audited-workspace"] == ROLE_ANALYST
    assert data["default_workspace_id"] == audited.id


def test_workspace_context_platform_admin_sees_inactive_workspaces(
    test_app,
    db_session: Session,
):
    organization = Organization(slug="platform-context", name="Platform Context", active=True)
    db_session.add(organization)
    db_session.flush()
    active = _add_workspace(db_session, "active-client", organization)
    _add_workspace(db_session, "inactive-client", organization, active=False)
    db_session.commit()

    with _client_as_auth(test_app, db_session, {"auth_type": "api_key"}) as client:
        response = client.get("/api/v1/workspaces")

    assert response.status_code == 200
    data = response.json()
    rows = {workspace["slug"]: workspace for workspace in data["workspaces"]}
    assert rows["active-client"]["active"] is True
    assert rows["inactive-client"]["active"] is False
    assert rows["active-client"]["effective_role"] == ROLE_WORKSPACE_OWNER
    assert data["default_workspace_id"] == active.id
