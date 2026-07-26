"""Workspace preference tests for the opt-in guided dashboard."""

from contextlib import contextmanager
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspace_access import ROLE_ANALYST


@contextmanager
def _client_as_auth(test_app, db_session, auth_context):
    async def mock_admin_auth():
        return auth_context

    def override_get_db():
        yield db_session

    original_overrides = dict(test_app.dependency_overrides)
    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    try:
        with TestClient(test_app) as client:
            yield client
    finally:
        test_app.dependency_overrides = original_overrides


def test_guided_dashboard_stays_disabled_when_the_deployment_flag_is_off(
    authed_client: TestClient,
    db_session,
):
    workspace = Workspace(
        slug="guidance-off",
        name="Guidance off",
        guided_mail_health_enabled=True,
    )
    db_session.add(workspace)
    db_session.commit()

    response = authed_client.get(
        "/api/v1/workspaces/guidance",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    assert response.json()["available"] is False
    assert response.json()["enabled"] is False
    assert response.json()["requested_enabled"] is True


def test_guided_dashboard_preference_can_be_opted_into_per_workspace(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    workspace = Workspace(slug="guidance-on", name="Guidance on")
    db_session.add(workspace)
    db_session.commit()
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.workspaces.get_settings",
        lambda: SimpleNamespace(GUIDED_MAIL_HEALTH_UI_ENABLED=True),
    )

    response = authed_client.put(
        "/api/v1/workspaces/guidance",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
        json={"enabled": True, "depth": "guided", "context": "watch"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "available": True,
        "enabled": True,
        "requested_enabled": True,
        "depth": "guided",
        "context": "watch",
        "goal": None,
        "interview_completed": False,
    }
    db_session.refresh(workspace)
    assert workspace.guided_mail_health_enabled is True


def test_guidance_profile_records_a_problem_first_goal_without_enabling_the_dashboard(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    workspace = Workspace(slug="guidance-goal", name="Guidance goal")
    db_session.add(workspace)
    db_session.commit()
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.workspaces.get_settings",
        lambda: SimpleNamespace(GUIDED_MAIL_HEALTH_UI_ENABLED=True),
    )

    response = authed_client.put(
        "/api/v1/workspaces/guidance/profile",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
        json={"goal": "reports_confusing", "depth": "guided"},
    )

    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert response.json()["goal"] == "reports_confusing"
    assert response.json()["interview_completed"] is True
    db_session.refresh(workspace)
    assert workspace.mail_health_goal == "reports_confusing"
    assert workspace.guidance_interview_completed_at is not None


def test_analysts_can_read_but_cannot_change_guidance_preferences(test_app, db_session):
    workspace = Workspace(slug="guidance-analyst", name="Guidance analyst")
    user = User(email="guidance-analyst@example.com", is_active=True, is_verified=True)
    db_session.add_all([workspace, user])
    db_session.flush()
    db_session.add(
        WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role=ROLE_ANALYST,
            active=True,
        )
    )
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}

    with _client_as_auth(test_app, db_session, {"auth_type": "session", "user_id": user.id}) as client:
        read_response = client.get("/api/v1/workspaces/guidance", headers=headers)
        preference_response = client.put(
            "/api/v1/workspaces/guidance",
            headers=headers,
            json={"enabled": True, "depth": "guided", "context": "watch"},
        )
        profile_response = client.put(
            "/api/v1/workspaces/guidance/profile",
            headers=headers,
            json={"goal": "curious", "depth": "guided"},
        )

    assert read_response.status_code == 200
    assert preference_response.status_code == 403
    assert profile_response.status_code == 403
