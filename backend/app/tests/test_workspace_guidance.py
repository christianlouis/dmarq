"""Workspace preference tests for the opt-in guided dashboard."""

from contextlib import contextmanager
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.user import User
from app.models.workspace import Workspace
from app.services.mail_health_incidents import record_mail_health_assessment
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
        "preference_scope": "workspace",
        "goal": None,
        "notification_posture": "actionable_only",
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


def test_user_guidance_preference_overrides_workspace_default_without_changing_it(test_app, db_session):
    workspace = Workspace(
        slug="guidance-personal",
        name="Guidance personal",
        guided_mail_health_enabled=True,
        guidance_depth="standard",
        guidance_context="watch",
    )
    user = User(email="guidance-personal@example.com", is_active=True, is_verified=True)
    db_session.add_all([workspace, user])
    db_session.flush()
    db_session.add(
        WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role="workspace_owner",
            active=True,
        )
    )
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}

    with _client_as_auth(test_app, db_session, {"auth_type": "session", "user_id": user.id}) as client:
        response = client.put(
            "/api/v1/workspaces/guidance",
            headers=headers,
            json={"enabled": True, "depth": "expert", "context": "evidence"},
        )
        read_response = client.get("/api/v1/workspaces/guidance", headers=headers)

    assert response.status_code == 200
    assert read_response.status_code == 200
    assert read_response.json()["depth"] == "expert"
    assert read_response.json()["context"] == "evidence"
    assert read_response.json()["preference_scope"] == "user"
    db_session.refresh(workspace)
    db_session.refresh(user)
    assert workspace.guidance_depth == "standard"
    assert workspace.guidance_context == "watch"
    assert user.guidance_depth == "expert"
    assert user.guidance_context == "evidence"


def test_notification_posture_and_incident_actions_are_workspace_scoped(authed_client, db_session):
    workspace = Workspace(slug="calm-api", name="Calm API")
    db_session.add(workspace)
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}

    posture_response = authed_client.put(
        "/api/v1/workspaces/guidance/notification-posture",
        headers=headers,
        json={"posture": "disabled"},
    )
    invalid_posture = authed_client.put(
        "/api/v1/workspaces/guidance/notification-posture",
        headers=headers,
        json={"posture": "noisy"},
    )
    created = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment={
            "outcome": "action_required",
            "domain": "example.test",
            "intended_mail_impact": "likely_affected",
            "urgency": "timely",
            "confidence": "High",
            "assessment_version": "v1",
            "next_action": {"href": "/domains/example.test#sending-sources"},
        },
    )
    list_response = authed_client.get("/api/v1/workspaces/mail-health/incidents?limit=999", headers=headers)
    update_response = authed_client.put(
        f"/api/v1/workspaces/mail-health/incidents/{created['incident']['id']}",
        headers=headers,
        json={"action": "snooze", "note": "Waiting for provider", "snoozed_until": "2026-07-28T10:00:00+02:00"},
    )
    missing_response = authed_client.put(
        "/api/v1/workspaces/mail-health/incidents/999999",
        headers=headers,
        json={"action": "acknowledge"},
    )
    invalid_action = authed_client.put(
        f"/api/v1/workspaces/mail-health/incidents/{created['incident']['id']}",
        headers=headers,
        json={"action": "resolve"},
    )

    assert posture_response.status_code == 200
    assert posture_response.json()["notification_posture"] == "disabled"
    assert invalid_posture.status_code == 422
    assert list_response.status_code == 200
    assert len(list_response.json()["incidents"]) == 1
    assert update_response.status_code == 200
    assert update_response.json()["status"] == "snoozed"
    assert update_response.json()["snoozed_until"] == "2026-07-28T08:00:00"
    assert missing_response.status_code == 404
    assert invalid_action.status_code == 422


def test_workspace_context_and_empty_incident_evaluation_work_for_platform_admin(authed_client, db_session):
    workspace = Workspace(slug="calm-evaluate", name="Calm Evaluate")
    db_session.add(workspace)
    db_session.commit()

    context_response = authed_client.get("/api/v1/workspaces")
    evaluation_response = authed_client.post(
        "/api/v1/workspaces/mail-health/incidents/evaluate",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert context_response.status_code == 200
    assert context_response.json()["default_workspace_id"] == workspace.id
    row = context_response.json()["workspaces"][0]
    assert row["id"] == workspace.id
    assert row["slug"] == "calm-evaluate"
    assert row["organization"] is None
    assert row["effective_role"] == "workspace_owner"
    assert "reports:write" in row["permissions"]
    assert evaluation_response.status_code == 200
    assert evaluation_response.json()["incident"] is None
    assert evaluation_response.json()["resolved"] == []


def test_guidance_validation_rejects_invalid_depth_context_and_goal(authed_client, db_session):
    workspace = Workspace(slug="guidance-invalid", name="Guidance invalid")
    db_session.add(workspace)
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}

    invalid_depth = authed_client.put(
        "/api/v1/workspaces/guidance",
        headers=headers,
        json={"enabled": True, "depth": "novice", "context": "watch"},
    )
    invalid_context = authed_client.put(
        "/api/v1/workspaces/guidance",
        headers=headers,
        json={"enabled": True, "depth": "guided", "context": "overview"},
    )
    invalid_goal = authed_client.put(
        "/api/v1/workspaces/guidance/profile",
        headers=headers,
        json={"goal": "everything", "depth": "guided"},
    )
    invalid_profile_depth = authed_client.put(
        "/api/v1/workspaces/guidance/profile",
        headers=headers,
        json={"goal": "curious", "depth": "novice"},
    )

    assert invalid_depth.status_code == 422
    assert invalid_context.status_code == 422
    assert invalid_goal.status_code == 422
    assert invalid_profile_depth.status_code == 422


def test_incident_evaluation_and_writes_are_denied_to_analysts(test_app, db_session):
    workspace = Workspace(slug="calm-analyst", name="Calm Analyst")
    user = User(email="calm-analyst@example.com", is_active=True, is_verified=True)
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
        read_response = client.get("/api/v1/workspaces/mail-health/incidents", headers=headers)
        evaluate_response = client.post("/api/v1/workspaces/mail-health/incidents/evaluate", headers=headers)
        posture_response = client.put(
            "/api/v1/workspaces/guidance/notification-posture",
            headers=headers,
            json={"posture": "all_signals"},
        )

    assert read_response.status_code == 200
    assert evaluate_response.status_code == 403
    assert posture_response.status_code == 403
