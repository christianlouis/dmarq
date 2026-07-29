"""Workspace preference tests for the opt-in guided dashboard."""

from contextlib import contextmanager
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.mail_health_incidents import record_mail_health_assessment
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


def test_new_workspace_defaults_to_guided_while_existing_standard_value_is_preserved(
    authed_client: TestClient,
    db_session,
):
    new_workspace = Workspace(slug="guidance-new-default", name="Guidance new default")
    existing_workspace = Workspace(
        slug="guidance-existing-default",
        name="Guidance existing default",
        guidance_depth="standard",
    )
    db_session.add_all([new_workspace, existing_workspace])
    db_session.commit()

    new_response = authed_client.get(
        "/api/v1/workspaces/guidance/effective",
        headers={"X-DMARQ-Workspace-ID": str(new_workspace.id)},
    )
    existing_response = authed_client.get(
        "/api/v1/workspaces/guidance/effective",
        headers={"X-DMARQ-Workspace-ID": str(existing_workspace.id)},
    )

    assert new_response.status_code == 200
    assert new_response.json()["depth"] == "guided"
    assert new_response.json()["context"] == "watch"
    assert new_response.json()["notification_posture"] == "actionable_only"
    assert existing_response.status_code == 200
    assert existing_response.json()["depth"] == "standard"


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
        "teaching_hints_enabled": True,
        "preference_scope": "workspace",
        "profile_version": 1,
        "goal": None,
        "installation_goals": [],
        "sovereignty_preference": "not_sure",
        "mail_context": {},
        "notification_posture": "actionable_only",
        "interview_version": 1,
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

    with _client_as_auth(
        test_app, db_session, {"auth_type": "session", "user_id": user.id}
    ) as client:
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


def test_user_guidance_preference_overrides_workspace_default_without_changing_it(
    test_app, db_session
):
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

    with _client_as_auth(
        test_app, db_session, {"auth_type": "session", "user_id": user.id}
    ) as client:
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


def test_analyst_can_change_only_their_personal_explanation_preference(test_app, db_session):
    workspace = Workspace(
        slug="guidance-personal-analyst",
        name="Guidance personal analyst",
        guidance_depth="standard",
        guidance_context="watch",
    )
    user = User(email="personal-analyst@example.com", is_active=True, is_verified=True)
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

    with _client_as_auth(
        test_app, db_session, {"auth_type": "session", "user_id": user.id}
    ) as client:
        response = client.put(
            "/api/v1/workspaces/guidance/preferences",
            headers=headers,
            json={
                "depth": "guided",
                "context": "diagnose",
                "teaching_hints_enabled": True,
            },
        )
        workspace_write = client.put(
            "/api/v1/workspaces/guidance/workspace-profile",
            headers=headers,
            json={
                "installation_goals": ["understand_reports"],
                "sovereignty_preference": "balanced",
                "notification_posture": "actionable_only",
                "mail_context": {},
                "interview_version": 1,
                "interview_completed": True,
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "depth": "guided",
        "context": "diagnose",
        "teaching_hints_enabled": True,
        "preference_scope": "user",
        "profile_version": 1,
    }
    assert workspace_write.status_code == 403
    db_session.refresh(user)
    db_session.refresh(workspace)
    assert user.guidance_depth == "guided"
    assert user.guidance_context == "diagnose"
    assert user.guidance_teaching_hints_enabled is True
    assert user.guidance_profile_version == 1
    assert workspace.guidance_depth == "standard"


def test_auth_disabled_preference_uses_durable_workspace_fallback(authed_client, db_session):
    workspace = Workspace(slug="guidance-single-user", name="Guidance single user")
    db_session.add(workspace)
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}

    response = authed_client.put(
        "/api/v1/workspaces/guidance/preferences",
        headers=headers,
        json={
            "depth": "expert",
            "context": "evidence",
            "teaching_hints_enabled": False,
        },
    )
    read_response = authed_client.get(
        "/api/v1/workspaces/guidance/preferences",
        headers=headers,
    )

    assert response.status_code == 200
    assert read_response.status_code == 200
    assert read_response.json()["depth"] == "expert"
    assert read_response.json()["context"] == "evidence"
    assert read_response.json()["teaching_hints_enabled"] is False
    assert read_response.json()["preference_scope"] == "workspace"
    db_session.refresh(workspace)
    assert workspace.guidance_depth == "expert"
    assert workspace.guidance_context == "evidence"
    assert workspace.guidance_teaching_hints_enabled is False


def test_workspace_guidance_profile_is_versioned_validated_and_audited(authed_client, db_session):
    workspace = Workspace(slug="guidance-workspace-profile", name="Guidance workspace profile")
    db_session.add(workspace)
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}
    payload = {
        "installation_goals": [
            "troubleshoot_delivery",
            "understand_reports",
            "troubleshoot_delivery",
        ],
        "sovereignty_preference": "keep_data_local",
        "notification_posture": "important_plus_digest",
        "mail_context": {
            "known_mail_providers": ["Poste.io", "Poste.io"],
            "self_hosted_sender": True,
            "dns_provider": "Cloudflare",
            "report_intake_preference": "local_imap",
            "controls_dns": True,
            "setup_effort": "maximum_control",
        },
        "interview_version": 1,
        "interview_completed": True,
    }

    response = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json=payload,
    )
    effective = authed_client.get(
        "/api/v1/workspaces/guidance/effective",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["installation_goals"] == [
        "troubleshoot_delivery",
        "understand_reports",
    ]
    assert response.json()["mail_context"]["known_mail_providers"] == ["Poste.io"]
    assert effective.status_code == 200
    assert effective.json()["sovereignty_preference"] == "keep_data_local"
    assert effective.json()["notification_posture"] == "important_plus_digest"
    assert effective.json()["profile_version"] == 1
    db_session.refresh(workspace)
    assert workspace.mail_health_goal == "delivery_problem"
    assert workspace.guidance_interview_completed_at is not None
    audit = db_session.query(WorkspaceAuditLog).one()
    assert audit.action == "workspace.guidance_profile_updated"
    assert audit.workspace_id == workspace.id
    assert "Poste.io" in audit.details


def test_workspace_guidance_profile_rejects_unknown_schema_values(authed_client, db_session):
    workspace = Workspace(slug="guidance-workspace-invalid", name="Guidance workspace invalid")
    db_session.add(workspace)
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}
    base = {
        "installation_goals": ["understand_reports"],
        "sovereignty_preference": "balanced",
        "notification_posture": "actionable_only",
        "mail_context": {},
        "interview_version": 1,
        "interview_completed": True,
    }

    invalid_goal = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={**base, "installation_goals": ["become_a_wizard"]},
    )
    invalid_context = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={**base, "mail_context": {"unexpected_private_field": True}},
    )
    future_version = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={**base, "interview_version": 99},
    )
    too_many_goals = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={**base, "installation_goals": ["understand_reports"] * 10},
    )

    assert invalid_goal.status_code == 422
    assert invalid_context.status_code == 422
    assert future_version.status_code == 422
    assert too_many_goals.status_code == 422
    assert db_session.query(WorkspaceAuditLog).count() == 0


def test_notification_posture_and_incident_actions_are_workspace_scoped(authed_client, db_session):
    workspace = Workspace(slug="calm-api", name="Calm API")
    other_workspace = Workspace(slug="calm-api-other", name="Calm API Other")
    db_session.add_all([workspace, other_workspace])
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
    foreign = record_mail_health_assessment(
        db_session,
        workspace=other_workspace,
        assessment={
            "outcome": "action_required",
            "domain": "foreign.test",
            "intended_mail_impact": "likely_affected",
            "urgency": "timely",
            "confidence": "High",
            "assessment_version": "v1",
            "next_action": {"href": "/domains/foreign.test#sending-sources"},
        },
    )
    list_response = authed_client.get(
        "/api/v1/workspaces/mail-health/incidents?limit=999", headers=headers
    )
    update_response = authed_client.put(
        f"/api/v1/workspaces/mail-health/incidents/{created['incident']['id']}",
        headers=headers,
        json={
            "action": "snooze",
            "note": "Waiting for provider",
            "snoozed_until": "2099-07-28T10:00:00+02:00",
        },
    )
    foreign_update_response = authed_client.put(
        f"/api/v1/workspaces/mail-health/incidents/{foreign['incident']['id']}",
        headers=headers,
        json={"action": "acknowledge"},
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
    assert list_response.json()["incidents"][0]["id"] == created["incident"]["id"]
    assert update_response.status_code == 200
    assert update_response.json()["status"] == "snoozed"
    assert update_response.json()["snoozed_until"] == "2099-07-28T08:00:00"
    assert foreign_update_response.status_code == 404
    assert missing_response.status_code == 404
    assert invalid_action.status_code == 422


def test_workspace_context_and_empty_incident_evaluation_work_for_platform_admin(
    authed_client, db_session
):
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

    with _client_as_auth(
        test_app, db_session, {"auth_type": "session", "user_id": user.id}
    ) as client:
        read_response = client.get("/api/v1/workspaces/mail-health/incidents", headers=headers)
        evaluate_response = client.post(
            "/api/v1/workspaces/mail-health/incidents/evaluate", headers=headers
        )
        posture_response = client.put(
            "/api/v1/workspaces/guidance/notification-posture",
            headers=headers,
            json={"posture": "all_signals"},
        )

    assert read_response.status_code == 200
    assert evaluate_response.status_code == 403
    assert posture_response.status_code == 403
