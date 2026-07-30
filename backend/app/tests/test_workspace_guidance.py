"""Workspace preference tests for the opt-in guided dashboard."""

import json
from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.api.api_v1.endpoints.workspaces import (
    _selected_diagnostic_domain,
    _stored_report_evidence,
)
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.dns_posture_snapshot import DomainDNSPostureCurrent, DomainDNSPostureSnapshot
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.report import DMARCReport, ForensicReport, ReportRecord, TLSReport
from app.models.setting import Setting
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.mail_health_incidents import record_mail_health_assessment
from app.services.workspace_access import ROLE_ANALYST


def test_requested_unmonitored_diagnostic_domain_does_not_fall_back_to_another_domain():
    known = SimpleNamespace(name="known.example")

    selected = _selected_diagnostic_domain(
        [known], {"mail_context": {"domains": ["requested.example"]}}
    )

    assert selected is None


def test_diagnostic_failures_use_the_latest_report_not_lifetime_history(db_session):
    workspace = Workspace(slug="fresh-diagnostic", name="Fresh diagnostic")
    domain = Domain(name="fresh.example", workspace=workspace)
    old_report = DMARCReport(
        domain=domain,
        report_id="old-failure",
        org_name="Receiver",
        begin_date=1_700_000_000,
        end_date=1_700_086_400,
    )
    fresh_report = DMARCReport(
        domain=domain,
        report_id="fresh-pass",
        org_name="Receiver",
        begin_date=1_700_086_401,
        end_date=1_700_172_800,
    )
    db_session.add_all(
        [
            workspace,
            domain,
            old_report,
            fresh_report,
            ReportRecord(
                report=old_report,
                source_ip="192.0.2.10",
                count=4,
                disposition="none",
                dkim="fail",
                spf="fail",
                header_from=domain.name,
            ),
            ReportRecord(
                report=fresh_report,
                source_ip="192.0.2.11",
                count=4,
                disposition="none",
                dkim="pass",
                spf="pass",
                header_from=domain.name,
            ),
        ]
    )
    db_session.commit()

    report_count, message_count, failed_message_count, latest_report_id = _stored_report_evidence(
        db_session, domain
    )

    assert (report_count, message_count, failed_message_count) == (2, 8, 0)
    assert latest_report_id == fresh_report.id


def test_report_intake_recommendation_uses_persisted_source_and_import_state(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    workspace = Workspace(
        slug="intake-recommendation",
        name="Intake recommendation",
        guidance_installation_goals='["continuous_monitoring"]',
        guidance_mail_context='{"setup_effort":"balanced"}',
    )
    domain = Domain(
        name="intake.example",
        workspace=workspace,
        dmarc_report_mailbox="reports@intake.example",
    )
    source = MailSource(
        workspace=workspace,
        name="Reports Gmail",
        method="GMAIL_API",
        enabled=True,
        last_checked=datetime.utcnow(),
    )
    report = DMARCReport(
        domain=domain,
        report_id="intake-report",
        org_name="Receiver",
        begin_date=1_700_000_000,
        end_date=1_700_086_400,
    )
    db_session.add_all([workspace, domain, source, report])
    db_session.flush()
    db_session.add(
        MailSourceImport(
            mail_source_id=source.id,
            trigger="manual",
            status="completed",
            processed=1,
            reports_found=1,
            duplicate_reports=0,
            error_count=0,
        )
    )
    db_session.commit()
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.workspaces.get_settings",
        lambda: SimpleNamespace(
            GUIDED_MAIL_HEALTH_UI_ENABLED=True,
            PUBLIC_BASE_URL="https://dmarq.example",
            WEBHOOK_SECRET="configured-not-returned",
            default_locale="en",
        ),
    )

    response = authed_client.get(
        "/api/v1/workspaces/guidance/report-intake-recommendation",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["recommended"]["id"] == "gmail"
    assert payload["first_report"]["state"] == "working"
    assert payload["first_report"]["report_count"] == 1
    assert payload["primary_action"]["href"] == f"/reports/{report.id}"
    assert len(payload["journey"]) == 8
    assert payload["journey"][0]["complete"] is True
    assert payload["public_endpoint"] == {
        "https_ready": True,
        "webhook_configured": True,
    }
    assert "configured-not-returned" not in response.text


def test_report_intake_recommendation_scopes_reports_and_base_url_to_selected_domain(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    workspace = Workspace(
        slug="selected-intake-domain",
        name="Selected intake domain",
        guidance_installation_goals='["continuous_monitoring"]',
        guidance_mail_context='{"domains":["selected.example"]}',
    )
    selected_domain = Domain(name="selected.example", workspace=workspace)
    other_domain = Domain(name="other.example", workspace=workspace)
    other_report = DMARCReport(
        domain=other_domain,
        report_id="other-domain-report",
        org_name="Receiver",
        begin_date=1_700_000_000,
        end_date=1_700_086_400,
    )
    db_session.add_all(
        [
            workspace,
            selected_domain,
            other_domain,
            other_report,
            Setting(key="general.base_url", value="https://saved.dmarq.example"),
        ]
    )
    db_session.commit()
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.workspaces.get_settings",
        lambda: SimpleNamespace(
            GUIDED_MAIL_HEALTH_UI_ENABLED=True,
            PUBLIC_BASE_URL=None,
            WEBHOOK_SECRET="configured-not-returned",
            default_locale="en",
        ),
    )

    response = authed_client.get(
        "/api/v1/workspaces/guidance/report-intake-recommendation",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["first_report"]["report_count"] == 0
    assert payload["primary_action"]["href"] != f"/reports/{other_report.id}"
    assert payload["public_endpoint"]["https_ready"] is True


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
    audit_details = json.loads(audit.details)
    assert audit_details["current"]["mail_context"]["known_mail_providers"] == ["Poste.io"]
    assert audit_details["previous"]["mail_context"] == {}


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


def test_diagnostic_plan_reads_persisted_domain_report_and_intake_evidence(
    authed_client: TestClient,
    db_session,
):
    workspace = Workspace(
        slug="diagnostic-plan",
        name="Diagnostic plan",
        guidance_installation_goals='["understand_reports"]',
        guidance_mail_context='{"domains":["diagnostic.example"],"domain_sends_mail":true}',
    )
    domain = Domain(
        name="diagnostic.example",
        workspace=workspace,
        dmarc_policy="reject",
        spf_record="v=spf1 -all",
    )
    report = DMARCReport(
        domain=domain,
        report_id="diagnostic-report",
        org_name="Example Receiver",
        begin_date=1_700_000_000,
        end_date=1_700_086_400,
        policy="reject",
    )
    record = ReportRecord(
        report=report,
        source_ip="192.0.2.10",
        count=8,
        disposition="none",
        dkim="pass",
        spf="pass",
        header_from="diagnostic.example",
    )
    source = MailSource(
        workspace=workspace,
        name="Diagnostic IMAP",
        method="IMAP",
        enabled=True,
        last_checked=datetime.utcnow(),
    )
    db_session.add_all([workspace, domain, report, record, source])
    db_session.flush()
    snapshot = DomainDNSPostureSnapshot(
        domain_id=domain.id,
        workspace_id=workspace.id,
        trigger="scheduled",
        selector_hash="selectors",
        result_fingerprint="result",
        result_json=json.dumps(
            {
                "dmarc": True,
                "spf": True,
                "dkim": True,
                "dkim_selectors": ["selector1", "selector2"],
                "dmarc_tags": {
                    "rua": "mailto:aggregate1@example.com,mailto:aggregate2@example.com",
                    "ruf": "mailto:failure@example.com",
                },
            }
        ),
        lookup_status="ok",
        accepted=True,
    )
    forensic = ForensicReport(
        domain_id=domain.id,
        report_id="forensic-1",
        reported_domain=domain.name,
    )
    tls_report = TLSReport(
        domain_id=domain.id,
        report_id="tls-1",
        policy_domain=domain.name,
    )
    db_session.add_all([snapshot, forensic, tls_report])
    db_session.flush()
    db_session.add(
        DomainDNSPostureCurrent(
            domain_id=domain.id,
            workspace_id=workspace.id,
            accepted_snapshot_id=snapshot.id,
            latest_snapshot_id=snapshot.id,
        )
    )
    db_session.commit()

    response = authed_client.get(
        "/api/v1/workspaces/guidance/diagnostic-plan",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["generated_from"] == "persisted_evidence"
    assert payload["domain"] == "diagnostic.example"
    assert payload["current_action"]["id"] == "explain_report"
    assert payload["current_action"]["href"] == f"/reports/{report.id}"
    assert payload["evidence"] == {
        "domain_count": 1,
        "report_count": 1,
        "forensic_report_count": 1,
        "tls_report_count": 1,
        "message_count": 8,
        "failed_message_count": 0,
        "enabled_source_count": 1,
        "checked_source_count": 1,
        "dns_evidence_available": True,
        "has_dmarc": True,
        "has_spf": True,
        "has_dkim": True,
        "dkim_selector_count": 2,
        "dmarc_rua_count": 2,
        "dmarc_ruf_count": 1,
        "dns_provider_connected": False,
    }
    assert any("DKIM" in fact for fact in payload["known_facts"])
    assert any("failure report" in fact for fact in payload["known_facts"])


def test_workspace_interview_context_is_resumable_and_sanitized(
    authed_client: TestClient,
    db_session,
):
    workspace = Workspace(slug="diagnostic-resume", name="Diagnostic resume")
    db_session.add(workspace)
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}

    response = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={
            "installation_goals": ["investigate_bounces", "continuous_monitoring"],
            "sovereignty_preference": "privacy_first",
            "notification_posture": "actionable_only",
            "mail_context": {
                "domains": ["Example.COM"],
                "controls_dns": False,
                "domain_sends_mail": True,
                "bounce_available": True,
                "low_volume": False,
                "symptom_recipient_provider": "Example receiver",
                "symptom_first_observed": "2026-07-30",
                "interview_step": 3,
            },
            "interview_version": 1,
            "interview_completed": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["interview_completed"] is False
    assert db_session.query(WorkspaceAuditLog).count() == 0
    assert response.json()["mail_context"] == {
        "known_mail_providers": [],
        "domains": ["example.com"],
        "controls_dns": False,
        "domain_sends_mail": True,
        "bounce_available": True,
        "low_volume": False,
        "symptom_recipient_provider": "Example receiver",
        "symptom_first_observed": "2026-07-30",
        "interview_step": 3,
    }

    invalid = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={
            "installation_goals": ["investigate_bounces"],
            "mail_context": {"domains": ["not a domain"], "interview_step": 5},
            "interview_completed": False,
        },
    )
    assert invalid.status_code == 422

    boolean_step = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={
            "installation_goals": ["investigate_bounces"],
            "mail_context": {"interview_step": True},
            "interview_completed": False,
        },
    )
    assert boolean_step.status_code == 422

    completed = authed_client.put(
        "/api/v1/workspaces/guidance/workspace-profile",
        headers=headers,
        json={
            "installation_goals": ["investigate_bounces", "continuous_monitoring"],
            "sovereignty_preference": "privacy_first",
            "notification_posture": "actionable_only",
            "mail_context": response.json()["mail_context"],
            "interview_version": 1,
            "interview_completed": True,
        },
    )
    assert completed.status_code == 200
    assert db_session.query(WorkspaceAuditLog).count() == 1


def test_diagnostic_plan_uses_german_copy_from_locale_cookie(
    authed_client: TestClient,
    db_session,
):
    workspace = Workspace(slug="diagnostic-de", name="Diagnostic DE")
    db_session.add(workspace)
    db_session.commit()

    response = authed_client.get(
        "/api/v1/workspaces/guidance/diagnostic-plan",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
        cookies={"dmarq_locale": "de"},
    )

    assert response.status_code == 200
    assert response.json()["current_action"]["label"] == "Domain hinzufügen"


def test_diagnostic_plan_uses_latest_report_for_current_failure_action(
    authed_client: TestClient,
    db_session,
):
    workspace = Workspace(
        slug="diagnostic-window",
        name="Diagnostic window",
        guidance_installation_goals='["continuous_monitoring"]',
    )
    domain = Domain(
        name="window.example",
        workspace=workspace,
        dmarc_policy="reject",
    )
    old_report = DMARCReport(
        domain=domain,
        report_id="old-failure",
        org_name="Example Receiver",
        begin_date=1,
        end_date=100,
        policy="reject",
    )
    latest_report = DMARCReport(
        domain=domain,
        report_id="latest-pass",
        org_name="Example Receiver",
        begin_date=2_999_000,
        end_date=3_000_000,
        policy="reject",
    )
    db_session.add_all(
        [
            workspace,
            domain,
            old_report,
            latest_report,
            ReportRecord(
                report=old_report,
                source_ip="192.0.2.1",
                count=50,
                disposition="reject",
                dkim="fail",
                spf="fail",
            ),
            ReportRecord(
                report=latest_report,
                source_ip="192.0.2.2",
                count=25,
                disposition="none",
                dkim="pass",
                spf="pass",
            ),
        ]
    )
    db_session.commit()

    response = authed_client.get(
        "/api/v1/workspaces/guidance/diagnostic-plan",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["evidence"]["report_count"] == 2
    assert payload["evidence"]["message_count"] == 75
    assert payload["evidence"]["failed_message_count"] == 0
    assert payload["current_action"]["id"] == "open_domain"
