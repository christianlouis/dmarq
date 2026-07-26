"""Tests for workspace-scoped Calm Watch incident lifecycles."""

from datetime import datetime, timedelta, timezone

from app.models.alert import MailHealthIncident
from app.models.workspace import Workspace
from app.services.mail_health_incidents import (
    record_mail_health_assessment,
    update_incident_operator_state,
)


def _assessment(outcome="action_required", domain="example.test"):
    return {
        "outcome": outcome,
        "domain": domain,
        "intended_mail_impact": "likely_affected" if outcome == "action_required" else "likely_not_affected",
        "urgency": "timely" if outcome == "action_required" else "none",
        "confidence": "High",
        "assessment_version": "v1",
        "next_action": {"href": f"/domains/{domain}#sending-sources"},
    }


def test_actionable_incident_notifies_only_when_created_or_materially_changed(db_session):
    workspace = Workspace(slug="calm-watch", name="Calm Watch")
    db_session.add(workspace)
    db_session.commit()

    first = record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())
    repeated = record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())
    changed_assessment = _assessment()
    changed_assessment["urgency"] = "urgent"
    changed = record_mail_health_assessment(db_session, workspace=workspace, assessment=changed_assessment)

    assert first["notification_reason"] == "created"
    assert repeated["notification_reason"] is None
    assert changed["notification_reason"] == "material_change"
    assert db_session.query(MailHealthIncident).count() == 1


def test_protected_unknown_use_is_persisted_but_suppressed_by_default(db_session):
    workspace = Workspace(slug="calm-suppressed", name="Calm Suppressed")
    db_session.add(workspace)
    db_session.commit()

    result = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment=_assessment("no_action_likely_unauthorized_use"),
    )

    assert result["incident"]["status"] == "open"
    assert result["notification_reason"] is None
    assert result["incident"]["assessment"] == _assessment("no_action_likely_unauthorized_use")


def test_incident_identity_is_workspace_scoped(db_session):
    first_workspace = Workspace(slug="calm-alpha", name="Calm Alpha")
    second_workspace = Workspace(slug="calm-beta", name="Calm Beta")
    db_session.add_all([first_workspace, second_workspace])
    db_session.commit()

    first = record_mail_health_assessment(db_session, workspace=first_workspace, assessment=_assessment())
    second = record_mail_health_assessment(db_session, workspace=second_workspace, assessment=_assessment())

    assert first["incident"]["incident_key"] != second["incident"]["incident_key"]
    assert db_session.query(MailHealthIncident).count() == 2


def test_acknowledge_and_snooze_do_not_mark_an_incident_resolved(db_session):
    workspace = Workspace(slug="calm-operator", name="Calm Operator")
    db_session.add(workspace)
    db_session.commit()
    result = record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())
    incident_id = result["incident"]["id"]

    acknowledged = update_incident_operator_state(
        db_session,
        workspace=workspace,
        incident_id=incident_id,
        action="acknowledge",
        note="Checking the provider configuration.",
        snoozed_until=None,
        auth_context={"auth_type": "api_token"},
    )
    snoozed = update_incident_operator_state(
        db_session,
        workspace=workspace,
        incident_id=incident_id,
        action="snooze",
        note=None,
        snoozed_until=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1),
        auth_context={"auth_type": "api_token"},
    )

    assert acknowledged["status"] == "acknowledged"
    assert snoozed["status"] == "snoozed"
    assert snoozed["resolved_at"] is None
