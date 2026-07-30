"""Tests for workspace-scoped Calm Watch incident lifecycles."""

from datetime import datetime, timedelta, timezone

from app.models.alert import MailHealthIncident
from app.models.workspace import Workspace
from app.services.mail_health_incidents import (
    incident_to_dict,
    list_mail_health_incidents,
    record_mail_health_assessment,
    update_incident_operator_state,
)


def _assessment(outcome="action_required", domain="example.test"):
    return {
        "outcome": outcome,
        "domain": domain,
        "intended_mail_impact": (
            "likely_affected" if outcome == "action_required" else "likely_not_affected"
        ),
        "urgency": "timely" if outcome == "action_required" else "none",
        "confidence": "High",
        "assessment_version": "v1",
        "claim_level": "inferred",
        "delivery_certainty": "inferred_only",
        "supporting_signals": [
            {
                "signal_id": "signal-a",
                "family": "dmarc_authentication",
                "signal_type": "aggregate_authentication_result",
                "outcome": "fail",
                "claim_level": "observed",
                "delivery_certainty": "authentication_only",
            }
        ],
        "next_action": {"href": f"/domains/{domain}#sending-sources"},
    }


def test_actionable_incident_notifies_only_when_created_or_materially_changed(db_session):
    workspace = Workspace(slug="calm-watch", name="Calm Watch")
    db_session.add(workspace)
    db_session.commit()

    first = record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())
    repeated = record_mail_health_assessment(
        db_session, workspace=workspace, assessment=_assessment()
    )
    changed_assessment = _assessment()
    changed_assessment["urgency"] = "urgent"
    changed = record_mail_health_assessment(
        db_session, workspace=workspace, assessment=changed_assessment
    )

    assert first["notification_reason"] == "created"
    assert repeated["notification_reason"] is None
    assert changed["notification_reason"] == "material_change"
    assert db_session.query(MailHealthIncident).count() == 1


def test_changed_evidence_certainty_is_a_material_notification_change(db_session):
    workspace = Workspace(slug="calm-evidence-change", name="Calm evidence change")
    db_session.add(workspace)
    db_session.commit()

    first = record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())
    changed_assessment = _assessment()
    changed_assessment["delivery_certainty"] = "non_delivery_reported"
    changed_assessment["supporting_signals"] = [{"signal_id": "dsn-signal-b"}]
    changed = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment=changed_assessment,
    )

    assert first["notification_reason"] == "created"
    assert changed["notification_reason"] == "material_change"
    assert changed["incident"]["assessment"]["delivery_certainty"] == "non_delivery_reported"


def test_rolling_evidence_row_ids_do_not_trigger_a_material_notification(db_session):
    workspace = Workspace(slug="calm-evidence-window", name="Calm evidence window")
    db_session.add(workspace)
    db_session.commit()

    first = record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())
    shifted_window = _assessment()
    shifted_window["supporting_signals"][0]["signal_id"] = "signal-from-next-window"
    repeated = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment=shifted_window,
    )

    assert first["notification_reason"] == "created"
    assert repeated["notification_reason"] is None


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

    first = record_mail_health_assessment(
        db_session, workspace=first_workspace, assessment=_assessment()
    )
    second = record_mail_health_assessment(
        db_session, workspace=second_workspace, assessment=_assessment()
    )

    assert first["incident"]["incident_key"] != second["incident"]["incident_key"]
    assert db_session.query(MailHealthIncident).count() == 2


def test_acknowledge_and_snooze_do_not_mark_an_incident_resolved(db_session):
    workspace = Workspace(slug="calm-operator", name="Calm Operator")
    db_session.add(workspace)
    db_session.commit()
    result = record_mail_health_assessment(
        db_session, workspace=workspace, assessment=_assessment()
    )
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


def test_healthy_assessment_resolves_open_incidents_for_the_domain(db_session):
    workspace = Workspace(slug="calm-resolve", name="Calm Resolve")
    db_session.add(workspace)
    db_session.commit()
    record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())

    resolved = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment={"outcome": "healthy", "domain": "example.test"},
    )

    assert resolved["incident"] is None
    assert len(resolved["resolved"]) == 1
    assert resolved["resolved"][0]["status"] == "resolved"


def test_all_signals_can_notify_a_protected_unknown_source(db_session):
    workspace = Workspace(
        slug="calm-all-signals", name="Calm All Signals", notification_posture="all_signals"
    )
    db_session.add(workspace)
    db_session.commit()

    result = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment=_assessment("no_action_likely_unauthorized_use"),
    )

    assert result["notification_reason"] == "created"


def test_low_volume_waiting_state_is_not_persisted_or_notified(db_session):
    workspace = Workspace(
        slug="calm-low-volume", name="Calm low volume", notification_posture="all_signals"
    )
    db_session.add(workspace)
    db_session.commit()
    waiting = _assessment("monitor", domain=None)
    waiting["supporting_signals"] = [
        {
            "family": "intake_health",
            "outcome": "no_report_evidence_in_window",
        }
    ]

    result = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment=waiting,
    )

    assert result == {"incident": None, "notification_reason": None, "resolved": []}
    assert db_session.query(MailHealthIncident).count() == 0


def test_new_outcome_resolves_the_previous_incident_for_one_domain(db_session):
    workspace = Workspace(slug="calm-supersede", name="Calm Supersede")
    db_session.add(workspace)
    db_session.commit()
    record_mail_health_assessment(db_session, workspace=workspace, assessment=_assessment())

    replacement = record_mail_health_assessment(
        db_session,
        workspace=workspace,
        assessment=_assessment("investigation_required"),
    )
    rows = list_mail_health_incidents(db_session, workspace=workspace)

    assert replacement["incident"]["outcome"] == "investigation_required"
    assert {row["status"] for row in rows} == {"open", "resolved"}


def test_invalid_operator_action_and_malformed_assessment_are_safe(db_session):
    workspace = Workspace(slug="calm-invalid", name="Calm Invalid")
    db_session.add(workspace)
    db_session.commit()
    created = record_mail_health_assessment(
        db_session, workspace=workspace, assessment=_assessment()
    )
    row = db_session.query(MailHealthIncident).one()
    row.assessment = "not-json"
    db_session.commit()

    assert incident_to_dict(row)["assessment"] == {}
    try:
        update_incident_operator_state(
            db_session,
            workspace=workspace,
            incident_id=created["incident"]["id"],
            action="resolve",
            note=None,
            snoozed_until=None,
            auth_context=None,
        )
    except ValueError as exc:
        assert "Unsupported" in str(exc)
    else:
        raise AssertionError("An unsupported operator action must be rejected.")


def test_disabled_and_active_snooze_suppress_notification_but_keep_incidents(db_session):
    disabled = Workspace(
        slug="calm-disabled", name="Calm Disabled", notification_posture="disabled"
    )
    snoozed_workspace = Workspace(slug="calm-snoozed", name="Calm Snoozed")
    db_session.add_all([disabled, snoozed_workspace])
    db_session.commit()

    disabled_result = record_mail_health_assessment(
        db_session, workspace=disabled, assessment=_assessment()
    )
    created = record_mail_health_assessment(
        db_session, workspace=snoozed_workspace, assessment=_assessment()
    )
    update_incident_operator_state(
        db_session,
        workspace=snoozed_workspace,
        incident_id=created["incident"]["id"],
        action="snooze",
        note=None,
        snoozed_until=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1),
        auth_context=None,
    )
    changed = _assessment()
    changed["urgency"] = "urgent"
    snoozed_result = record_mail_health_assessment(
        db_session, workspace=snoozed_workspace, assessment=changed
    )

    assert disabled_result["notification_reason"] is None
    assert snoozed_result["notification_reason"] is None
    assert snoozed_result["incident"]["status"] == "snoozed"


def test_operator_state_rejects_missing_incident_and_snooze_timestamp(db_session):
    workspace = Workspace(slug="calm-missing", name="Calm Missing")
    other_workspace = Workspace(slug="calm-missing-other", name="Calm Missing Other")
    db_session.add_all([workspace, other_workspace])
    db_session.commit()
    foreign = record_mail_health_assessment(
        db_session, workspace=other_workspace, assessment=_assessment(domain="other.test")
    )

    for kwargs, message in (
        ({"incident_id": 9999, "action": "acknowledge", "snoozed_until": None}, "not found"),
        ({"incident_id": 9999, "action": "snooze", "snoozed_until": None}, "not found"),
        (
            {
                "incident_id": foreign["incident"]["id"],
                "action": "acknowledge",
                "snoozed_until": None,
            },
            "not found",
        ),
    ):
        try:
            update_incident_operator_state(
                db_session,
                workspace=workspace,
                note=None,
                auth_context=None,
                **kwargs,
            )
        except LookupError as exc:
            assert message in str(exc)
        else:
            raise AssertionError("A cross-workspace incident must not be writable.")

    created = record_mail_health_assessment(
        db_session, workspace=workspace, assessment=_assessment()
    )
    try:
        update_incident_operator_state(
            db_session,
            workspace=workspace,
            incident_id=created["incident"]["id"],
            action="snooze",
            note=None,
            snoozed_until=None,
            auth_context=None,
        )
    except ValueError as exc:
        assert "required" in str(exc)
    else:
        raise AssertionError("A snooze without an end time must be rejected.")
