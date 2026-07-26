"""Tests for the focused, non-delivery-claiming mail-health assessment."""

import json
from datetime import datetime, timezone

from app.models.domain import Domain
from app.models.report import DomainSourceDailyProjection
from app.models.workspace import Workspace
from app.services.mail_health import build_workspace_mail_health_assessment


def _projection(
    domain_id: int,
    *,
    ip: str,
    passed: int = 0,
    failed: int = 0,
    disposition_counts: dict | None = None,
    hostname: str | None = None,
) -> DomainSourceDailyProjection:
    evidence = {"captured_at": "2026-07-26T12:00:00Z"}
    if hostname:
        evidence["ptr"] = {"hostname": hostname}
    return DomainSourceDailyProjection(
        domain_id=domain_id,
        source_ip=ip,
        observed_at=int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp()),
        first_seen=int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp()),
        last_seen=int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp()),
        message_count=passed + failed,
        report_count=1,
        dmarc_pass_count=passed,
        dmarc_fail_count=failed,
        disposition_counts=json.dumps(disposition_counts or {}),
        source_evidence=json.dumps(evidence),
    )


def _assessment(db_session, workspace):
    return build_workspace_mail_health_assessment(
        db_session,
        workspace=workspace,
        start_ts=int(datetime(2026, 7, 1, tzinfo=timezone.utc).timestamp()),
        end_ts=int(datetime(2026, 7, 31, tzinfo=timezone.utc).timestamp()),
    )


def test_known_sender_failures_are_actionable_without_claiming_delivery(db_session):
    workspace = Workspace(slug="guided-known", name="Guided known")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(
        _projection(
            domain.id,
            ip="203.0.113.10",
            passed=10,
            failed=3,
            disposition_counts={"none": 3, "reject": 10},
            hostname="mta1.mtasv.net",
        )
    )
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "action_required"
    assert result["domain"] == "example.test"
    assert "may affect mail you intend to send" in result["summary"]
    assert result["intended_mail_impact"] == "likely_affected"
    assert result["urgency"] == "timely"
    assert "do not prove" in result["evidence_scope"]
    assert result["claim_type"] == "aggregate_dmarc_authentication"


def test_unknown_rejected_source_is_quietly_classified_as_likely_unauthorized_use(db_session):
    workspace = Workspace(slug="guided-unknown", name="Guided unknown")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(
        _projection(
            domain.id,
            ip="198.51.100.15",
            failed=7,
            disposition_counts={"reject": 7},
        )
    )
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "no_action_likely_unauthorized_use"
    assert result["next_step"] == "Review source evidence"
    assert result["intended_mail_impact"] == "likely_not_affected"
    assert result["urgency"] == "none"
    assert "not proof" in result["evidence_scope"]


def test_empty_workspace_requests_report_intake_before_any_technical_work(db_session):
    workspace = Workspace(slug="guided-empty", name="Guided empty")
    db_session.add(workspace)
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "insufficient_evidence"
    assert result["href"] == "/mail-sources"


def test_sender_activity_without_authentication_results_is_not_reported_healthy(db_session):
    workspace = Workspace(slug="guided-incomplete", name="Guided incomplete")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(_projection(domain.id, ip="203.0.113.25"))
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "insufficient_evidence"
    assert result["next_step"] == "Review report intake"
    assert "not enough" in result["evidence_scope"].lower()


def test_successful_authentication_evidence_is_reported_as_healthy(db_session):
    workspace = Workspace(slug="guided-healthy", name="Guided healthy")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(_projection(domain.id, ip="203.0.113.26", passed=12))
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "healthy"
    assert result["confidence"] == "High"
    assert result["intended_mail_impact"] == "likely_not_affected"
    assert result["urgency"] == "none"
