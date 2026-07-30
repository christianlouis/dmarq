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
    first_seen: int | None = None,
    last_seen: int | None = None,
    metadata: dict | None = None,
    spf_passed: int = 0,
    spf_failed: int = 0,
    dkim_passed: int = 0,
    dkim_failed: int = 0,
) -> DomainSourceDailyProjection:
    evidence = {"captured_at": "2026-07-26T12:00:00Z"}
    if hostname:
        evidence["ptr"] = {"hostname": hostname}
    return DomainSourceDailyProjection(
        domain_id=domain_id,
        source_ip=ip,
        observed_at=int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp()),
        first_seen=first_seen or int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp()),
        last_seen=last_seen or int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp()),
        message_count=passed + failed,
        report_count=1,
        spf_pass_count=spf_passed,
        spf_fail_count=spf_failed,
        dkim_pass_count=dkim_passed,
        dkim_fail_count=dkim_failed,
        dmarc_pass_count=passed,
        dmarc_fail_count=failed,
        disposition_counts=json.dumps(disposition_counts or {}),
        metadata_json=json.dumps(metadata or {}),
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
    assert result["assessment_version"] == "v1"
    assert result["known_facts"]
    assert result["inferences"]
    assert result["unknowns"]
    assert result["next_action"]["href"] == result["href"]
    assert "do not prove" in result["evidence_scope"]
    assert result["claim_type"] == "aggregate_dmarc_authentication"
    assert result["claim_level"] == "inferred"
    assert result["delivery_certainty"] == "inferred_only"
    assert result["signal_schema_version"] == "dmarq.mail_signal.v1"
    assert {signal["family"] for signal in result["supporting_signals"]} == {
        "dmarc_authentication",
        "dmarc_reported_disposition",
    }
    assert {claim["claim_level"] for claim in result["claims"]} == {
        "observed",
        "derived",
        "inferred",
        "unknown",
    }


def test_health_signals_keep_protocol_counts_identities_and_report_boundaries(db_session):
    workspace = Workspace(slug="guided-signal-detail", name="Guided signal detail")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    first_seen = int(datetime(2026, 7, 25, 3, 15, tzinfo=timezone.utc).timestamp())
    last_seen = int(datetime(2026, 7, 25, 21, 45, tzinfo=timezone.utc).timestamp())
    db_session.add(
        _projection(
            domain.id,
            ip="203.0.113.10",
            passed=8,
            failed=2,
            disposition_counts={"none": 8, "reject": 2},
            hostname="mta1.mtasv.net",
            first_seen=first_seen,
            last_seen=last_seen,
            spf_passed=7,
            spf_failed=3,
            dkim_passed=8,
            dkim_failed=2,
            metadata={
                "header_from_domains": ["example.test"],
                "envelope_from_domains": ["bounce.example.test"],
                "spf_domains": ["bounce.example.test"],
                "dkim_domains": ["example.test"],
                "dkim_selectors": ["selector1"],
                "report_generators": ["receiver.example"],
            },
        )
    )
    db_session.commit()

    result = _assessment(db_session, workspace)
    authentication = next(
        signal
        for signal in result["supporting_signals"]
        if signal["family"] == "dmarc_authentication"
    )

    assert authentication["window_start"] == first_seen
    assert authentication["window_end"] == last_seen
    assert authentication["payload"] == {
        "source_ip": "203.0.113.10",
        "passed": 8,
        "failed": 2,
        "spf_passed": 7,
        "spf_failed": 3,
        "dkim_passed": 8,
        "dkim_failed": 2,
        "header_from_domains": ["example.test"],
        "envelope_from_domains": ["bounce.example.test"],
        "spf_domains": ["bounce.example.test"],
        "dkim_domains": ["example.test"],
        "dkim_selectors": ["selector1"],
        "report_generators": ["receiver.example"],
    }


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
    assert result["no_action_reason"]
    assert result["watch_condition"]
    assert "not proof" in result["evidence_scope"]


def test_unknown_source_without_protective_handling_requires_investigation(db_session):
    workspace = Workspace(slug="guided-unknown-open", name="Guided unknown open")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(
        _projection(
            domain.id,
            ip="198.51.100.31",
            failed=4,
            disposition_counts={"none": 4},
        )
    )
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "investigation_required"
    assert result["intended_mail_impact"] == "unknown"
    assert result["urgency"] == "timely"
    assert "approved service" in result["next_step"]


def test_empty_workspace_requests_report_intake_before_any_technical_work(db_session):
    workspace = Workspace(slug="guided-empty", name="Guided empty")
    db_session.add(workspace)
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "insufficient_evidence"
    assert result["href"] == "/mail-sources"
    assert result["claim_level"] == "derived"
    assert result["supporting_signals"][0]["family"] == "intake_health"
    assert result["supporting_signals"][0]["delivery_certainty"] == "not_applicable"


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
    assert result["supporting_signals"][0]["delivery_certainty"] == "authentication_only"
