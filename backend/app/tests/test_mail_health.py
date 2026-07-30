"""Tests for the focused, non-delivery-claiming mail-health assessment."""

import json
from datetime import datetime, timezone

from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.report import DomainSourceDailyProjection
from app.models.workspace import Workspace
from app.services.delivery_events import ingest_provider_event
from app.services.mail_health import build_workspace_mail_health_assessment
from app.services.sender_classifications import record_sender_classification


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
    observed_at: int | None = None,
) -> DomainSourceDailyProjection:
    evidence = {"captured_at": "2026-07-26T12:00:00Z"}
    if hostname:
        evidence["ptr"] = {"hostname": hostname}
    return DomainSourceDailyProjection(
        domain_id=domain_id,
        source_ip=ip,
        observed_at=observed_at or int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp()),
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


def test_actual_non_delivery_event_outranks_aggregate_authentication_inference(db_session):
    workspace = Workspace(slug="delivery-evidence", name="Delivery evidence")
    db_session.add(workspace)
    db_session.commit()
    ingest_provider_event(
        db_session,
        workspace=workspace,
        payload={
            "schema_version": "dmarq.provider_delivery_event.v1",
            "provider": "postmark",
            "event_id": "bounce-1",
            "event": "bounced",
            "occurred_at": datetime(2026, 7, 25),
            "domain": "example.test",
            "recipient": "recipient@example.net",
            "status_code": "5.7.26",
            "diagnostic_text": "DMARC authentication failed",
        },
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "action_required"
    assert result["domain"] == "example.test"
    assert result["delivery_certainty"] == "non_delivery_reported"
    assert result["supporting_signals"][0]["family"] == "provider_delivery_event"
    assert result["next_action"]["href"] == "/delivery-events?domain=example.test"


def test_newer_correlated_delivery_supersedes_an_earlier_bounce(db_session):
    workspace = Workspace(slug="delivery-retry", name="Delivery retry")
    db_session.add(workspace)
    db_session.commit()
    base = {
        "schema_version": "dmarq.provider_delivery_event.v1",
        "provider": "postmark",
        "domain": "example.test",
        "recipient": "recipient@example.net",
        "message_id": "retry-message-1",
    }
    ingest_provider_event(
        db_session,
        workspace=workspace,
        payload={
            **base,
            "event_id": "bounce-before-retry",
            "event": "bounced",
            "occurred_at": datetime(2026, 7, 25),
            "status_code": "4.7.0",
        },
    )
    ingest_provider_event(
        db_session,
        workspace=workspace,
        payload={
            **base,
            "event_id": "delivered-after-retry",
            "event": "delivered",
            "occurred_at": datetime(2026, 7, 26),
        },
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] != "action_required"
    assert result["title"] != "A sending system reported non-delivery"


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
    assert result["schema_version"] == "dmarq.mail_health_assessment.v2"
    assert result["assessment_algorithm_version"] == "deterministic-2026-07"
    assert result["assessment_id"]
    assert result["confidence_band"] in {"high", "medium", "low"}
    assert result["intended_mail_impact_band"] == "likely"
    assert result["urgency_band"] == "soon"
    assert result["evidence_window"]["start"]
    assert result["conclusion"]["key"]
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


def test_projection_reader_aggregates_daily_counters_and_compact_evidence(db_session):
    workspace = Workspace(slug="guided-sql-aggregate", name="Guided SQL aggregate")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    first_day = int(datetime(2026, 7, 24, tzinfo=timezone.utc).timestamp())
    second_day = int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp())
    db_session.add_all(
        [
            _projection(
                domain.id,
                ip="203.0.113.10",
                passed=3,
                disposition_counts={"none": 3},
                hostname="mta1.mtasv.net",
                observed_at=first_day,
                first_seen=first_day,
                last_seen=first_day,
                metadata={"dkim_selectors": ["first"]},
            ),
            _projection(
                domain.id,
                ip="203.0.113.10",
                failed=2,
                disposition_counts={"reject": 2},
                hostname="mta1.mtasv.net",
                observed_at=second_day,
                first_seen=second_day,
                last_seen=second_day,
                metadata={"dkim_selectors": ["second"]},
            ),
        ]
    )
    db_session.commit()

    result = _assessment(db_session, workspace)
    authentication = next(
        signal
        for signal in result["supporting_signals"]
        if signal["family"] == "dmarc_authentication"
    )
    disposition = next(
        signal
        for signal in result["supporting_signals"]
        if signal["family"] == "dmarc_reported_disposition"
    )

    assert authentication["payload"]["passed"] == 3
    assert authentication["payload"]["failed"] == 2
    assert authentication["payload"]["dkim_selectors"] == ["first", "second"]
    assert authentication["window_start"] == first_day
    assert authentication["window_end"] == second_day
    assert disposition["payload"]["dispositions"] == {"none": 3, "reject": 2}


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
    assert result["delivery_certainty"] == "not_applicable"
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
    assert result["delivery_certainty"] == "not_applicable"


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


def test_operator_legitimate_sender_with_previous_passes_is_prioritized_as_regression(db_session):
    workspace = Workspace(slug="guided-regression", name="Guided regression")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    prior = int(datetime(2026, 6, 25, tzinfo=timezone.utc).timestamp())
    current = int(datetime(2026, 7, 25, tzinfo=timezone.utc).timestamp())
    db_session.add_all(
        [
            _projection(
                domain.id,
                ip="198.51.100.44",
                passed=24,
                observed_at=prior,
                first_seen=prior,
                last_seen=prior,
            ),
            _projection(
                domain.id,
                ip="198.51.100.44",
                failed=3,
                disposition_counts={"none": 3},
                observed_at=current,
                first_seen=current,
                last_seen=current,
            ),
            _projection(
                domain.id,
                ip="198.51.100.99",
                failed=300,
                disposition_counts={"none": 300},
                observed_at=current,
                first_seen=current,
                last_seen=current,
            ),
        ]
    )
    record_sender_classification(
        db_session,
        workspace=workspace,
        domain="example.test",
        source_ip="198.51.100.44",
        classification="legitimate",
        reason="Primary transactional sender",
        auth_context={"auth_type": "disabled"},
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "action_required"
    assert result["confidence_band"] == "high"
    assert "previous window" in " ".join(result["known_facts"])
    assert "operator classified" in " ".join(result["confidence_reasons"]).lower()
    assert "known provider" not in " ".join(result["confidence_reasons"]).lower()
    assert result["supporting_signals"][0]["payload"]["source_ip"] == "198.51.100.44"
    classification_claim = next(
        claim for claim in result["claims"] if "operator classified" in claim["statement"].lower()
    )
    assert classification_claim["claim_level"] == "operator_reported"


def test_expected_forwarding_never_recommends_adding_intermediary_to_spf(db_session):
    workspace = Workspace(slug="guided-forwarding", name="Guided forwarding")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(
        _projection(
            domain.id,
            ip="198.51.100.45",
            failed=8,
            disposition_counts={"none": 8},
        )
    )
    record_sender_classification(
        db_session,
        workspace=workspace,
        domain="example.test",
        source_ip="198.51.100.45",
        classification="expected_forwarding",
        reason="Known list forwarder",
        auth_context={"auth_type": "disabled"},
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "monitor"
    assert result["conclusion"]["key"] == "mail_health.expected_forwarding"
    assert "do not add" in result["summary"].lower()
    assert "SPF" not in result["next_action"]["label"]


def test_expected_forwarding_does_not_hide_an_unrecognized_unprotected_failure(db_session):
    workspace = Workspace(slug="guided-forwarding-mixed", name="Guided forwarding mixed")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add_all(
        [
            _projection(
                domain.id,
                ip="198.51.100.45",
                failed=20,
                disposition_counts={"none": 20},
            ),
            _projection(
                domain.id,
                ip="198.51.100.47",
                failed=2,
                disposition_counts={"none": 2},
            ),
        ]
    )
    record_sender_classification(
        db_session,
        workspace=workspace,
        domain="example.test",
        source_ip="198.51.100.45",
        classification="expected_forwarding",
        reason="Known list forwarder",
        auth_context={"auth_type": "disabled"},
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "investigation_required"
    assert result["supporting_signals"][0]["payload"]["source_ip"] == "198.51.100.47"


def test_explicit_unauthorized_source_does_not_request_classification_again(db_session):
    workspace = Workspace(slug="guided-unauthorized", name="Guided unauthorized")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(
        _projection(
            domain.id,
            ip="198.51.100.46",
            failed=9,
            disposition_counts={"none": 9},
        )
    )
    record_sender_classification(
        db_session,
        workspace=workspace,
        domain="example.test",
        source_ip="198.51.100.46",
        classification="unauthorized",
        reason="Confirmed outside the mail estate",
        auth_context={"auth_type": "disabled"},
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "action_required"
    assert result["conclusion"]["key"] == "mail_health.confirmed_unauthorized_use_unprotected"
    assert "classif" not in result["next_action"]["label"].lower()
    assert any(claim["claim_level"] == "operator_reported" for claim in result["claims"])


def test_unknown_unprotected_failure_outranks_confirmed_blocked_abuse(db_session):
    workspace = Workspace(slug="guided-unauthorized-mixed", name="Guided unauthorized mixed")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add_all(
        [
            _projection(
                domain.id,
                ip="198.51.100.46",
                failed=90,
                disposition_counts={"reject": 90},
            ),
            _projection(
                domain.id,
                ip="198.51.100.47",
                failed=2,
                disposition_counts={"none": 2},
            ),
        ]
    )
    record_sender_classification(
        db_session,
        workspace=workspace,
        domain="example.test",
        source_ip="198.51.100.46",
        classification="unauthorized",
        reason="Confirmed abuse already blocked by receivers",
        auth_context={"auth_type": "disabled"},
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "investigation_required"
    assert result["supporting_signals"][0]["payload"]["source_ip"] == "198.51.100.47"


def test_ipv6_operator_classification_matches_noncanonical_projection_spelling(db_session):
    workspace = Workspace(slug="guided-ipv6", name="Guided IPv6")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(
        _projection(
            domain.id,
            ip="2001:0db8:0000:0000:0000:0000:0000:0001",
            failed=2,
            disposition_counts={"none": 2},
        )
    )
    record_sender_classification(
        db_session,
        workspace=workspace,
        domain="example.test",
        source_ip="2001:db8::1",
        classification="legitimate",
        reason="Owned IPv6 sender",
        auth_context={"auth_type": "disabled"},
    )

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "action_required"
    assert result["supporting_signals"][0]["payload"]["source_ip"] == "2001:db8::1"


def test_connected_low_volume_workspace_without_reports_is_a_watch_state(db_session):
    workspace = Workspace(
        slug="guided-low-volume",
        name="Guided low volume",
        guidance_mail_context='{"low_volume":true}',
    )
    db_session.add(workspace)
    db_session.flush()
    db_session.add(
        MailSource(workspace_id=workspace.id, name="Reports", method="IMAP", enabled=True)
    )
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "monitor"
    assert result["urgency_band"] == "watch"
    assert result["next_action"]["href"] == "/mail-sources"
    assert "No urgent failure" in result["summary"]


def test_dmarc_pass_with_operator_reported_bounce_requires_delivery_evidence(db_session):
    workspace = Workspace(
        slug="guided-bounce-mismatch",
        name="Guided bounce mismatch",
        guidance_mail_context='{"bounce_available":true}',
    )
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(_projection(domain.id, ip="203.0.113.26", passed=12))
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "insufficient_evidence"
    assert result["conclusion"]["key"] == "mail_health.dmarc_pass_bounce_mismatch"
    assert "SMTP" in result["summary"]
    assert result["delivery_certainty"] == "inferred_only"


def test_bounce_context_does_not_claim_an_unselected_domain_explains_the_bounce(db_session):
    workspace = Workspace(
        slug="guided-bounce-domain",
        name="Guided bounce domain",
        guidance_mail_context='{"bounce_available":true,"domains":["bounce.test"]}',
    )
    bounce_domain = Domain(name="bounce.test", workspace=workspace)
    healthy_domain = Domain(name="healthy.test", workspace=workspace)
    db_session.add_all([workspace, bounce_domain, healthy_domain])
    db_session.flush()
    db_session.add(_projection(healthy_domain.id, ip="203.0.113.40", passed=40))
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "healthy"
    assert result["domain"] is None
    assert result["conclusion"]["key"] != "mail_health.dmarc_pass_bounce_mismatch"


def test_stale_report_evidence_limits_confidence(db_session):
    workspace = Workspace(slug="guided-stale", name="Guided stale")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    stale = int(datetime(2026, 7, 10, tzinfo=timezone.utc).timestamp())
    db_session.add(
        _projection(
            domain.id,
            ip="203.0.113.26",
            passed=12,
            observed_at=stale,
            first_seen=stale,
            last_seen=stale,
        )
    )
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "healthy"
    assert result["freshness"] == "stale"
    assert result["confidence_band"] == "medium"
    assert result["freshness_at"] == datetime.fromtimestamp(stale, tz=timezone.utc).isoformat()
    assert {signal["freshness"] for signal in result["supporting_signals"]} == {"stale"}


def test_selected_stale_source_is_not_masked_by_unrelated_fresh_evidence(db_session):
    workspace = Workspace(slug="guided-selected-stale", name="Guided selected stale")
    stale_domain = Domain(name="stale.test", workspace=workspace)
    fresh_domain = Domain(name="fresh.test", workspace=workspace)
    db_session.add_all([workspace, stale_domain, fresh_domain])
    db_session.flush()
    stale = int(datetime(2026, 7, 10, tzinfo=timezone.utc).timestamp())
    fresh = int(datetime(2026, 7, 29, tzinfo=timezone.utc).timestamp())
    db_session.add_all(
        [
            _projection(
                stale_domain.id,
                ip="203.0.113.26",
                failed=4,
                hostname="mta1.mtasv.net",
                observed_at=stale,
                first_seen=stale,
                last_seen=stale,
            ),
            _projection(
                fresh_domain.id,
                ip="203.0.113.27",
                passed=100,
                observed_at=fresh,
                first_seen=fresh,
                last_seen=fresh,
            ),
        ]
    )
    db_session.commit()

    result = _assessment(db_session, workspace)

    assert result["outcome"] == "action_required"
    assert result["domain"] == "stale.test"
    assert result["freshness"] == "stale"
    assert result["freshness_at"] == datetime.fromtimestamp(stale, tz=timezone.utc).isoformat()
    assert {signal["freshness"] for signal in result["supporting_signals"]} == {"stale"}


def test_assessment_id_identifies_the_exact_evidence_window(db_session):
    workspace = Workspace(slug="guided-assessment-id", name="Guided assessment ID")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    db_session.add(_projection(domain.id, ip="203.0.113.26", passed=12))
    db_session.commit()
    start = int(datetime(2026, 7, 1, tzinfo=timezone.utc).timestamp())
    first_end = int(datetime(2026, 7, 30, tzinfo=timezone.utc).timestamp())
    second_end = int(datetime(2026, 7, 31, tzinfo=timezone.utc).timestamp())

    first = build_workspace_mail_health_assessment(
        db_session, workspace=workspace, start_ts=start, end_ts=first_end
    )
    repeated = build_workspace_mail_health_assessment(
        db_session, workspace=workspace, start_ts=start, end_ts=first_end
    )
    shifted = build_workspace_mail_health_assessment(
        db_session, workspace=workspace, start_ts=start, end_ts=second_end
    )

    assert first["assessment_id"] == repeated["assessment_id"]
    assert first["assessment_id"] != shifted["assessment_id"]


def test_assessment_id_changes_when_existing_projection_evidence_changes(db_session):
    workspace = Workspace(slug="guided-assessment-revision", name="Guided revision")
    domain = Domain(name="example.test", workspace=workspace)
    db_session.add_all([workspace, domain])
    db_session.flush()
    projection = _projection(domain.id, ip="203.0.113.26", passed=12)
    db_session.add(projection)
    db_session.commit()

    first = _assessment(db_session, workspace)
    projection.dmarc_pass_count = 13
    projection.message_count = 13
    db_session.commit()
    revised = _assessment(db_session, workspace)

    assert (
        first["supporting_signals"][0]["signal_id"] == revised["supporting_signals"][0]["signal_id"]
    )
    assert first["assessment_id"] != revised["assessment_id"]
