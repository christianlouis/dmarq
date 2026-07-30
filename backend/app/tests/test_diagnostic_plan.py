"""Scenario coverage for the problem-first diagnostic planner."""

import pytest

from app.services.diagnostic_plan import DiagnosticEvidence, build_diagnostic_plan


def _profile(goal, **context):
    return {"installation_goals": [goal], "mail_context": context}


@pytest.mark.parametrize(
    ("profile", "evidence", "expected_action"),
    [
        (
            _profile("continuous_monitoring", controls_dns=True),
            DiagnosticEvidence(
                domain_names=("monitor.example",),
                selected_domain="monitor.example",
                dns_evidence_available=True,
            ),
            "publish_monitoring_dmarc",
        ),
        (
            _profile("understand_reports"),
            DiagnosticEvidence(
                domain_names=("reports.example",),
                selected_domain="reports.example",
                has_dmarc=True,
                dns_evidence_available=True,
                report_count=3,
                message_count=25,
                latest_report_id=17,
            ),
            "explain_report",
        ),
        (
            _profile("troubleshoot_delivery", known_mail_providers=["Example SaaS"]),
            DiagnosticEvidence(
                domain_names=("sender.example",),
                selected_domain="sender.example",
                has_dmarc=True,
                dns_evidence_available=True,
                report_count=2,
                message_count=100,
                failed_message_count=12,
            ),
            "review_failing_senders",
        ),
        (
            _profile("protect_against_spoofing", domain_sends_mail=False),
            DiagnosticEvidence(
                domain_names=("parked.example",),
                selected_domain="parked.example",
                has_dmarc=True,
                dns_evidence_available=True,
                report_count=2,
                message_count=40,
                failed_message_count=40,
            ),
            "review_protected_spoofing",
        ),
        (
            _profile("investigate_bounces", bounce_available=True),
            DiagnosticEvidence(
                domain_names=("bounce.example",),
                selected_domain="bounce.example",
                has_dmarc=True,
                dns_evidence_available=True,
            ),
            "review_bounce_evidence",
        ),
        (
            _profile("continuous_monitoring", low_volume=True),
            DiagnosticEvidence(
                domain_names=("personal.example",),
                selected_domain="personal.example",
                has_dmarc=True,
                dns_evidence_available=True,
                enabled_source_count=1,
            ),
            "verify_report_intake",
        ),
        (
            _profile("continuous_monitoring"),
            DiagnosticEvidence(
                domain_names=("ready.example",),
                selected_domain="ready.example",
                has_dmarc=True,
                dns_evidence_available=True,
                report_count=4,
                message_count=90,
                enabled_source_count=1,
            ),
            "open_domain",
        ),
        (
            _profile("continuous_monitoring", controls_dns=False),
            DiagnosticEvidence(
                domain_names=("handoff.example",),
                selected_domain="handoff.example",
                dns_evidence_available=True,
            ),
            "prepare_dns_handoff",
        ),
    ],
)
def test_problem_first_scenarios_choose_one_current_action(profile, evidence, expected_action):
    plan = build_diagnostic_plan(profile, evidence)

    assert plan["schema"] == "dmarq.diagnostic_plan.v1"
    assert plan["generated_from"] == "persisted_evidence"
    assert plan["current_action"]["id"] == expected_action
    assert plan["current_action"]["label"]
    assert plan["current_action"]["verification"]
    assert len(plan["later_steps"]) <= 4


def test_no_domain_starts_with_a_non_mutating_domain_action():
    plan = build_diagnostic_plan(_profile("learn_or_explore"), DiagnosticEvidence())

    assert plan["current_action"]["id"] == "add_domain"
    assert plan["current_action"]["href"] == "/domains"
    assert "does not change DNS" in plan["current_action"]["why"]
    assert {step["id"] for step in plan["later_steps"]}.isdisjoint(
        {"classify_senders", "open_evidence"}
    )


def test_requested_unmonitored_domain_is_not_replaced_with_an_existing_domain():
    plan = build_diagnostic_plan(
        _profile("continuous_monitoring", domains=["new.example"]),
        DiagnosticEvidence(
            domain_names=("existing.example",),
            selected_domain=None,
            has_dmarc=True,
            dns_evidence_available=True,
            report_count=3,
        ),
    )

    assert plan["domain"] is None
    assert plan["current_action"]["id"] == "add_domain"


def test_missing_dns_evidence_is_not_treated_as_confirmed_missing_dmarc():
    plan = build_diagnostic_plan(
        _profile("continuous_monitoring", controls_dns=True),
        DiagnosticEvidence(
            domain_names=("unknown.example",),
            selected_domain="unknown.example",
            dns_evidence_available=False,
        ),
    )

    assert plan["conclusion"]["code"] == "insufficient_evidence"
    assert plan["current_action"]["id"] == "inspect_dns_evidence"


def test_delivery_goal_uses_available_bounce_evidence_first():
    plan = build_diagnostic_plan(
        _profile("troubleshoot_delivery", bounce_available=True),
        DiagnosticEvidence(
            domain_names=("bounce.example",),
            selected_domain="bounce.example",
        ),
    )

    assert plan["current_action"]["id"] == "review_bounce_evidence"


def test_delivery_problem_uses_bounce_evidence_when_the_interview_has_it():
    plan = build_diagnostic_plan(
        _profile("troubleshoot_delivery", bounce_available=True),
        DiagnosticEvidence(domain_names=("bounce.example",), selected_domain="bounce.example"),
    )

    assert plan["current_action"]["id"] == "review_bounce_evidence"


def test_low_volume_waiting_is_explained_without_claiming_intake_is_broken():
    plan = build_diagnostic_plan(
        _profile("continuous_monitoring", low_volume=True),
        DiagnosticEvidence(
            domain_names=("quiet.example",),
            selected_domain="quiet.example",
            has_dmarc=True,
            dns_evidence_available=True,
            enabled_source_count=1,
        ),
    )

    assert plan["current_action"]["id"] == "verify_report_intake"
    assert "low-volume" in plan["inferences"][0]


def test_copy_is_available_in_english_and_german():
    evidence = DiagnosticEvidence(
        domain_names=("example.com",),
        selected_domain="example.com",
        dns_evidence_available=True,
    )

    english = build_diagnostic_plan(
        _profile("continuous_monitoring", controls_dns=True), evidence, locale="en"
    )
    german = build_diagnostic_plan(
        _profile("continuous_monitoring", controls_dns=True), evidence, locale="de"
    )

    assert english["current_action"]["title"] == "Publish a monitoring-only DMARC record"
    assert german["current_action"]["title"] == "DMARC zunächst nur zur Beobachtung einrichten"
    assert english["current_action"]["title"] != german["current_action"]["title"]
