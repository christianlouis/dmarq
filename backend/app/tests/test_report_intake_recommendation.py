"""Deterministic scenarios for the guided report-intake chooser."""

import pytest

from app.services.report_intake_recommendation import (
    OPTION_ORDER,
    ReportIntakeEvidence,
    build_report_intake_recommendation,
)


def _profile(*, sovereignty="not_sure", goals=None, **context):
    return {
        "sovereignty_preference": sovereignty,
        "installation_goals": goals or [],
        "mail_context": context,
    }


def test_privacy_first_with_a_local_bridge_recommends_proton_bridge():
    result = build_report_intake_recommendation(
        _profile(
            sovereignty="privacy_first",
            local_bridge_available=True,
            setup_effort="maximum_control",
            continuous_monitoring=True,
        ),
        ReportIntakeEvidence(),
    )

    assert result["recommended"]["id"] == "proton_bridge"
    assert result["recommended"]["available"] is True


def test_maximum_control_without_a_bridge_recommends_local_imap():
    result = build_report_intake_recommendation(
        _profile(
            sovereignty="keep_data_local",
            local_bridge_available=False,
            setup_effort="maximum_control",
            continuous_monitoring=True,
        ),
        ReportIntakeEvidence(),
    )

    assert result["recommended"]["id"] == "local_imap"
    proton = next(item for item in result["alternatives"] if item["id"] == "proton_bridge")
    assert proton["available"] is False


def test_known_microsoft_provider_guides_convenience_setup_to_m365():
    result = build_report_intake_recommendation(
        _profile(
            sovereignty="convenience_first",
            known_mail_providers=["Microsoft 365"],
            setup_effort="simplest",
            continuous_monitoring=True,
        ),
        ReportIntakeEvidence(public_base_url="https://dmarq.example"),
    )

    assert result["recommended"]["id"] == "m365"


def test_manual_evaluation_is_preferred_without_continuous_monitoring():
    result = build_report_intake_recommendation(
        _profile(
            sovereignty="not_sure",
            setup_effort="simplest",
            continuous_monitoring=False,
        ),
        ReportIntakeEvidence(),
    )

    assert result["recommended"]["id"] == "manual_upload"


def test_unavailable_public_webhook_path_does_not_become_the_recommendation():
    result = build_report_intake_recommendation(
        _profile(
            report_intake_preference="cloudflare_worker",
            dns_provider="Cloudflare",
            continuous_monitoring=True,
        ),
        ReportIntakeEvidence(public_base_url="http://dmarq.internal"),
    )

    assert result["recommended"]["id"] != "cloudflare_worker"
    worker = next(item for item in result["alternatives"] if item["id"] == "cloudflare_worker")
    assert worker["available"] is False
    assert "HTTPS" in worker["availability_reason"]


def test_existing_gmail_source_and_reports_are_recognized_as_working():
    result = build_report_intake_recommendation(
        _profile(continuous_monitoring=True),
        ReportIntakeEvidence(
            source_methods=("GMAIL_API",),
            source_labels=("Gmail reports@example.com",),
            enabled_source_count=1,
            checked_source_count=1,
            total_report_count=7,
            latest_report_id=42,
            domain_name="mail.example",
            report_destination_configured=True,
            dmarc_reporting_configured=True,
        ),
    )

    assert result["recommended"]["id"] == "gmail"
    assert result["recommended"]["already_configured"] is True
    assert result["first_report"]["state"] == "working"
    assert all(item["complete"] for item in result["verification"])
    assert result["primary_action"] == {
        "label": "Open latest interpretation",
        "href": "/reports/42",
    }
    assert len(result["journey"]) == 8
    assert result["journey"][-1]["complete"] is True


def test_configured_source_without_reporting_dns_guides_the_dns_step():
    result = build_report_intake_recommendation(
        _profile(continuous_monitoring=True),
        ReportIntakeEvidence(
            source_methods=("IMAP",),
            enabled_source_count=1,
            checked_source_count=1,
            domain_name="mail.example",
            report_destination_configured=True,
            dmarc_reporting_configured=False,
        ),
    )

    assert result["primary_action"] == {
        "label": "Prepare reporting DNS",
        "href": "/domains/mail.example#dns-records",
    }
    assert result["journey"][0]["complete"] is True
    assert result["journey"][1]["complete"] is False


@pytest.mark.parametrize(
    ("evidence", "state"),
    [
        (
            ReportIntakeEvidence(
                enabled_source_count=1,
                latest_import_duplicates=2,
            ),
            "duplicate",
        ),
        (
            ReportIntakeEvidence(
                enabled_source_count=1,
                latest_import_errors=3,
            ),
            "rejected",
        ),
        (ReportIntakeEvidence(enabled_source_count=1), "waiting"),
    ],
)
def test_first_report_outcomes_are_explicit(evidence, state):
    result = build_report_intake_recommendation(_profile(continuous_monitoring=True), evidence)

    assert result["first_report"]["state"] == state


def test_catalog_is_complete_and_german_copy_is_localized():
    result = build_report_intake_recommendation(
        _profile(report_intake_preference="manual_upload"),
        ReportIntakeEvidence(),
        locale="de-DE",
    )

    option_ids = {result["recommended"]["id"]} | {item["id"] for item in result["alternatives"]}
    assert option_ids == set(OPTION_ORDER)
    assert result["recommended"]["title"] == "Vorhandenen Report hochladen"
    assert result["schema"] == "dmarq.report_intake_recommendation.v1"
