"""Contract tests for protocol-aware mail-health signals."""

import pytest

from app.services.mail_signals import (
    CLAIM_LEVELS,
    DELIVERY_CERTAINTIES,
    MAIL_SIGNAL_SCHEMA_VERSION,
    SIGNAL_FAMILIES,
    build_dmarc_source_signals,
    build_intake_window_signal,
    guided_signal_statement,
    make_mail_signal,
    signal_families,
)


def test_signal_taxonomy_covers_current_and_planned_evidence_families():
    assert set(signal_families()) == SIGNAL_FAMILIES
    assert SIGNAL_FAMILIES == {
        "dmarc_authentication",
        "dmarc_reported_disposition",
        "dmarc_failure_detail",
        "smtp_tls_report",
        "dsn_delivery_status",
        "provider_delivery_event",
        "dns_posture",
        "intake_health",
        "operator_reported_symptom",
    }
    assert "observed" in CLAIM_LEVELS
    assert "operator_reported" in CLAIM_LEVELS
    assert "authentication_only" in DELIVERY_CERTAINTIES
    assert "non_delivery_reported" in DELIVERY_CERTAINTIES


@pytest.mark.parametrize("family", sorted(SIGNAL_FAMILIES))
def test_common_envelope_accepts_every_versioned_signal_family(family):
    signal = make_mail_signal(
        family=family,
        signal_type="contract_test",
        outcome="unknown",
        claim_level="unknown",
        delivery_certainty="not_applicable",
        source_system="test",
        evidence_refs=("test:1",),
    ).to_dict()

    assert signal["schema_version"] == MAIL_SIGNAL_SCHEMA_VERSION
    assert signal["family"] == family
    assert len(signal["signal_id"]) == 64


def test_signal_identity_is_stable_but_changes_with_immutable_evidence_reference():
    values = {
        "family": "dns_posture",
        "signal_type": "dmarc_record",
        "outcome": "present",
        "claim_level": "observed",
        "delivery_certainty": "not_applicable",
        "source_system": "dns_posture_snapshot",
        "workspace_id": 7,
        "domain": "example.test",
        "evidence_refs": ("dns_posture_snapshot:41",),
    }
    first = make_mail_signal(**values)
    repeated = make_mail_signal(**values)
    changed = make_mail_signal(**{**values, "evidence_refs": ("dns_posture_snapshot:42",)})

    assert first.signal_id == repeated.signal_id
    assert first.signal_id != changed.signal_id


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("family", "smtp_guess", "family"),
        ("claim_level", "probably", "claim level"),
        ("delivery_certainty", "maybe_delivered", "delivery certainty"),
        ("privacy_classification", "public_body", "privacy classification"),
    ],
)
def test_common_envelope_rejects_unknown_contract_values(field, value, message):
    values = {
        "family": "dns_posture",
        "signal_type": "contract_test",
        "outcome": "unknown",
        "claim_level": "unknown",
        "delivery_certainty": "not_applicable",
        "source_system": "test",
    }
    values[field] = value

    with pytest.raises(ValueError, match=message):
        make_mail_signal(**values)


def test_dmarc_source_creates_separate_authentication_and_disposition_signals():
    signals = build_dmarc_source_signals(
        {
            "source_ip": "192.0.2.10",
            "dmarc_pass_count": 4,
            "dmarc_fail_count": 6,
            "disposition_counts": {"none": 2, "reject": 4},
            "window_start": 100,
            "window_end": 200,
            "captured_at": "2026-07-30T00:00:00Z",
            "spf_pass_count": 3,
            "spf_fail_count": 7,
            "dkim_pass_count": 4,
            "dkim_fail_count": 6,
            "header_from_domains": ["example.test"],
            "dkim_domains": ["example.test"],
            "dkim_selectors": ["mail"],
            "report_generators": ["Receiver A"],
        },
        workspace_id=3,
        domain="example.test",
        evidence_refs=("domain_source_daily_projection:10",),
    )

    authentication, disposition = signals
    assert authentication["family"] == "dmarc_authentication"
    assert authentication["outcome"] == "mixed"
    assert authentication["delivery_certainty"] == "authentication_only"
    assert authentication["payload"]["source_ip"] == "192.0.2.10"
    assert authentication["payload"]["passed"] == 4
    assert authentication["payload"]["failed"] == 6
    assert authentication["payload"]["spf_passed"] == 3
    assert authentication["payload"]["dkim_failed"] == 6
    assert authentication["payload"]["header_from_domains"] == ["example.test"]
    assert authentication["payload"]["dkim_selectors"] == ["mail"]
    assert authentication["payload"]["report_generators"] == ["Receiver A"]
    assert disposition["family"] == "dmarc_reported_disposition"
    assert disposition["outcome"] == "mixed"
    assert disposition["delivery_certainty"] == "receiver_disposition_reported"
    assert disposition["evidence_refs"] == ["domain_source_daily_projection:10"]


def test_missing_report_window_is_a_derived_intake_fact_not_a_delivery_claim():
    signal = build_intake_window_signal(
        workspace_id=5,
        window_start=100,
        window_end=200,
        has_evidence=False,
    )

    assert signal["family"] == "intake_health"
    assert signal["claim_level"] == "derived"
    assert signal["delivery_certainty"] == "not_applicable"
    assert "no persisted report evidence" in guided_signal_statement(signal)


@pytest.mark.parametrize(
    ("signal", "expected", "forbidden"),
    [
        (
            {
                "family": "dmarc_authentication",
                "outcome": "pass",
                "delivery_certainty": "authentication_only",
            },
            "authenticated",
            "delivered",
        ),
        (
            {
                "family": "dmarc_reported_disposition",
                "outcome": "reject",
                "delivery_certainty": "receiver_disposition_reported",
            },
            "recorded",
            "bounced",
        ),
        (
            {
                "family": "provider_delivery_event",
                "outcome": "delivered",
                "delivery_certainty": "delivery_reported",
            },
            "provider reported",
            "inbox",
        ),
    ],
)
def test_guided_wording_matrix_preserves_protocol_boundaries(signal, expected, forbidden):
    statement = guided_signal_statement(signal).lower()

    assert expected in statement
    assert forbidden not in statement
