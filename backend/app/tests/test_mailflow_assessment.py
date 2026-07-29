"""Tests for the report-backed domain mailflow diagnosis."""

from app.services.mailflow_assessment import build_domain_mailflow_assessment


def _source(**overrides):
    source = {
        "source_ip": "192.0.2.10",
        "count": 12,
        "spf_pass_count": 12,
        "spf_fail_count": 0,
        "dkim_pass_count": 0,
        "dkim_fail_count": 12,
        "dmarc_pass_count": 12,
        "dmarc_fail_count": 0,
        "dmarc_result": "pass",
        "disposition": "none",
        "disposition_counts": {"none": 12},
        "header_from_domains": ["example.com"],
        "envelope_from_domains": ["bounce.example.com"],
        "spf_domains": ["example.com"],
        "dkim_domains": [],
        "dkim_selectors": [],
    }
    source.update(overrides)
    return source


def test_spf_aligned_path_without_dkim_gets_guided_repair():
    result = build_domain_mailflow_assessment(
        "example.com",
        [_source()],
        {"192.0.2.10": {"name": "Unknown sender", "status": "unknown"}},
    )

    assert result["status"] == "action_required"
    assert result["counts"]["aligned_dkim_not_observed"] == 1
    assert result["repair_steps"]
    assert result["flows"][0]["spf_alignment"] == "pass"
    assert result["flows"][0]["dkim_alignment"] == "not_observed"
    assert result["flows"][0]["provider_evidence_status"] == "not_connected"
    assert "cannot tell" in result["flows"][0]["detail"]


def test_unknown_rejected_spoofer_does_not_get_dkim_repair():
    result = build_domain_mailflow_assessment(
        "example.com",
        [
            _source(
                spf_pass_count=0,
                spf_fail_count=7,
                dkim_fail_count=7,
                dmarc_pass_count=0,
                dmarc_fail_count=7,
                dmarc_result="fail",
                disposition="reject",
                disposition_counts={"reject": 7},
            )
        ],
        {"192.0.2.10": {"name": "Unknown sender", "status": "unknown"}},
    )

    assert result["status"] == "no_action_likely_unauthorized_use"
    assert result["repair_steps"] == []
    assert result["flows"][0]["status"] == "likely_unauthorized"
    assert result["flows"][0]["evidence_level"] == "inferred"
    assert result["inferences"]
    assert result["unknowns"]


def test_known_provider_without_alignment_does_not_get_dkim_repair():
    result = build_domain_mailflow_assessment(
        "example.com",
        [
            _source(
                spf_pass_count=0,
                spf_fail_count=7,
                dkim_fail_count=7,
                dmarc_pass_count=0,
                dmarc_fail_count=7,
                dmarc_result="fail",
                disposition="reject",
                disposition_counts={"reject": 7},
            )
        ],
        {"192.0.2.10": {"name": "Shared provider", "status": "known"}},
    )

    assert result["status"] == "no_action_likely_unauthorized_use"
    assert result["repair_steps"] == []


def test_known_sender_with_aligned_dkim_is_healthy():
    result = build_domain_mailflow_assessment(
        "example.com",
        [_source(dkim_pass_count=12, dkim_fail_count=0)],
        {"192.0.2.10": {"name": "Owned infrastructure", "status": "known"}},
    )

    assert result["status"] == "healthy"
    assert result["flows"][0]["status"] == "healthy"
    assert result["flows"][0]["dkim_alignment"] == "pass"


def test_aligned_dkim_is_healthy_without_provider_recognition():
    result = build_domain_mailflow_assessment(
        "example.com",
        [_source(spf_pass_count=0, spf_fail_count=12, dkim_pass_count=12, dkim_fail_count=0)],
        {"192.0.2.10": {"name": "Unclassified sender", "status": "unknown"}},
    )

    assert result["status"] == "healthy"
    assert result["flows"][0]["status"] == "healthy"


def test_known_sender_dmarc_failure_requests_alignment_review():
    result = build_domain_mailflow_assessment(
        "example.com",
        [
            _source(
                spf_pass_count=0,
                spf_fail_count=12,
                dkim_pass_count=0,
                dkim_fail_count=0,
                dmarc_pass_count=0,
                dmarc_fail_count=12,
                dmarc_result="fail",
                disposition="none",
                disposition_counts={"none": 12},
            )
        ],
        {"192.0.2.10": {"name": "Known provider", "status": "known"}},
    )

    flow = result["flows"][0]
    assert result["status"] == "investigation_required"
    assert flow["status"] == "investigate_alignment"
    assert flow["evidence_level"] == "inferred"
    assert "known sending service" in flow["detail"]
    assert result["inferences"]
    assert result["unknowns"]


def test_zero_traffic_is_ignored():
    result = build_domain_mailflow_assessment(
        "example.com",
        [_source(count=0, spf_pass_count=0, dkim_fail_count=0)],
        {},
    )

    assert result["status"] == "insufficient_evidence"
    assert result["flows"] == []


def test_mixed_dkim_path_requires_identity_correlation_before_repair():
    result = build_domain_mailflow_assessment(
        "example.com",
        [
            _source(
                dkim_pass_count=8,
                dkim_fail_count=4,
                dkim_domains=["example.com", "relay.example.net"],
                dkim_selectors=["mail", "relay"],
            )
        ],
        {"192.0.2.10": {"name": "Owned infrastructure", "status": "known"}},
    )

    flow = result["flows"][0]
    assert flow["status"] == "intermittent_dkim_alignment"
    assert flow["dkim_domains"] == ["example.com", "relay.example.net"]
    assert flow["dkim_selectors"] == ["mail", "relay"]
    assert "cannot identify which value" in flow["detail"]
    assert result["status"] == "investigation_required"
    assert result["repair_steps"] == []
