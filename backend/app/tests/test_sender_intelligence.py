from app.services.sender_intelligence import identify_sender


def test_identify_sender_matches_known_provider_from_hostname_and_selector():
    source = {
        "dkim_selectors": ["google"],
        "spf_domains": ["_spf.google.com"],
        "dmarc_result": "pass",
        "dmarc_fail_count": 0,
    }

    sender = identify_sender(
        "203.0.113.75",
        source,
        hostname="mail-qv1-f75.google.com",
        domain="example.com",
    )

    assert sender["id"] == "google-workspace"
    assert sender["name"] == "Google Workspace"
    assert sender["status"] == "known"
    assert sender["confidence"] == 95
    assert sender["evidence"]
    assert "Google Workspace DKIM" in sender["remediation_hint"]


def test_identify_sender_flags_ambiguous_provider_evidence():
    source = {
        "spf_domains": ["google.com", "stripe.com"],
        "dmarc_result": "pass",
    }

    sender = identify_sender("203.0.113.7", source, hostname=None, domain="example.com")

    assert sender["id"] == "ambiguous-sender"
    assert sender["status"] == "ambiguous"
    assert sender["confidence"] == 40
    assert "Confirm the service owner" in sender["remediation_hint"]


def test_identify_sender_keeps_unknown_failing_source_distinct():
    source = {
        "dmarc_result": "fail",
        "dmarc_fail_count": 8,
    }

    sender = identify_sender("192.0.2.99", source, hostname=None, domain="example.com")

    assert sender["id"] == "unknown-sender"
    assert sender["status"] == "suspicious"
    assert sender["confidence"] == 0
    assert "before authorizing it" in sender["remediation_hint"]


def test_identify_sender_recognizes_owned_infrastructure():
    source = {
        "dmarc_result": "pass",
        "dmarc_fail_count": 0,
    }

    sender = identify_sender(
        "203.0.113.10",
        source,
        hostname="primary-saas.mail.dmarq.org",
        domain="dmarq.org",
    )

    assert sender["id"] == "owned-infrastructure"
    assert sender["name"] == "Owned infrastructure"
    assert sender["status"] == "known"
