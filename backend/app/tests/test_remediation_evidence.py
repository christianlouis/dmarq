from app.services.remediation_evidence import evidence_refresh_for_remediation_item


def test_evidence_refresh_blocks_provider_prerequisite_until_value_is_collected():
    refresh = evidence_refresh_for_remediation_item(
        "example.com",
        {
            "source": "dns_lint",
            "prerequisites": ["Provider-specific DKIM target is missing"],
            "verification_plan": {
                "stale_evidence_warning": "provider target required",
                "next_check": "after provider publishes the target",
            },
        },
    )

    assert refresh["source"] == "mail_provider"
    assert refresh["refresh_key"] == "provider_value"
    assert refresh["safe_to_run"] is False
    assert refresh["ui_anchor"] == "#dns-guidance"
    assert refresh["endpoint_hint"] == ""
    assert refresh["stale_warning"] == "provider target required"
    assert refresh["next_check"] == "after provider publishes the target"


def test_evidence_refresh_uses_dns_for_provider_preview_and_manual_dns_paths():
    provider_refresh = evidence_refresh_for_remediation_item(
        "example.com",
        {"automation": {"eligible": True}},
    )
    manual_refresh = evidence_refresh_for_remediation_item(
        "example.com",
        {"source": "dns_lint", "prerequisites": ["publish TXT record"]},
    )

    assert provider_refresh["source"] == "dns"
    assert provider_refresh["refresh_key"] == "dns"
    assert provider_refresh["endpoint_hint"] == "/api/v1/domains/example.com/dns?refresh=true"
    assert manual_refresh["source"] == "dns"
    assert manual_refresh["safe_to_run"] is True


def test_evidence_refresh_uses_reputation_for_sending_ip_risk():
    refresh = evidence_refresh_for_remediation_item(
        "example.com",
        {"incident_type": "sending_ip_reputation_risk"},
    )

    assert refresh["source"] == "source_reputation"
    assert refresh["refresh_key"] == "source_reputation"
    assert refresh["ui_anchor"] == "#sending-sources"
    assert refresh["endpoint_hint"] == "/api/v1/domains/example.com/sources?refresh=true"


def test_evidence_refresh_uses_reports_and_sources_for_investigations():
    refresh = evidence_refresh_for_remediation_item(
        "example.com",
        {"state": "investigate"},
    )

    assert refresh["source"] == "dmarc_reports_and_sources"
    assert refresh["refresh_key"] == "reports_and_sources"
    assert refresh["ui_anchor"] == "#sending-sources"
    assert refresh["endpoint_hint"] == "/api/v1/domains/example.com/sources?refresh=true"


def test_evidence_refresh_defaults_to_report_reload_for_manual_items():
    refresh = evidence_refresh_for_remediation_item("example.com", {})

    assert refresh["source"] == "dmarc_reports"
    assert refresh["refresh_key"] == "reports"
    assert refresh["ui_anchor"] == "#reports"
    assert refresh["endpoint_hint"] == "/api/v1/domains/example.com/reports"
