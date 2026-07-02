from app.services.sender_intelligence import (
    build_source_intelligence,
    identify_sender,
    source_geo_for,
)


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


def test_identify_sender_matches_postmark_mtasv_domains():
    source = {
        "spf_domains": ["pm.mtasv.net"],
        "dkim_domains": ["example.com"],
        "dmarc_result": "pass",
    }

    sender = identify_sender(
        "203.0.113.88",
        source,
        hostname="a1234.smtp-out.mtasv.net",
        domain="example.com",
    )

    assert sender["id"] == "postmark"
    assert sender["name"] == "Postmark"
    assert sender["status"] == "known"
    assert sender["docs_url"] == (
        "https://postmarkapp.com/support/article/910-how-do-i-add-a-custom-return-path"
    )


def test_identify_sender_matches_major_email_service_domains():
    cases = [
        ("mailgun", "mailgun.org", "mxa.mailgun.org"),
        ("sparkpost", "sparkpostmail.com", "mta.sparkpostmail.com"),
        ("mailjet", "spf.mailjet.com", "mailjet.com"),
        ("brevo", "sender-sib.com", "kh.d.sender-sib.com"),
        ("klaviyo", "klaviyomail.com", "send.klaviyomail.com"),
        ("hubspot", "hubspotemail.net", "smtp.hubspotemail.net"),
        ("constant-contact", "auth.ccsend.com", "mail.auth.ccsend.com"),
        ("zoho-mail", "one.zoho.com", "sender.zohomail.com"),
    ]

    for expected_id, auth_domain, hostname in cases:
        sender = identify_sender(
            "203.0.113.90",
            {
                "spf_domains": [auth_domain],
                "dmarc_result": "pass",
            },
            hostname=hostname,
            domain="example.com",
        )
        assert sender["id"] == expected_id
        assert sender["status"] == "known"
        assert sender["confidence"] >= 55
        assert sender["remediation_hint"]
        assert sender["docs_url"]


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


def test_source_geo_prefers_report_metadata():
    geo = source_geo_for(
        "198.51.100.88",
        {
            "extensions": {
                "demo:country": "France",
                "demo:country_code": "FR",
                "demo:region": "Europe",
                "demo:asn": "AS64555",
                "demo:network": "Example Relay",
            }
        },
    )

    assert geo["country"] == "France"
    assert geo["country_code"] == "FR"
    assert geo["region"] == "Europe"
    assert geo["asn"] == "AS64555"
    assert geo["network"] == "Example Relay"
    assert geo["source"] == "metadata"


def test_source_geo_handles_private_and_invalid_addresses():
    private_geo = source_geo_for("10.0.0.8")
    invalid_geo = source_geo_for("not-an-ip")

    assert private_geo["region"] == "Private or reserved"
    assert private_geo["network"] == "Private or reserved address space"
    assert invalid_geo["region"] == "Unknown"


def test_identify_sender_can_match_report_extension_metadata():
    sender = identify_sender(
        "203.0.113.12",
        {
            "dkim_selectors": ["selector1"],
            "extensions": {"source": "microsoft-365"},
        },
        hostname=None,
        domain="example.com",
    )

    assert sender["id"] == "microsoft-365"
    assert any("Report metadata matched" in item for item in sender["evidence"])


def test_identify_sender_keeps_unknown_passing_source_low_priority():
    sender = identify_sender(
        "203.0.113.200",
        {"dmarc_result": "pass", "dmarc_fail_count": 0},
        hostname=None,
        domain="example.com",
    )

    assert sender["id"] == "unknown-sender"
    assert sender["status"] == "unknown"
    assert sender["reason"] == "No known provider profile matched this source."


def test_build_source_intelligence_detects_regions_and_anomalies():
    reports = [
        {
            "domain": "example.com",
            "report_id": "baseline",
            "begin_timestamp": 1_700_000_000,
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 120,
                    "spf_result": "pass",
                    "dkim_result": "pass",
                }
            ],
        },
        {
            "domain": "example.com",
            "report_id": "recent",
            "begin_timestamp": 1_702_000_000,
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 500,
                    "spf_result": "fail",
                    "dkim_result": "fail",
                },
                {
                    "source_ip": "198.51.100.199",
                    "count": 45,
                    "spf_result": "fail",
                    "dkim_result": "fail",
                },
            ],
        },
    ]
    sources = [
        {"source_ip": "203.0.113.10", "count": 620, "dmarc_fail_count": 500},
        {"source_ip": "198.51.100.199", "count": 45, "dmarc_fail_count": 45},
    ]

    intelligence = build_source_intelligence("example.com", reports, sources, period_days=30)

    anomaly_types = {item["type"] for item in intelligence["anomalies"]}
    assert {"alignment_failure", "new_sender", "new_region"}.issubset(anomaly_types)
    assert intelligence["regions"][0]["region"] in {"North America", "Europe"}
    assert "198.51.100.199" in intelligence["anomalies_by_ip"]


def test_build_source_intelligence_handles_no_data():
    intelligence = build_source_intelligence("empty.example", [], [], period_days=30)

    assert intelligence["regions"] == []
    assert intelligence["anomalies"] == []
    assert intelligence["summary"] == {
        "regions": 0,
        "sources": 0,
        "messages": 0,
        "anomalies": 0,
        "critical": 0,
        "warnings": 0,
    }


def test_build_source_intelligence_accepts_iso_report_dates():
    reports = [
        {
            "domain": "example.com",
            "report_id": "iso-date",
            "begin_date": "2026-06-25T00:00:00",
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 4,
                    "spf_result": "pass",
                    "dkim_result": "pass",
                }
            ],
        },
        {
            "domain": "example.com",
            "report_id": "bad-date",
            "begin_date": "not-a-date",
            "records": [],
        },
    ]

    intelligence = build_source_intelligence(
        "example.com",
        reports,
        [{"source_ip": "203.0.113.10", "count": 4, "dmarc_fail_count": 0}],
        period_days=30,
    )

    assert intelligence["summary"]["regions"] == 1


def test_build_source_intelligence_preserves_aware_iso_offsets():
    reports = [
        {
            "domain": "example.com",
            "begin_date": "2026-06-24T23:00:00-02:00",
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 10,
                    "spf_result": "pass",
                    "dkim_result": "pass",
                }
            ],
        },
        {
            "domain": "example.com",
            "begin_date": "2026-06-25T00:30:00+00:00",
            "records": [
                {
                    "source_ip": "198.51.100.199",
                    "count": 20,
                    "spf_result": "fail",
                    "dkim_result": "fail",
                }
            ],
        },
    ]

    intelligence = build_source_intelligence(
        "example.com",
        reports,
        [
            {"source_ip": "203.0.113.10", "count": 10, "dmarc_fail_count": 0},
            {"source_ip": "198.51.100.199", "count": 20, "dmarc_fail_count": 20},
        ],
        period_days=30,
    )

    anomaly_ips = {item["source_ip"] for item in intelligence["anomalies"]}
    assert "203.0.113.10" in anomaly_ips


def test_build_source_intelligence_limits_baseline_to_analysis_window():
    reports = [
        {
            "domain": "example.com",
            "begin_timestamp": 1_700_000_000,
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 1000,
                    "spf_result": "pass",
                    "dkim_result": "pass",
                }
            ],
        },
        {
            "domain": "example.com",
            "begin_timestamp": 1_703_500_000,
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 10,
                    "spf_result": "pass",
                    "dkim_result": "pass",
                }
            ],
        },
        {
            "domain": "example.com",
            "begin_timestamp": 1_704_000_000,
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 70,
                    "spf_result": "pass",
                    "dkim_result": "pass",
                }
            ],
        },
    ]

    intelligence = build_source_intelligence(
        "example.com",
        reports,
        [{"source_ip": "203.0.113.10", "count": 1080, "dmarc_fail_count": 0}],
        period_days=7,
    )

    assert any(item["type"] == "volume_spike" for item in intelligence["anomalies"])
