"""
Integration tests for the domain detail API endpoints:
  GET /api/v1/domains/{domain_id}/reports
  GET /api/v1/domains/{domain_id}/sources

These tests ensure that the ReportStore data is correctly projected into
the Pydantic response models, including the policy-dict extraction and
the use of begin_timestamp/end_timestamp integers for date fields.
"""

import csv
from io import StringIO

import pytest
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.services.report_store import ReportStore

# ---------------------------------------------------------------------------
# Helpers / constants
# ---------------------------------------------------------------------------

DOMAIN = "example.com"

# A minimal parsed DMARC report with policy stored as a dict (the real-world
# shape produced by DMARCParser) and Unix timestamps alongside ISO strings.
REPORT_DICT_POLICY = {
    "domain": DOMAIN,
    "report_id": "rpt-dict-policy",
    "org_name": "Google LLC",
    "begin_date": "2020-08-15T00:00:00",
    "end_date": "2020-08-15T23:59:59",
    "begin_timestamp": 1597449600,
    "end_timestamp": 1597535999,
    "policy": {"p": "reject", "sp": "reject", "pct": "100"},
    "records": [
        {
            "source_ip": "209.85.220.1",
            "count": 10,
            "disposition": "none",
            "dkim_result": "pass",
            "spf_result": "pass",
            "header_from": DOMAIN,
        }
    ],
    "summary": {"total_count": 10, "passed_count": 10, "failed_count": 0},
}

# Same report but with policy already stored as a plain string.
REPORT_STR_POLICY = {
    **REPORT_DICT_POLICY,
    "report_id": "rpt-str-policy",
    "policy": "quarantine",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def seeded_client(client: TestClient):
    """Client with one report (dict-style policy) in the ReportStore."""
    ReportStore.get_instance().add_report(REPORT_DICT_POLICY)
    return client


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/reports
# ---------------------------------------------------------------------------


def test_get_domain_reports_returns_200(seeded_client: TestClient):
    """Endpoint returns HTTP 200 and correct structure for a known domain."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/reports")
    assert response.status_code == 200
    data = response.json()
    assert "reports" in data
    assert "compliance_timeline" in data


def test_get_domain_reports_policy_dict_extracted(seeded_client: TestClient):
    """When the stored policy is a dict, the 'p' value should be surfaced."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/reports")
    assert response.status_code == 200
    reports = response.json()["reports"]
    assert len(reports) == 1
    assert reports[0]["policy"] == "reject"


def test_get_domain_reports_policy_string_preserved(client: TestClient):
    """When the stored policy is already a string it should be kept as-is."""
    ReportStore.get_instance().add_report(REPORT_STR_POLICY)
    response = client.get(f"/api/v1/domains/{DOMAIN}/reports")
    assert response.status_code == 200
    reports = response.json()["reports"]
    assert len(reports) == 1
    assert reports[0]["policy"] == "quarantine"


def test_get_domain_reports_timestamps_are_integers(seeded_client: TestClient):
    """begin_date and end_date in the response must be integers (Unix timestamps)."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/reports")
    assert response.status_code == 200
    report = response.json()["reports"][0]
    assert isinstance(report["begin_date"], int)
    assert isinstance(report["end_date"], int)
    assert report["begin_date"] == 1597449600
    assert report["end_date"] == 1597535999


def test_get_domain_reports_unknown_domain_returns_404(client: TestClient):
    """Returns 404 when the requested domain has no reports."""
    response = client.get("/api/v1/domains/no-such-domain.example.com/reports")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/reports/export
# ---------------------------------------------------------------------------


def test_export_domain_reports_returns_csv(seeded_client: TestClient):
    """CSV export includes report summary rows for the requested domain."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/reports/export")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]

    rows = list(csv.DictReader(StringIO(response.text)))
    assert len(rows) == 1
    assert rows[0]["domain"] == DOMAIN
    assert rows[0]["report_id"] == "rpt-dict-policy"
    assert rows[0]["begin_date"] == "2020-08-15"
    assert rows[0]["total_emails"] == "10"
    assert rows[0]["passed"] == "10"
    assert rows[0]["failed"] == "0"
    assert rows[0]["policy"] == "reject"


def test_export_domain_reports_filters_by_date_range(client: TestClient):
    """CSV export only includes reports inside the requested date range."""
    ReportStore.get_instance().add_report(REPORT_DICT_POLICY)
    ReportStore.get_instance().add_report(
        {
            **REPORT_STR_POLICY,
            "report_id": "rpt-next-day",
            "begin_date": "2020-08-16T00:00:00",
            "end_date": "2020-08-16T23:59:59",
            "begin_timestamp": 1597536000,
            "end_timestamp": 1597622399,
        }
    )

    response = client.get(
        f"/api/v1/domains/{DOMAIN}/reports/export?start_date=2020-08-16&end_date=2020-08-16"
    )

    assert response.status_code == 200
    rows = list(csv.DictReader(StringIO(response.text)))
    assert [row["report_id"] for row in rows] == ["rpt-next-day"]


def test_export_domain_reports_rejects_invalid_date_order(seeded_client: TestClient):
    """CSV export validates that the start date is not after the end date."""
    response = seeded_client.get(
        f"/api/v1/domains/{DOMAIN}/reports/export?start_date=2020-08-17&end_date=2020-08-16"
    )

    assert response.status_code == 422


def test_export_domain_reports_unknown_domain_returns_404(client: TestClient):
    """Returns 404 when exporting a domain with no reports."""
    response = client.get("/api/v1/domains/no-such-domain.example.com/reports/export")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/sources
# ---------------------------------------------------------------------------


def test_get_domain_sources_returns_200(seeded_client: TestClient):
    """Endpoint returns HTTP 200 and a sources list for a known domain."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources")
    assert response.status_code == 200
    data = response.json()
    assert "sources" in data
    assert len(data["sources"]) == 1
    source = data["sources"][0]
    assert source["ip"] == "209.85.220.1"
    assert source["spf"] == "pass"
    assert source["dkim"] == "pass"
    assert source["dmarc"] == "pass"


def test_get_domain_sources_returns_rollup_counts(client: TestClient):
    """Endpoint reports pass/fail totals instead of only the latest IP result."""
    report = {
        **REPORT_DICT_POLICY,
        "report_id": "rpt-mixed-source",
        "records": [
            {
                "source_ip": "209.85.220.9",
                "count": 4,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "fail",
                "header_from": DOMAIN,
            },
            {
                "source_ip": "209.85.220.9",
                "count": 6,
                "disposition": "quarantine",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": DOMAIN,
            },
        ],
        "summary": {"total_count": 10, "passed_count": 4, "failed_count": 6},
    }
    ReportStore.get_instance().add_report(report)

    response = client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    source = response.json()["sources"][0]
    assert source["ip"] == "209.85.220.9"
    assert source["count"] == 10
    assert source["spf"] == "fail"
    assert source["dkim"] == "mixed"
    assert source["dmarc"] == "mixed"
    assert source["spf_pass_count"] == 0
    assert source["spf_fail_count"] == 10
    assert source["dkim_pass_count"] == 4
    assert source["dkim_fail_count"] == 6
    assert source["dmarc_pass_count"] == 4
    assert source["dmarc_fail_count"] == 6
    assert source["disposition_counts"] == {"none": 4, "quarantine": 6}


def test_get_domain_sources_returns_recommendations(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    """Endpoint includes actionable guidance for common failure patterns."""

    async def fake_ptr_lookup(_provider, _ip, timeout=3.0):  # pylint: disable=unused-argument
        return "sender.example.net"

    monkeypatch.setattr(domains_endpoint, "_safe_ptr_lookup", fake_ptr_lookup)
    report = {
        **REPORT_DICT_POLICY,
        "report_id": "rpt-full-fail",
        "records": [
            {
                "source_ip": "192.0.2.10",
                "count": 3,
                "disposition": "none",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": DOMAIN,
            }
        ],
        "summary": {"total_count": 3, "passed_count": 0, "failed_count": 3},
    }
    ReportStore.get_instance().add_report(report)

    response = client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    source = response.json()["sources"][0]
    recommendation_types = {item["type"] for item in source["recommendations"]}
    assert recommendation_types == {"full_fail", "policy_not_enforced"}
    assert source["spf_fix_hint"] == "ip4:192.0.2.10"


def test_source_recommendations_cover_common_cases():
    """Recommendation builder handles the milestone source patterns."""
    cases = [
        (
            {
                "source_ip": "192.0.2.20",
                "spf_result": "pass",
                "dkim_result": "fail",
                "dmarc_result": "pass",
                "dmarc_pass_count": 8,
                "dmarc_fail_count": 0,
                "disposition": "none",
            },
            "mail.example.net",
            None,
            {"spf_only_pass"},
        ),
        (
            {
                "source_ip": "192.0.2.21",
                "spf_result": "fail",
                "dkim_result": "pass",
                "dmarc_result": "pass",
                "dmarc_pass_count": 8,
                "dmarc_fail_count": 0,
                "disposition": "none",
            },
            "mail.example.net",
            "ip4:192.0.2.21",
            {"dkim_only_pass"},
        ),
        (
            {
                "source_ip": "192.0.2.22",
                "spf_result": "fail",
                "dkim_result": "fail",
                "dmarc_result": "fail",
                "dmarc_pass_count": 0,
                "dmarc_fail_count": 8,
                "disposition": "none",
                "disposition_counts": {"none": 8},
            },
            "mail.example.net",
            "ip4:192.0.2.22",
            {"full_fail", "policy_not_enforced"},
        ),
        (
            {
                "source_ip": "192.0.2.23",
                "spf_result": "fail",
                "dkim_result": "fail",
                "dmarc_result": "fail",
                "dmarc_pass_count": 0,
                "dmarc_fail_count": 8,
                "disposition": "quarantine",
            },
            None,
            "ip4:192.0.2.23",
            {"unknown_source", "full_fail"},
        ),
    ]

    for source, hostname, spf_fix_hint, expected_types in cases:
        recommendations = domains_endpoint._source_recommendations(  # pylint: disable=protected-access
            source["source_ip"], source, hostname, spf_fix_hint
        )
        assert {item.type for item in recommendations} == expected_types


def test_get_domain_sources_days_param_accepted(seeded_client: TestClient):
    """The 'days' query parameter is accepted without raising a TypeError."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=7")
    assert response.status_code == 200


def test_get_domain_sources_unknown_domain_returns_404(client: TestClient):
    """Returns 404 when the requested domain has no reports."""
    response = client.get("/api/v1/domains/no-such-domain.example.com/sources")
    assert response.status_code == 404
