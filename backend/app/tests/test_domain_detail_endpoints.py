"""
Integration tests for the domain detail API endpoints:
  GET /api/v1/domains/{domain_id}/reports
  GET /api/v1/domains/{domain_id}/sources

These tests ensure that the ReportStore data is correctly projected into
the Pydantic response models, including the policy-dict extraction and
the use of begin_timestamp/end_timestamp integers for date fields.
"""

import pytest
from fastapi.testclient import TestClient

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


def test_get_domain_sources_days_param_accepted(seeded_client: TestClient):
    """The 'days' query parameter is accepted without raising a TypeError."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=7")
    assert response.status_code == 200


def test_get_domain_sources_unknown_domain_returns_404(client: TestClient):
    """Returns 404 when the requested domain has no reports."""
    response = client.get("/api/v1/domains/no-such-domain.example.com/sources")
    assert response.status_code == 404
