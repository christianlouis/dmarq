"""
Integration tests for the domain detail API endpoints:
  GET /api/v1/domains/{domain_id}/reports
  GET /api/v1/domains/{domain_id}/sources

These tests ensure that the ReportStore data is correctly projected into
the Pydantic response models, including the policy-dict extraction and
the use of begin_timestamp/end_timestamp integers for date fields.
"""

import csv
from datetime import date
from io import StringIO
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.models.domain import Domain
from app.services import report_persistence
from app.services.health_score_snapshots import upsert_health_score_snapshot
from app.services.report_store import ReportStore
from app.services.workspaces import get_or_create_default_workspace

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
    "policy": {
        "p": "reject",
        "sp": "reject",
        "pct": "100",
        "np": "none",
        "adkim": "s",
        "aspf": "r",
        "fo": "1",
        "testing": "y",
        "discovery_method": "treewalk",
    },
    "schema_version": "1.0",
    "variant": "rfc9990",
    "generator": "ExampleRUA 2.0",
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
def seeded_client(authed_client: TestClient, db_session):
    """Client with one report (dict-style policy) in the ReportStore."""
    workspace = get_or_create_default_workspace(db_session)
    db_session.add(
        Domain(name=DOMAIN, workspace_id=workspace.id, active=True, dmarc_policy="reject")
    )
    db_session.commit()
    ReportStore.get_instance().add_report(REPORT_DICT_POLICY)
    return authed_client


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


def test_domain_read_stats_selectors_and_search_use_workspace_auth(
    seeded_client: TestClient,
):
    """Read-only domain surfaces remain available after workspace RBAC checks."""
    domain = seeded_client.get(f"/api/v1/domains/domains/{DOMAIN}")
    assert domain.status_code == 200
    assert domain.json()["name"] == DOMAIN
    assert domain.json()["policy"] == "reject"

    domain_list = seeded_client.get("/api/v1/domains/domains")
    assert domain_list.status_code == 200
    assert domain_list.json()[0]["name"] == DOMAIN
    assert domain_list.json()[0]["policy"] == "reject"

    stats = seeded_client.get(f"/api/v1/domains/{DOMAIN}/stats")
    assert stats.status_code == 200
    assert stats.json()["totalEmails"] == 10

    selectors = seeded_client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert selectors.status_code == 200
    assert selectors.json() == {"selectors": [], "report_selectors": []}

    search = seeded_client.get("/api/v1/domains/search?q=example")
    assert search.status_code == 200
    assert search.json()[0]["name"] == DOMAIN
    assert search.json()[0]["policy"] == "reject"


def test_delete_domain_uses_workspace_scoped_domain_cleanup(
    seeded_client: TestClient,
):
    """Domain deletion removes the authorized workspace domain state."""
    response = seeded_client.delete(f"/api/v1/domains/{DOMAIN}")

    assert response.status_code == 204
    assert ReportStore.get_instance().get_domains() == []


def test_get_domain_reports_policy_dict_extracted(seeded_client: TestClient):
    """When the stored policy is a dict, the 'p' value should be surfaced."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/reports")
    assert response.status_code == 200
    reports = response.json()["reports"]
    assert len(reports) == 1
    assert reports[0]["policy"] == "reject"


def test_get_domain_reports_policy_string_preserved(authed_client: TestClient):
    """When the stored policy is already a string it should be kept as-is."""
    ReportStore.get_instance().add_report(REPORT_STR_POLICY)
    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/reports")
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


def test_get_domain_reports_uses_nested_summary_totals(seeded_client: TestClient):
    """Report rows should display totals from the parsed report summary."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/reports")
    assert response.status_code == 200
    report = response.json()["reports"][0]
    assert report["total_emails"] == 10


def test_get_domain_reports_unknown_domain_returns_404(authed_client: TestClient):
    """Returns 404 when the requested domain has no reports."""
    response = authed_client.get("/api/v1/domains/no-such-domain.example.com/reports")
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
    assert rows[0]["non_subdomain_policy"] == "none"
    assert rows[0]["adkim"] == "s"
    assert rows[0]["aspf"] == "r"
    assert rows[0]["failure_options"] == "1"
    assert rows[0]["testing"] == "y"
    assert rows[0]["discovery_method"] == "treewalk"
    assert rows[0]["schema_version"] == "1.0"
    assert rows[0]["report_variant"] == "rfc9990"
    assert rows[0]["generator"] == "ExampleRUA 2.0"


def test_export_domain_reports_filters_by_date_range(authed_client: TestClient):
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

    response = authed_client.get(
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


def test_export_domain_reports_unknown_domain_returns_404(authed_client: TestClient):
    """Returns 404 when exporting a domain with no reports."""
    response = authed_client.get("/api/v1/domains/no-such-domain.example.com/reports/export")
    assert response.status_code == 404


def test_domain_health_history_returns_persisted_trend(seeded_client: TestClient, db_session):
    """Health history exposes persisted score movement for the requested domain."""
    workspace = get_or_create_default_workspace(db_session)
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name=DOMAIN,
        health={"score": 80, "grade": "B-", "status": "attention", "factors": {}, "actions": []},
        policy="quarantine",
        compliance_rate=91,
        total_emails=100,
        failed_emails=9,
        report_count=1,
        snapshot_date=date(2026, 6, 1),
    )
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name=DOMAIN,
        health={
            "score": 88,
            "grade": "B+",
            "status": "attention",
            "factors": {},
            "actions": [{"title": "Fix SPF coverage", "severity": "high", "score_impact": 12}],
        },
        policy="quarantine",
        compliance_rate=95,
        total_emails=200,
        failed_emails=10,
        report_count=2,
        snapshot_date=date(2026, 6, 2),
    )

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/posture/history?capture_current=false")

    assert response.status_code == 200
    data = response.json()
    assert data["current_score"] == 88
    assert data["previous_score"] == 80
    assert data["score_delta"] == 8
    assert data["points"][1]["top_actions"][0]["title"] == "Fix SPF coverage"


def test_export_domain_health_evidence_returns_sanitized_csv(
    seeded_client: TestClient,
    db_session,
):
    """Health evidence export contains scores and actions without forensic content."""
    workspace = get_or_create_default_workspace(db_session)
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name=DOMAIN,
        health={
            "score": 72,
            "grade": "C",
            "status": "attention",
            "factors": {"dns_posture": 80, "policy_strength": 55, "report_confidence": 78},
            "actions": [{"title": "Move out of monitoring mode", "severity": "medium"}],
        },
        policy="none",
        compliance_rate=94,
        total_emails=500,
        failed_emails=30,
        report_count=5,
        snapshot_date=date(2026, 6, 3),
    )

    response = seeded_client.get(
        f"/api/v1/domains/{DOMAIN}/posture/evidence/export?capture_current=false"
    )

    assert response.status_code == 200
    rows = list(csv.DictReader(StringIO(response.text)))
    assert rows[0]["domain"] == DOMAIN
    assert rows[0]["score"] == "72"
    assert rows[0]["policy"] == "none"
    assert rows[0]["top_actions"] == "medium:Move out of monitoring mode"
    assert "message" not in response.text.lower()


def _stub_current_health(monkeypatch):
    async def fake_dns_health(db, store, domain_id, refresh=False):
        return domains_endpoint.DNSHealthResponse(
            status="healthy",
            policy="reject",
            compliance_rate=98,
            total_emails=1000,
            failed_emails=20,
            checks=[],
            recommendations=[],
        )

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 96,
            "grade": "A",
            "status": "healthy",
            "factors": {
                "dns_posture": 100,
                "policy_strength": 100,
                "report_confidence": 90,
            },
            "actions": [
                {
                    "type": "monitoring",
                    "severity": "low",
                    "title": "Keep monitoring",
                    "score_impact": 1,
                }
            ],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_health", fake_dns_health)
    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)


def test_domain_health_history_capture_current_snapshot(
    seeded_client: TestClient,
    monkeypatch,
):
    """Health history can capture today's computed posture before reading history."""
    _stub_current_health(monkeypatch)

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/posture/history")

    assert response.status_code == 200
    data = response.json()
    assert data["current_score"] == 96
    assert data["points"][-1]["policy"] == "reject"
    assert data["top_drivers"][0]["title"] == "Keep monitoring"


def test_domain_health_evidence_export_capture_current_snapshot(
    seeded_client: TestClient,
    monkeypatch,
):
    """Evidence export can capture the current score before writing CSV."""
    _stub_current_health(monkeypatch)

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/posture/evidence/export")

    assert response.status_code == 200
    rows = list(csv.DictReader(StringIO(response.text)))
    assert rows[0]["score"] == "96"
    assert rows[0]["policy"] == "reject"
    assert rows[0]["top_actions"] == "low:Keep monitoring"


def test_domain_posture_dashboard_records_current_snapshot(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """The posture dashboard records today's health score outside demo mode."""
    _stub_current_health(monkeypatch)

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/posture")

    assert response.status_code == 200
    assert response.json()["health"]["score"] == 96
    workspace = get_or_create_default_workspace(db_session)
    snapshots = domains_endpoint.list_health_score_snapshots(
        db_session,
        workspace_id=workspace.id,
        domain_name=DOMAIN,
    )
    assert snapshots[-1].score == 96


def test_domain_health_history_rejects_invalid_date_order(seeded_client: TestClient):
    """Health history validates that the start date is not after the end date."""
    response = seeded_client.get(
        f"/api/v1/domains/{DOMAIN}/posture/history"
        "?start_date=2026-06-03&end_date=2026-06-02&capture_current=false"
    )

    assert response.status_code == 422


def test_domain_health_evidence_export_rejects_invalid_date_order(
    seeded_client: TestClient,
):
    """Health evidence export validates that the start date is not after the end date."""
    response = seeded_client.get(
        f"/api/v1/domains/{DOMAIN}/posture/evidence/export"
        "?start_date=2026-06-03&end_date=2026-06-02&capture_current=false"
    )

    assert response.status_code == 422


def test_domain_health_history_unknown_domain_returns_404(authed_client: TestClient):
    """Health history returns 404 for domains outside the selected workspace."""
    response = authed_client.get(
        "/api/v1/domains/no-such.example/posture/history?capture_current=false"
    )

    assert response.status_code == 404


def test_domain_health_evidence_export_unknown_domain_returns_404(
    authed_client: TestClient,
):
    """Health evidence export returns 404 for domains outside the selected workspace."""
    response = authed_client.get(
        "/api/v1/domains/no-such.example/posture/evidence/export?capture_current=false"
    )

    assert response.status_code == 404


def _enable_endpoint_demo_mode(monkeypatch):
    settings = SimpleNamespace(DEMO_MODE=True)
    monkeypatch.setattr(domains_endpoint, "get_settings", lambda: settings)
    monkeypatch.setattr(report_persistence, "get_settings", lambda: settings)


def test_domain_health_history_uses_demo_history_fallback(
    authed_client: TestClient,
    monkeypatch,
):
    """Demo mode serves rolling health history when no snapshots are stored."""
    _enable_endpoint_demo_mode(monkeypatch)

    response = authed_client.get(
        "/api/v1/domains/dmarq.org/posture/history"
        "?capture_current=false&start_date=2026-06-01&limit=3"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "dmarq.org"
    assert len(data["points"]) <= 3
    assert data["current_score"] is not None


def test_domain_health_evidence_export_uses_demo_history_fallback(
    authed_client: TestClient,
    monkeypatch,
):
    """Demo mode exports rolling health evidence without persisted snapshots."""
    _enable_endpoint_demo_mode(monkeypatch)

    response = authed_client.get(
        "/api/v1/domains/dmarq.com/posture/evidence/export"
        "?capture_current=false&start_date=2026-06-01&limit=2"
    )

    assert response.status_code == 200
    rows = list(csv.DictReader(StringIO(response.text)))
    assert 0 < len(rows) <= 2
    assert rows[-1]["domain"] == "dmarq.com"
    assert rows[-1]["policy"] == "none"


def test_health_history_helpers_cover_demo_and_empty_paths():
    empty = domains_endpoint._history_response_from_points(DOMAIN, [])
    assert empty.current_score is None
    assert empty.points == []

    points = domains_endpoint._demo_history_points(
        "dmarq.org",
        start_date=date(2026, 6, 1),
        end_date=date(2099, 12, 31),
        limit=2,
    )
    response = domains_endpoint._history_response_from_points("dmarq.org", points)
    assert len(response.points) <= 2
    assert response.current_score is not None
    assert response.top_drivers

    export_rows = domains_endpoint._demo_evidence_export_rows("dmarq.org", points)
    assert export_rows[0]["domain"] == "dmarq.org"
    assert "medium:" in export_rows[0]["top_actions"]

    csv_response = domains_endpoint._write_health_evidence_csv(
        export_rows,
        domain_id="dmarq.org",
    )
    assert csv_response.media_type == "text/csv"
    assert "health-evidence.csv" in csv_response.headers["content-disposition"]


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


def test_get_domain_sources_returns_rollup_counts(authed_client: TestClient):
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

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/sources")

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


def test_get_domain_sources_returns_recommendations(
    authed_client: TestClient, monkeypatch: pytest.MonkeyPatch
):
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

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    source = response.json()["sources"][0]
    recommendation_types = {item["type"] for item in source["recommendations"]}
    assert recommendation_types == {"unknown_sender", "full_fail", "policy_not_enforced"}
    assert source["sender"]["name"] == "Unknown sender"
    assert source["sender"]["status"] == "unknown"
    assert source["spf_fix_hint"] == "ip4:192.0.2.10"


def test_get_domain_sources_returns_sender_identity(
    authed_client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    """Endpoint names recognized sending services with evidence and remediation."""

    async def fake_ptr_lookup(_provider, _ip, timeout=3.0):  # pylint: disable=unused-argument
        return "mail-qv1-f75.google.com"

    monkeypatch.setattr(domains_endpoint, "_safe_ptr_lookup", fake_ptr_lookup)
    report = {
        **REPORT_DICT_POLICY,
        "report_id": "rpt-google-source",
        "records": [
            {
                "source_ip": "203.0.113.75",
                "count": 12,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "header_from": DOMAIN,
                "envelope_from": f"bounce.{DOMAIN}",
                "dkim": [{"domain": DOMAIN, "selector": "google", "result": "pass"}],
                "spf": [{"domain": "_spf.google.com", "scope": "mfrom", "result": "pass"}],
            }
        ],
        "summary": {"total_count": 12, "passed_count": 12, "failed_count": 0},
    }
    ReportStore.get_instance().add_report(report)

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    source = response.json()["sources"][0]
    assert source["sender"]["id"] == "google-workspace"
    assert source["sender"]["name"] == "Google Workspace"
    assert source["sender"]["status"] == "known"
    assert source["sender"]["confidence"] >= 90
    assert source["sender"]["evidence"]
    assert "Google Workspace DKIM" in source["sender"]["remediation_hint"]


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
        recommendations = (
            domains_endpoint._source_recommendations(  # pylint: disable=protected-access
                source["source_ip"], source, hostname, spf_fix_hint
            )
        )
        assert {item.type for item in recommendations} == expected_types


def test_get_domain_sources_days_param_accepted(seeded_client: TestClient):
    """The 'days' query parameter is accepted without raising a TypeError."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=7")
    assert response.status_code == 200


def test_get_domain_sources_unknown_domain_returns_404(authed_client: TestClient):
    """Returns 404 when the requested domain has no reports."""
    response = authed_client.get("/api/v1/domains/no-such-domain.example.com/sources")
    assert response.status_code == 404
