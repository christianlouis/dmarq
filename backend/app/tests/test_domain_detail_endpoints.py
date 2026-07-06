"""
Integration tests for the domain detail API endpoints:
  GET /api/v1/domains/{domain_id}/reports
  GET /api/v1/domains/{domain_id}/sources

These tests ensure that the ReportStore data is correctly projected into
the Pydantic response models, including the policy-dict extraction and
the use of begin_timestamp/end_timestamp integers for date fields.
"""

import asyncio
import csv
import json
from datetime import date
from io import StringIO
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.models.domain import Domain
from app.models.setting import Setting
from app.models.webhook import WebhookDelivery
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog
from app.services import report_persistence
from app.services.health_score_snapshots import upsert_health_score_snapshot
from app.services.report_store import ReportStore
from app.services.source_network import SourceNetworkIntelligence
from app.services.source_reputation import (
    DomainReputation,
    ReputationEvidence,
    SourceReputation,
)
from app.services.webhook_events import (
    EVENT_REMEDIATION_APPROVAL_REQUIRED,
    create_webhook_endpoint,
)
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


def _stub_approval_ready_remediation(monkeypatch):
    """Stub a deterministic approval-ready remediation queue for example.com."""

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 72,
            "grade": "C",
            "status": "attention",
            "factors": {"dns_posture": 60},
            "actions": [],
        }

    async def fake_dns_guidance(db, store, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "critical",
            "dns_provider": {"provider_id": "cloudflare"},
            "findings": [],
            "change_plans": [
                {
                    "plan_id": "dmarc-missing",
                    "finding_code": "dmarc_missing",
                    "severity": "error",
                    "operation": "create",
                    "record_type": "TXT",
                    "name": "_dmarc.example.com",
                    "proposed_value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                    "current_values": [],
                    "rationale": "Publish a monitoring DMARC record.",
                    "expected_health_impact": "High",
                    "manual_steps": ["Create the TXT record."],
                }
            ],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: ["cloudflare"])
    monkeypatch.setattr(
        domains_endpoint,
        "_recommended_dns_write_provider",
        lambda dns_provider, available_providers: "cloudflare",
    )


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
    report_persistence.save_parsed_report(
        db_session,
        REPORT_DICT_POLICY,
        workspace_id=workspace.id,
    )
    db_session.commit()
    ReportStore.get_instance().add_report(REPORT_DICT_POLICY)
    return authed_client


@pytest.fixture(autouse=True)
def _stub_source_network_enrichment(monkeypatch):
    """Keep domain endpoint tests deterministic unless a test overrides enrichment."""

    async def fake_networks(*_args, **_kwargs):
        return {}

    monkeypatch.setattr(domains_endpoint, "lookup_sources_network_cached", fake_networks)


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


def test_domain_stats_and_reports_use_single_domain_persisted_reports(
    seeded_client: TestClient,
    monkeypatch,
):
    """Stats and recent reports should not hydrate every workspace report."""

    def fail_global_hydration(*args, **kwargs):
        raise AssertionError("domain detail endpoints should not hydrate all reports")

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fail_global_hydration)

    stats = seeded_client.get(f"/api/v1/domains/{DOMAIN}/stats")
    reports = seeded_client.get(f"/api/v1/domains/{DOMAIN}/reports")

    assert stats.status_code == 200
    assert stats.json()["totalEmails"] == 10
    assert reports.status_code == 200
    assert reports.json()["reports"][0]["id"] == "rpt-dict-policy"


def test_compliance_timeline_does_not_treat_no_volume_as_perfect_compliance():
    """Zero-volume report periods must not become 100% compliance points."""
    store = ReportStore()
    store.add_report(
        {
            **REPORT_DICT_POLICY,
            "report_id": "rpt-zero-volume",
            "begin_timestamp": 1597536000,
            "begin_date": "2020-08-16T00:00:00",
            "end_date": "2020-08-16T23:59:59",
            "records": [],
            "summary": {"total_count": 0, "passed_count": 0, "failed_count": 0},
        }
    )

    timeline = domains_endpoint._build_compliance_timeline(store, DOMAIN)

    assert timeline[0].volume == 0
    assert timeline[0].total == 0
    assert timeline[0].compliance_rate == 0.0
    assert timeline[0].failure_rate == 0.0


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


def test_domain_ownership_endpoint_returns_dns_proof(
    seeded_client: TestClient,
    db_session,
):
    """Domain detail pages can show the TXT proof needed for ownership."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/ownership")

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["verified"] is False
    assert data["proof_record_name"] == f"_dmarq-verify.{DOMAIN}"
    assert data["proof_record_type"] == "TXT"
    assert data["proof_record_value"].startswith("dmarq-verify=")
    assert "Report mailbox access is enough" in data["proof_reason"]
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).one().verification_token


def test_domain_ownership_verify_marks_matching_txt_verified(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """A matching live TXT proof marks the authorized workspace domain verified."""
    proof = seeded_client.get(f"/api/v1/domains/{DOMAIN}/ownership").json()

    class FakeProvider:
        async def lookup_txt(self, name):
            assert name == proof["proof_record_name"]
            return [proof["proof_record_value"]]

    monkeypatch.setattr(domains_endpoint, "get_default_provider", lambda db: FakeProvider())

    response = seeded_client.post(f"/api/v1/domains/{DOMAIN}/ownership/verify")

    assert response.status_code == 200
    data = response.json()
    assert data["matched"] is True
    assert data["verified"] is True
    assert proof["proof_record_value"] in data["observed_values"]
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).one().verified is True


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


def test_export_domain_reports_accepts_numeric_domain_id(
    seeded_client: TestClient,
    db_session,
):
    """CSV export resolves numeric path IDs to the canonical domain name."""
    domain = db_session.query(Domain).filter(Domain.name == DOMAIN).one()

    response = seeded_client.get(f"/api/v1/domains/{domain.id}/reports/export")

    assert response.status_code == 200
    assert f'filename="{DOMAIN}-dmarc-reports.csv"' in response.headers["content-disposition"]
    rows = list(csv.DictReader(StringIO(response.text)))
    assert len(rows) == 1
    assert rows[0]["domain"] == DOMAIN
    assert rows[0]["report_id"] == "rpt-dict-policy"


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


def test_workspace_health_history_returns_persisted_trend(
    seeded_client: TestClient,
    db_session,
):
    """Workspace health history aggregates daily scores across monitored domains."""
    workspace = get_or_create_default_workspace(db_session)
    db_session.add(
        Domain(name="example.net", workspace_id=workspace.id, active=True, dmarc_policy="none")
    )
    db_session.commit()
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name=DOMAIN,
        health={"score": 92, "grade": "A-", "status": "healthy", "factors": {}, "actions": []},
        policy="reject",
        compliance_rate=97,
        total_emails=900,
        failed_emails=27,
        report_count=10,
        snapshot_date=date(2026, 6, 1),
    )
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name="example.net",
        health={
            "score": 68,
            "grade": "D",
            "status": "critical",
            "factors": {},
            "actions": [
                {
                    "title": "Move out of monitoring mode",
                    "severity": "medium",
                    "score_impact": 14,
                }
            ],
        },
        policy="none",
        compliance_rate=72,
        total_emails=100,
        failed_emails=28,
        report_count=3,
        snapshot_date=date(2026, 6, 1),
    )

    response = seeded_client.get(
        "/api/v1/domains/summary/health/history"
        "?start_date=2026-06-01&end_date=2026-06-30&limit=30"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "workspace"
    assert data["current_score"] == 90
    assert data["points"][0]["domain_count"] == 2
    assert data["points"][0]["total_emails"] == 1000
    assert data["top_drivers"][0]["domain"] == "example.net"


def test_export_workspace_health_evidence_returns_json(
    seeded_client: TestClient,
    db_session,
):
    """Workspace evidence export returns sanitized aggregate rows as JSON."""
    workspace = get_or_create_default_workspace(db_session)
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name=DOMAIN,
        health={
            "score": 91,
            "grade": "A-",
            "status": "healthy",
            "factors": {"dns_posture": 96, "policy_strength": 100, "report_confidence": 90},
            "actions": [{"title": "Keep monitoring", "severity": "low", "score_impact": 1}],
        },
        policy="reject",
        compliance_rate=98,
        total_emails=1200,
        failed_emails=24,
        report_count=8,
        snapshot_date=date(2026, 6, 4),
    )

    response = seeded_client.get("/api/v1/domains/summary/health/evidence/export?format=json")

    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "workspace"
    assert data["rows"][0]["domain"] == "workspace"
    assert data["rows"][0]["score"] == 91
    assert "forensic" not in response.text.lower()
    assert "workspace-health-evidence.json" in response.headers["content-disposition"]


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


def test_export_domain_health_evidence_returns_sanitized_json(
    seeded_client: TestClient,
    db_session,
):
    """Domain health evidence can be exported as JSON without sensitive report content."""
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
        f"/api/v1/domains/{DOMAIN}/posture/evidence/export" "?capture_current=false&format=json"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "domain"
    assert data["rows"][0]["domain"] == DOMAIN
    assert data["rows"][0]["policy"] == "none"
    assert "message" not in response.text.lower()
    assert "example.com-health-evidence.json" in response.headers["content-disposition"]


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


def test_domain_remediation_queue_groups_dns_and_health_actions(
    seeded_client: TestClient,
    monkeypatch,
):
    """Domain remediation returns a prioritized, human-reviewed action queue."""

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 72,
            "grade": "C",
            "status": "attention",
            "factors": {
                "dns_posture": 60,
                "policy_strength": 40,
                "report_confidence": 90,
            },
            "actions": [
                {
                    "type": "missing_dmarc",
                    "severity": "high",
                    "title": "Publish DMARC",
                    "detail": "No DMARC policy was found.",
                    "next_step": "Publish a DMARC TXT record.",
                    "score_impact": 30,
                },
                {
                    "type": "low_compliance",
                    "severity": "medium",
                    "title": "Review failing senders",
                    "detail": "Some senders fail DMARC.",
                    "next_step": "Investigate the top failing source.",
                    "score_impact": 12,
                },
            ],
        }

    async def fake_dns_guidance(db, store, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "critical",
            "dns_provider": {"provider_id": "cloudflare"},
            "findings": [
                {
                    "code": "dmarc_missing",
                    "severity": "error",
                    "title": "Publish DMARC",
                    "detail": "No DMARC TXT record was found.",
                    "evidence": ["_dmarc.example.com"],
                }
            ],
            "change_plans": [
                {
                    "plan_id": "dmarc-missing",
                    "finding_code": "dmarc_missing",
                    "severity": "error",
                    "operation": "create",
                    "record_type": "TXT",
                    "name": "_dmarc.example.com",
                    "proposed_value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                    "current_values": [],
                    "rationale": "Publish a monitoring DMARC record.",
                    "expected_health_impact": "High",
                    "manual_steps": ["Create the TXT record."],
                }
            ],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: ["cloudflare"])
    monkeypatch.setattr(
        domains_endpoint,
        "_recommended_dns_write_provider",
        lambda dns_provider, available_providers: "cloudflare",
    )

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/remediation")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "needs_approval"
    assert data["summary"]["total"] == 2
    assert data["summary"]["approval_ready"] == 1
    assert data["summary"]["investigate"] == 1
    assert data["summary"]["provider_fix_available"] == 1
    assert data["loop"]["status"] == "approval_required"
    assert data["loop"]["what_dmarq_can_fix"] == 1
    assert data["loop"]["what_needs_investigation"] == 1
    assert data["loop"]["top_incident_type"] == "dmarc_policy_missing_or_weak"
    assert data["items"][0]["id"] == "dns:dmarc-missing"
    assert data["items"][0]["incident_type"] == "dmarc_policy_missing_or_weak"
    assert data["items"][0]["loop_state"] == "proposal_ready_for_approval"
    assert data["items"][0]["remediation_track"] == "provider_preview"
    assert data["items"][0]["priority_score"] == 455
    assert "approve_after_preview" in data["items"][0]["operator_decisions"]
    assert data["items"][0]["automation"]["eligible"] is True
    assert data["items"][0]["automation"]["provider"] == "cloudflare"
    assert data["items"][0]["verification_plan"]["status"] == "pending_operator_approval"
    assert "fresh DNS evidence" in data["items"][0]["verification_plan"]["summary"]
    assert data["items"][0]["repair_progression"]["stage"] == "preview_ready"
    assert data["items"][0]["repair_progression"]["can_preview"] is True
    assert data["items"][0]["repair_progression"]["verification_status"] == (
        "pending_operator_approval"
    )
    assert data["items"][1]["verification_plan"]["status"] == "pending_sender_review"
    assert data["items"][1]["repair_progression"]["stage"] == "classification_required"
    assert data["items"][1]["incident_type"] == "legitimate_sender_failing_alignment"
    assert data["items"][1]["loop_state"] == "evidence_review_required"
    assert data["items"][1]["remediation_track"] == "sender_investigation"
    assert "receiver report window" in data["items"][1]["verification_plan"]["next_check"]
    dispatch = data["items"][0]["notification"]["dispatch"]
    assert dispatch["enabled"] is False
    assert dispatch["eligible"] is False
    assert dispatch["delivery_enqueued"] is False
    assert "Remediation dispatch is disabled" in dispatch["blocked_reasons"][0]
    assert [item["id"] for item in data["items"]] == [
        "dns:dmarc-missing",
        "health:low_compliance",
    ]


def test_dashboard_remediation_loop_exposes_operator_decision_context():
    """Workspace dashboard remediation cards use the same operator language as detail queues."""
    loop = domains_endpoint._build_dashboard_remediation_loop(
        [
            {
                "domain_name": "example.com",
                "health": {
                    "actions": [
                        {
                            "type": "missing_dmarc",
                            "severity": "high",
                            "title": "Publish DMARC",
                            "detail": "No DMARC policy was found.",
                            "next_step": "Publish a DMARC TXT record.",
                            "score_impact": 30,
                        },
                        {
                            "type": "source_reputation_review",
                            "severity": "high",
                            "title": "Review suspicious source",
                            "detail": "A sending IP needs review.",
                            "next_step": "Open source intelligence.",
                            "score_impact": 10,
                        },
                    ]
                },
            }
        ],
        {"summary": {"resolved": 2, "verified_fixed": 1}},
    )

    assert loop["resolved"] == 2
    assert loop["verified_fixed"] == 1
    assert loop["track_provider_preview"] == 1
    assert loop["track_reputation_review"] == 1
    assert loop["repair_preview_ready"] == 1
    assert loop["provider_preview_available"] == 1
    assert loop["provider_apply_after_approval"] == 1
    assert loop["provider_apply_blocked"] == 0
    assert loop["provider_value_missing"] == 0
    assert loop["repair_needs_evidence"] == 2
    assert loop["evidence_refresh_required"] == 2
    assert loop["evidence_refresh_dns"] == 1
    assert loop["evidence_refresh_reputation"] == 1
    assert loop["evidence_refresh_reports"] == 0
    assert loop["verification_pending_operator_approval"] == 1
    assert loop["verification_pending_sender_review"] == 0
    assert loop["verification_pending_reputation_review"] == 1
    assert loop["verification_blocked_by_prerequisite"] == 0
    assert loop["top_incident_type"] == "dmarc_policy_missing_or_weak"
    assert loop["repair_blocked"] == 0
    assert loop["repair_ready_for_preview"] == 1
    assert loop["repair_waiting_on_operator"] == 1
    assert loop["repair_readiness_blocked"] == 0
    assert loop["repair_readiness_score"] == 80
    assert loop["items"][0]["priority_band"] == "high"
    assert loop["items"][0]["safe_to_automate"] is True
    assert loop["items"][0]["risk_level"] == "medium"
    assert loop["items"][0]["repair_progression"]["stage"] == "preview_ready"
    assert loop["items"][0]["repair_progression"]["can_preview"] is True
    assert loop["items"][0]["repair_progression"]["readiness_level"] == "ready_for_preview"
    assert loop["items"][0]["repair_progression"]["readiness_score"] == 80
    assert loop["items"][0]["evidence_refresh"]["refresh_key"] == "dns"
    assert loop["items"][0]["evidence_refresh"]["safe_to_run"] is True
    assert loop["items"][0]["verification_plan"]["status"] == "pending_operator_approval"
    assert loop["items"][0]["verification_plan"]["verification_method"] == (
        "provider_write_then_dns_refresh"
    )
    assert "Fresh DNS evidence" in loop["items"][0]["verification_plan"]["freshness_requirement"]
    assert "approved provider apply" in loop["items"][0]["verification_plan"]["closure_gate"]
    assert "DNS propagation evidence" in (
        loop["items"][0]["verification_plan"]["stale_evidence_warning"]
    )
    assert "Preview the exact DNS" in loop["items"][0]["operator_decision_summary"]
    assert loop["items"][1]["remediation_track"] == "reputation_review"
    assert loop["items"][1]["repair_progression"]["stage"] == "reputation_review"
    assert loop["items"][1]["repair_progression"]["readiness_level"] == "needs_reputation_review"
    assert loop["items"][1]["evidence_refresh"]["refresh_key"] == "source_reputation"
    assert loop["items"][1]["verification_plan"]["status"] == "pending_reputation_review"
    assert loop["items"][1]["verification_plan"]["verification_method"] == (
        "fresh_reputation_evidence"
    )
    assert "Fresh reputation" in (
        loop["items"][1]["verification_plan"]["freshness_requirement"]
    )
    assert "fresh reputation evidence" in loop["items"][1]["verification_plan"]["closure_gate"]
    assert loop["items"][1]["risk_level"] == "high"
    assert loop["items"][1]["safe_to_automate"] is False


def test_dashboard_remediation_loop_counts_provider_specific_prerequisite_blocks():
    """Dashboard repair-gate counters include blocked DNS repair prerequisites."""
    loop = domains_endpoint._build_dashboard_remediation_loop(
        [
            {
                "domain_name": "example.com",
                "health": {
                    "actions": [
                        {
                            "type": "missing_dkim",
                            "source": "dns_lint",
                            "severity": "high",
                            "title": "Publish DKIM",
                            "detail": "No DKIM selector was found.",
                            "next_step": "Collect the provider-specific DKIM value.",
                            "score_impact": 25,
                            "prerequisites": [
                                "A provider-specific final value is required before automation is safe."
                            ],
                        }
                    ]
                },
            }
        ],
        {"summary": {}},
    )

    assert loop["track_blocked_by_prerequisite"] == 1
    assert loop["repair_blocked"] == 1
    assert loop["provider_preview_available"] == 0
    assert loop["provider_apply_after_approval"] == 0
    assert loop["provider_apply_blocked"] == 1
    assert loop["provider_value_missing"] == 1
    assert loop["repair_preview_ready"] == 0
    assert loop["repair_needs_evidence"] == 1
    assert loop["evidence_refresh_required"] == 1
    assert loop["evidence_refresh_prerequisite"] == 1
    assert loop["verification_pending_operator_approval"] == 0
    assert loop["verification_blocked_by_prerequisite"] == 1
    assert loop["repair_ready_for_preview"] == 0
    assert loop["repair_waiting_on_operator"] == 0
    assert loop["repair_readiness_blocked"] == 1
    assert loop["repair_readiness_score"] == 20
    assert loop["items"][0]["remediation_track"] == "blocked_by_prerequisite"
    assert loop["items"][0]["repair_progression"]["stage"] == "blocked"
    assert loop["items"][0]["repair_progression"]["can_preview"] is False
    assert loop["items"][0]["repair_progression"]["readiness_level"] == "blocked"
    assert loop["items"][0]["evidence_refresh"]["refresh_key"] == "provider_value"
    assert loop["items"][0]["evidence_refresh"]["safe_to_run"] is False
    assert loop["items"][0]["verification_plan"]["status"] == "blocked_by_prerequisite"
    assert loop["items"][0]["verification_plan"]["verification_method"] == (
        "provider_specific_value_then_health_rebuild"
    )
    assert "provider-specific target value" in (
        loop["items"][0]["verification_plan"]["stale_evidence_warning"]
    )
    assert "provider-specific value" in loop["items"][0]["repair_progression"]["summary"]


def test_domain_remediation_dispatch_preview_becomes_eligible_without_enqueuing(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Opt-in remediation dispatch readiness is visible but still read-only."""
    _stub_approval_ready_remediation(monkeypatch)
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            Setting(
                key="notifications.remediation_dispatch_enabled",
                value="true",
                description="Enable remediation dispatch",
                value_type="boolean",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_require_acknowledgement",
                value="true",
                description="Require remediation acknowledgement",
                value_type="boolean",
                category="notifications",
            ),
        ]
    )
    create_webhook_endpoint(
        db_session,
        workspace_id=workspace.id,
        name="remediation receiver",
        url="https://receiver.example/remediation",
        event_types=[EVENT_REMEDIATION_APPROVAL_REQUIRED],
    )
    db_session.commit()

    audit_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "event": EVENT_REMEDIATION_APPROVAL_REQUIRED,
            "lifecycle_state": "acknowledged",
        },
    )
    assert audit_response.status_code == 200

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/remediation")

    assert response.status_code == 200
    dispatch = response.json()["items"][0]["notification"]["dispatch"]
    assert dispatch["enabled"] is True
    assert dispatch["eligible"] is True
    assert dispatch["would_enqueue"] is True
    assert dispatch["delivery_enqueued"] is False
    assert dispatch["lifecycle_state"] == "acknowledged"
    assert dispatch["webhook_endpoint_count"] == 1
    assert dispatch["blocked_reasons"] == []
    assert db_session.query(WebhookDelivery).count() == 0


def test_domain_remediation_dispatch_preview_reports_blockers_for_unsupported_routes(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Dispatch previews stay blocked for unsupported channels and event routing."""
    _stub_approval_ready_remediation(monkeypatch)
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            Setting(
                key="notifications.remediation_dispatch_enabled",
                value="true",
                description="Enable remediation dispatch",
                value_type="boolean",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_channel",
                value="email",
                description="Route remediation dispatch through email",
                value_type="string",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_events",
                value="dmarq.domain.health.degraded, not-a-real-event",
                description="Eligible remediation events",
                value_type="string",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_require_acknowledgement",
                value="true",
                description="Require remediation acknowledgement",
                value_type="boolean",
                category="notifications",
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="system",
                actor_id="test-suite",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:dmarc-missing",
                entity_name=DOMAIN,
                details="{broken-json",
            ),
        ]
    )
    db_session.commit()

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/remediation")

    assert response.status_code == 200
    dispatch = response.json()["items"][0]["notification"]["dispatch"]
    assert dispatch["enabled"] is True
    assert dispatch["eligible"] is False
    assert dispatch["event_enabled"] is False
    assert dispatch["channel"] == "email"
    assert dispatch["lifecycle_state"] is None
    assert dispatch["delivery_enqueued"] is False
    assert dispatch["blocked_reasons"] == [
        "This remediation event is not enabled for dispatch.",
        "Only webhook dispatch is supported in this release slice.",
        "Record a previewed or acknowledged lifecycle marker first.",
    ]
    assert "Add the event to notifications.remediation_dispatch_events." in dispatch["next_steps"]
    assert "Set notifications.remediation_dispatch_channel=webhook." in dispatch["next_steps"]


def test_domain_remediation_notification_dispatch_enqueues_webhook_delivery(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Explicit dispatch approval queues webhook delivery state without DNS writes."""
    _stub_approval_ready_remediation(monkeypatch)
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            Setting(
                key="notifications.remediation_dispatch_enabled",
                value="true",
                description="Enable remediation dispatch",
                value_type="boolean",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_channel",
                value="webhook",
                description="Route remediation dispatch through webhooks",
                value_type="string",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_events",
                value=EVENT_REMEDIATION_APPROVAL_REQUIRED,
                description="Eligible remediation events",
                value_type="string",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_require_acknowledgement",
                value="true",
                description="Require remediation acknowledgement",
                value_type="boolean",
                category="notifications",
            ),
        ]
    )
    db_session.commit()
    create_webhook_endpoint(
        db_session,
        workspace_id=workspace.id,
        name="Security operations",
        url="https://hooks.example.test/remediation",
        secret="remediation-secret-value",
        event_types=[EVENT_REMEDIATION_APPROVAL_REQUIRED],
    )

    audit_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "event": EVENT_REMEDIATION_APPROVAL_REQUIRED,
            "lifecycle_state": "acknowledged",
        },
    )
    assert audit_response.status_code == 200

    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/dispatch",
        json={
            "item_id": "dns:dmarc-missing",
            "confirm": True,
            "event": EVENT_REMEDIATION_APPROVAL_REQUIRED,
            "dedupe_key": f"dmarq:remediation:{DOMAIN}:dns:dmarc-missing",
            "note": "Route this to the webhook queue",
        },
        headers={"X-Forwarded-For": "203.0.113.45"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["item_id"] == "dns:dmarc-missing"
    assert data["delivery_enqueued"] is True
    assert data["delivery_count"] == 1
    assert data["dispatch"]["eligible"] is True
    assert data["dispatch"]["delivery_enqueued"] is True
    assert data["deliveries"][0]["event_type"] == EVENT_REMEDIATION_APPROVAL_REQUIRED
    assert data["deliveries"][0]["status"] == "pending"
    assert data["audit"]["action"] == "remediation.notification_dispatch_enqueued"
    assert data["audit"]["ip_address"] == "203.0.113.45"
    details = data["audit"]["details"]
    assert details["sent"] is False
    assert details["delivery_enqueued"] is True
    assert details["delivery_count"] == 1
    assert details["dns_write_attempted"] is False
    assert details["operator_note"] == "Route this to the webhook queue"
    assert db_session.query(WebhookDelivery).count() == 1

    queue_response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/remediation")
    assert queue_response.status_code == 200
    history = queue_response.json()["items"][0]["notification"]["history"]
    assert [entry["action"] for entry in history[:2]] == [
        "remediation.notification_dispatch_enqueued",
        "remediation.notification_lifecycle_recorded",
    ]
    assert history[0]["state"] == "delivery_enqueued"
    assert history[0]["delivery_enqueued"] is True
    assert history[0]["delivery_count"] == 1
    assert history[0]["dns_write_attempted"] is False
    assert history[0]["operator_note"] == "Route this to the webhook queue"
    assert history[1]["state"] == "acknowledged"
    assert "deliveries" not in history[0]

    duplicate_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/dispatch",
        json={
            "item_id": "dns:dmarc-missing",
            "confirm": True,
            "event": EVENT_REMEDIATION_APPROVAL_REQUIRED,
        },
    )
    assert duplicate_response.status_code == 200
    assert duplicate_response.json()["delivery_count"] == 1
    assert db_session.query(WebhookDelivery).count() == 1


def test_domain_remediation_notification_dispatch_requires_confirmed_readiness(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Dispatch stays blocked until an operator confirms and readiness is green."""
    _stub_approval_ready_remediation(monkeypatch)
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            Setting(
                key="notifications.remediation_dispatch_enabled",
                value="true",
                description="Enable remediation dispatch",
                value_type="boolean",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_channel",
                value="webhook",
                description="Route remediation dispatch through webhooks",
                value_type="string",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_events",
                value=EVENT_REMEDIATION_APPROVAL_REQUIRED,
                description="Eligible remediation events",
                value_type="string",
                category="notifications",
            ),
            Setting(
                key="notifications.remediation_dispatch_require_acknowledgement",
                value="true",
                description="Require remediation acknowledgement",
                value_type="boolean",
                category="notifications",
            ),
        ]
    )
    db_session.commit()
    create_webhook_endpoint(
        db_session,
        workspace_id=workspace.id,
        name="Security operations",
        url="https://hooks.example.test/remediation",
        secret="remediation-secret-value",
        event_types=[EVENT_REMEDIATION_APPROVAL_REQUIRED],
    )

    unconfirmed_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/dispatch",
        json={
            "item_id": "dns:dmarc-missing",
            "confirm": False,
        },
    )
    assert unconfirmed_response.status_code == 400
    assert "confirm=true" in unconfirmed_response.json()["detail"]

    blocked_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/dispatch",
        json={
            "item_id": "dns:dmarc-missing",
            "confirm": True,
        },
    )
    assert blocked_response.status_code == 409
    detail = blocked_response.json()["detail"]
    assert detail["message"] == "Remediation notification is not dispatch-ready."
    assert "Record a previewed or acknowledged lifecycle marker first." in detail["blocked_reasons"]
    assert db_session.query(WebhookDelivery).count() == 0


def test_domain_remediation_notification_dispatch_rejects_stale_identifiers(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Dispatch requests must target the current queue item metadata."""
    _stub_approval_ready_remediation(monkeypatch)

    missing_item_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/dispatch",
        json={
            "item_id": "__missing-remediation-item__",
            "confirm": True,
        },
    )
    assert missing_item_response.status_code == 404
    assert missing_item_response.json()["detail"] == "Remediation item not found"
    assert db_session.query(WebhookDelivery).count() == 0

    event_mismatch_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/dispatch",
        json={
            "item_id": "dns:dmarc-missing",
            "confirm": True,
            "event": "remediation.invalid",
        },
    )
    assert event_mismatch_response.status_code == 400
    assert "event does not match" in event_mismatch_response.json()["detail"]
    assert db_session.query(WebhookDelivery).count() == 0

    dedupe_mismatch_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/dispatch",
        json={
            "item_id": "dns:dmarc-missing",
            "confirm": True,
            "dedupe_key": "dmarq:remediation:wrong",
        },
    )
    assert dedupe_mismatch_response.status_code == 400
    assert "dedupe_key does not match" in dedupe_mismatch_response.json()["detail"]
    assert db_session.query(WebhookDelivery).count() == 0


def test_domain_remediation_notification_lifecycle_audit_records_sanitized_marker(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Operators can audit notification lifecycle steps without dispatching work."""

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 72,
            "grade": "C",
            "status": "attention",
            "factors": {"dns_posture": 60},
            "actions": [],
        }

    async def fake_dns_guidance(db, store, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "critical",
            "dns_provider": {"provider_id": "cloudflare"},
            "findings": [],
            "change_plans": [
                {
                    "plan_id": "dmarc-missing",
                    "finding_code": "dmarc_missing",
                    "severity": "error",
                    "operation": "create",
                    "record_type": "TXT",
                    "name": "_dmarc.example.com",
                    "proposed_value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                    "current_values": [],
                    "rationale": "Publish a monitoring DMARC record.",
                    "expected_health_impact": "High",
                    "manual_steps": ["Create the TXT record."],
                }
            ],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: ["cloudflare"])
    monkeypatch.setattr(
        domains_endpoint,
        "_recommended_dns_write_provider",
        lambda dns_provider, available_providers: "cloudflare",
    )

    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "event": "dmarq.remediation.approval_required",
            "lifecycle_state": "acknowledged",
            "note": "Reviewed with DNS owner",
        },
        headers={"X-Forwarded-For": "203.0.113.44"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["item_id"] == "dns:dmarc-missing"
    assert data["lifecycle_state"] == "acknowledged"
    assert data["audit"]["action"] == "remediation.notification_lifecycle_recorded"
    assert data["audit"]["ip_address"] == "203.0.113.44"
    details = data["audit"]["details"]
    assert details["sent"] is False
    assert details["delivery_enqueued"] is False
    assert details["dns_write_attempted"] is False
    assert details["payload_preview"]["event_type"] == "dmarq.remediation.approval_required"

    audit_row = (
        db_session.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.action == "remediation.notification_lifecycle_recorded")
        .one()
    )
    persisted_details = json.loads(audit_row.details)
    assert persisted_details["operator_note"] == "Reviewed with DNS owner"
    assert persisted_details["automation_provider"] == "cloudflare"


def test_domain_remediation_notification_lifecycle_audit_records_sender_decision(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Investigation decisions are audit markers, not hidden DNS/provider writes."""

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 68,
            "grade": "C",
            "status": "attention",
            "factors": {"report_confidence": 70},
            "actions": [
                {
                    "type": "low_compliance",
                    "severity": "high",
                    "title": "Review failing senders",
                    "detail": "Recent reports include an unknown failing sender.",
                    "next_step": "Classify the sender before changing DNS.",
                    "score_impact": 18,
                }
            ],
        }

    async def fake_dns_guidance(db, store, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "ok",
            "dns_provider": {"provider_id": "cloudflare"},
            "findings": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)

    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "health:low_compliance",
            "event": "dmarq.remediation.investigation_required",
            "lifecycle_state": "mark_unknown",
            "note": "This source is not owned by us.",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["item_id"] == "health:low_compliance"
    assert data["lifecycle_state"] == "mark_unknown"
    details = data["audit"]["details"]
    assert details["sent"] is False
    assert details["delivery_enqueued"] is False
    assert details["dns_write_attempted"] is False

    queue_response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/remediation")
    assert queue_response.status_code == 200
    item = queue_response.json()["items"][0]
    assert item["id"] == "health:low_compliance"
    assert item["notification"]["history"][0]["state"] == "mark_unknown"
    assert item["notification"]["history"][0]["label"] == "Marked unknown sender"
    assert item["notification"]["dispatch"]["operator_hold"] is True
    assert item["notification"]["dispatch"]["verification"]["label"] == "Marked unknown sender"
    assert "unknown sender" in item["notification"]["dispatch"]["blocked_reasons"][0]
    assert db_session.query(WorkspaceAuditLog).count() == 1


def test_domain_remediation_notification_lifecycle_audit_rejects_mismatched_event(
    seeded_client: TestClient,
    monkeypatch,
):
    """Lifecycle markers must match the current remediation notification metadata."""

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 72,
            "grade": "C",
            "status": "attention",
            "factors": {"dns_posture": 60},
            "actions": [],
        }

    async def fake_dns_guidance(db, store, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "critical",
            "dns_provider": {"provider_id": "cloudflare"},
            "findings": [],
            "change_plans": [
                {
                    "plan_id": "dmarc-missing",
                    "finding_code": "dmarc_missing",
                    "severity": "error",
                    "operation": "create",
                    "record_type": "TXT",
                    "name": "_dmarc.example.com",
                    "proposed_value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                    "current_values": [],
                    "rationale": "Publish a monitoring DMARC record.",
                    "expected_health_impact": "High",
                    "manual_steps": ["Create the TXT record."],
                }
            ],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: ["cloudflare"])
    monkeypatch.setattr(
        domains_endpoint,
        "_recommended_dns_write_provider",
        lambda dns_provider, available_providers: "cloudflare",
    )

    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "event": "dmarq.remediation.summary",
            "lifecycle_state": "acknowledged",
        },
    )

    assert response.status_code == 400
    assert "does not match" in response.json()["detail"]

    empty_event_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "event": "",
            "lifecycle_state": "acknowledged",
        },
    )

    assert empty_event_response.status_code == 400
    assert "does not match" in empty_event_response.json()["detail"]


def test_domain_remediation_notification_lifecycle_audit_rejects_invalid_state(
    seeded_client: TestClient,
):
    """Lifecycle markers only accept the explicit operator states."""
    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "lifecycle_state": "sent",
        },
    )

    assert response.status_code == 422
    assert "Unsupported lifecycle_state" in response.json()["detail"]


def test_domain_remediation_notification_lifecycle_audit_rejects_unknown_item(
    seeded_client: TestClient,
    monkeypatch,
):
    """Lifecycle markers must target a current remediation queue item."""

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 100,
            "grade": "A",
            "status": "healthy",
            "factors": {},
            "actions": [],
        }

    async def fake_dns_guidance(db, store, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "healthy",
            "dns_provider": None,
            "findings": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: [])

    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "lifecycle_state": "previewed",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Remediation item not found"


def test_domain_remediation_notification_lifecycle_audit_rejects_mismatched_dedupe_key(
    seeded_client: TestClient,
    monkeypatch,
):
    """Lifecycle markers can optionally guard against stale dedupe keys."""

    async def fake_domain_grade(db, domain_id, store, refresh=False):
        return {
            "domain": domain_id,
            "score": 72,
            "grade": "C",
            "status": "attention",
            "factors": {"dns_posture": 60},
            "actions": [],
        }

    async def fake_dns_guidance(db, store, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "critical",
            "dns_provider": {"provider_id": "cloudflare"},
            "findings": [],
            "change_plans": [
                {
                    "plan_id": "dmarc-missing",
                    "finding_code": "dmarc_missing",
                    "severity": "error",
                    "operation": "create",
                    "record_type": "TXT",
                    "name": "_dmarc.example.com",
                    "proposed_value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                    "current_values": [],
                    "rationale": "Publish a monitoring DMARC record.",
                    "expected_health_impact": "High",
                    "manual_steps": ["Create the TXT record."],
                }
            ],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: ["cloudflare"])
    monkeypatch.setattr(
        domains_endpoint,
        "_recommended_dns_write_provider",
        lambda dns_provider, available_providers: "cloudflare",
    )

    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "dedupe_key": "stale-key",
            "lifecycle_state": "previewed",
        },
    )

    assert response.status_code == 400
    assert "dedupe_key does not match" in response.json()["detail"]

    empty_dedupe_response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/remediation/notifications/audit",
        json={
            "item_id": "dns:dmarc-missing",
            "dedupe_key": "",
            "lifecycle_state": "previewed",
        },
    )

    assert empty_dedupe_response.status_code == 400
    assert "dedupe_key does not match" in empty_dedupe_response.json()["detail"]


def test_domain_remediation_queue_hydrates_report_store_with_workspace_filter(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Domain remediation only hydrates reports scoped to the authorized workspace."""
    workspace = get_or_create_default_workspace(db_session)
    captured = {}

    def fake_hydrate(db, store_arg, workspace_id=None):
        captured["workspace_id"] = workspace_id
        return 1

    async def fake_domain_grade(db, domain_id, store_arg, refresh=False):
        return {
            "domain": domain_id,
            "score": 100,
            "grade": "A",
            "status": "healthy",
            "factors": {},
            "actions": [],
        }

    async def fake_dns_guidance(db, store_arg, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "healthy",
            "dns_provider": None,
            "findings": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)
    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: [])

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/remediation")

    assert response.status_code == 200
    assert captured["workspace_id"] == workspace.id
    assert response.json()["domain"] == DOMAIN


def test_domain_remediation_queue_falls_back_for_legacy_report_domains(
    authed_client: TestClient,
    monkeypatch,
):
    """Domain remediation uses scoped hydration before legacy report-only fallback."""
    hydrate_calls = []

    def fake_hydrate(db, store_arg, workspace_id=None):
        hydrate_calls.append(workspace_id)
        if workspace_id is not None:
            store_arg.clear()
            return 0
        store_arg.add_report(REPORT_DICT_POLICY)
        return 1

    async def fake_domain_grade(db, domain_id, store_arg, refresh=False):
        return {
            "domain": domain_id,
            "score": 100,
            "grade": "A",
            "status": "healthy",
            "factors": {},
            "actions": [],
        }

    async def fake_dns_guidance(db, store_arg, domain_id, refresh=False):
        return {
            "domain": domain_id,
            "status": "healthy",
            "dns_provider": None,
            "findings": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)
    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: [])

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/remediation")

    assert response.status_code == 200
    assert len(hydrate_calls) == 2
    assert hydrate_calls[0] is not None
    assert hydrate_calls[1] is None
    assert response.json()["domain"] == DOMAIN


def test_domain_remediation_queue_accepts_numeric_domain_id(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Domain remediation resolves numeric path IDs to the authorized domain name."""
    domain = db_session.query(Domain).filter(Domain.name == DOMAIN).one()
    hydrate_calls = []
    seen_domains = []

    def fake_hydrate(db, store_arg, workspace_id=None):
        hydrate_calls.append(workspace_id)
        return 1

    async def fake_domain_grade(db, domain_id, store_arg, refresh=False):
        seen_domains.append(domain_id)
        return {
            "domain": domain_id,
            "score": 100,
            "grade": "A",
            "status": "healthy",
            "factors": {},
            "actions": [],
        }

    async def fake_dns_guidance(db, store_arg, domain_id, refresh=False):
        seen_domains.append(domain_id)
        return {
            "domain": domain_id,
            "status": "healthy",
            "dns_provider": None,
            "findings": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)
    monkeypatch.setattr(domains_endpoint, "_build_domain_health_grade", fake_domain_grade)
    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_dns_guidance)
    monkeypatch.setattr(domains_endpoint, "_ready_dns_write_provider_ids", lambda: [])

    response = seeded_client.get(f"/api/v1/domains/{domain.id}/remediation")

    assert response.status_code == 200
    assert len(hydrate_calls) == 1
    assert hydrate_calls[0] is not None
    assert seen_domains == [DOMAIN, DOMAIN]
    assert response.json()["domain"] == DOMAIN


def test_domain_remediation_queue_rejects_other_workspace_numeric_domain_without_fallback(
    seeded_client: TestClient,
    db_session,
    monkeypatch,
):
    """Existing domains outside the authorized workspace do not trigger legacy fallback."""
    other_workspace = Workspace(slug="other-remediation", name="Other Remediation", active=True)
    db_session.add(other_workspace)
    db_session.flush()
    other_domain = Domain(
        name="other-remediation.example",
        workspace_id=other_workspace.id,
        active=True,
    )
    db_session.add(other_domain)
    db_session.commit()
    hydrate_calls = []

    def fake_hydrate(db, store_arg, workspace_id=None):
        hydrate_calls.append(workspace_id)
        return 0

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)

    response = seeded_client.get(f"/api/v1/domains/{other_domain.id}/remediation")

    assert response.status_code == 404
    assert len(hydrate_calls) == 1
    assert hydrate_calls[0] is not None


@pytest.mark.parametrize("other_workspace_active", [True, False])
def test_domain_remediation_queue_rejects_report_only_fallback_with_multiple_workspaces(
    authed_client: TestClient,
    db_session,
    monkeypatch,
    other_workspace_active,
):
    """Legacy report-only fallback is only safe for single-workspace deployments."""
    other_workspace = Workspace(
        slug="second-remediation",
        name="Second Remediation",
        active=other_workspace_active,
    )
    db_session.add(other_workspace)
    db_session.commit()
    hydrate_calls = []

    def fake_hydrate(db, store_arg, workspace_id=None):
        hydrate_calls.append(workspace_id)
        if workspace_id is None:
            store_arg.add_report(REPORT_DICT_POLICY)
            return 1
        store_arg.clear()
        return 0

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/remediation")

    assert response.status_code == 404
    assert len(hydrate_calls) == 1
    assert hydrate_calls[0] is not None


def test_domain_health_history_rejects_invalid_date_order(seeded_client: TestClient):
    """Health history validates that the start date is not after the end date."""
    response = seeded_client.get(
        f"/api/v1/domains/{DOMAIN}/posture/history"
        "?start_date=2026-06-03&end_date=2026-06-02&capture_current=false"
    )

    assert response.status_code == 422


def test_workspace_health_history_rejects_invalid_date_order(seeded_client: TestClient):
    """Workspace health history validates that the start date is not after the end date."""
    response = seeded_client.get(
        "/api/v1/domains/summary/health/history" "?start_date=2026-06-03&end_date=2026-06-02"
    )

    assert response.status_code == 422


def test_workspace_health_evidence_export_rejects_invalid_date_order(
    seeded_client: TestClient,
):
    """Workspace evidence export validates date order."""
    response = seeded_client.get(
        "/api/v1/domains/summary/health/evidence/export"
        "?start_date=2026-06-03&end_date=2026-06-02"
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


def test_workspace_health_history_uses_demo_history_fallback(
    authed_client: TestClient,
    monkeypatch,
):
    """Demo mode serves rolling workspace health history without persisted snapshots."""
    _enable_endpoint_demo_mode(monkeypatch)

    response = authed_client.get(
        "/api/v1/domains/summary/health/history" "?start_date=2026-06-01&limit=3"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "workspace"
    assert 0 < len(data["points"]) <= 3
    assert data["current_score"] is not None
    assert data["points"][-1]["domain_count"] == 2


def test_workspace_health_evidence_export_uses_demo_history_fallback(
    authed_client: TestClient,
    monkeypatch,
):
    """Demo mode exports rolling workspace evidence without persisted snapshots."""
    _enable_endpoint_demo_mode(monkeypatch)

    response = authed_client.get(
        "/api/v1/domains/summary/health/evidence/export"
        "?format=json&start_date=2026-06-01&limit=2"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "workspace"
    assert 0 < len(data["rows"]) <= 2
    assert data["rows"][-1]["domain"] == "workspace"
    top_action_domains = {
        action.partition(":")[0] for action in data["rows"][-1]["top_actions"].split("; ") if action
    }
    assert top_action_domains == {"dmarq" + ".org", "dmarq" + ".com"}


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

    workspace_points = domains_endpoint._demo_workspace_history_points(
        ["dmarq.org", "dmarq.com"],
        start_date=date(2026, 6, 1),
        limit=2,
    )
    workspace_response = domains_endpoint._workspace_history_response_from_points(workspace_points)
    assert len(workspace_response.points) <= 2
    assert workspace_response.current_score is not None
    workspace_rows = domains_endpoint._workspace_evidence_export_rows(workspace_points)
    assert workspace_rows[0]["domain"] == "workspace"
    top_action_domains = {
        action.partition(":")[0]
        for action in workspace_rows[0]["top_actions"].split("; ")
        if action
    }
    assert top_action_domains == {"dmarq" + ".org", "dmarq" + ".com"}


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


def test_get_domain_migration_readiness_projects_parallel_cutover_state(
    seeded_client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    """Migration readiness summarizes reports, sources, DNS state, and exports."""

    async def fake_guidance(*_args, **_kwargs):
        return {
            "domain": DOMAIN,
            "status": "ready",
            "findings": [],
            "target_records": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_guidance)

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/migration/readiness")

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["report_count"] == 1
    assert data["source_count"] == 1
    assert data["parallel_reporting_days"] == 1
    assert data["status"] == "in_progress"
    assert data["readiness_score"] == 80
    statuses = {item["key"]: item["status"] for item in data["checklist"]}
    assert statuses["parallel-reporting"] == "complete"
    assert statuses["volume-parity"] == "in_progress"
    assert statuses["dns-readiness"] == "complete"
    titles = {item["key"]: item["title"] for item in data["checklist"]}
    assert titles["volume-parity"] == "Build 14-30 days of report evidence"
    assert titles["sender-parity"] == "Review observed sending sources"
    assert any(link["format"] == "json" for link in data["export_links"])
    assert {link["label"] for link in data["export_links"]} >= {
        "Workspace health evidence",
        "DNS lint CSV",
    }
    assert "DMARCguard" in data["supported_sources"]


def test_get_domain_migration_readiness_accepts_canonical_domain_id(
    seeded_client: TestClient,
    db_session,
    monkeypatch: pytest.MonkeyPatch,
):
    """Path IDs resolve to the canonical domain name before report lookups."""
    domain = db_session.query(Domain).filter(Domain.name == DOMAIN).one()

    async def fake_guidance(*_args, **_kwargs):
        assert _args[2] == DOMAIN
        return {
            "domain": DOMAIN,
            "status": "ready",
            "findings": [],
            "target_records": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_guidance)

    response = seeded_client.get(f"/api/v1/domains/{domain.id}/migration/readiness")

    assert response.status_code == 200
    assert response.json()["domain"] == DOMAIN


def test_resolve_domain_name_for_read_accepts_report_store_only_domain(db_session):
    """Legacy ReportStore-only domains can still resolve through the helper."""
    store_only_domain = "store-only.example"
    store = ReportStore()
    store.add_report(
        {
            **REPORT_DICT_POLICY,
            "domain": store_only_domain,
            "report_id": "rpt-store-only-domain",
            "records": [
                {
                    **REPORT_DICT_POLICY["records"][0],
                    "header_from": store_only_domain,
                }
            ],
        }
    )

    resolved = domains_endpoint._resolve_domain_name_for_read(
        db_session,
        store,
        store_only_domain,
        SimpleNamespace(id=1),
    )

    assert resolved == store_only_domain


def test_get_domain_migration_readiness_returns_404_for_missing_domain(
    seeded_client: TestClient,
):
    """Unknown domains are rejected before readiness guidance is built."""
    response = seeded_client.get("/api/v1/domains/missing.example/migration/readiness")

    assert response.status_code == 404
    assert response.json()["detail"] == "Domain not found"


def test_get_domain_migration_parity_requires_legacy_baseline(seeded_client: TestClient):
    """Parity dashboard is explicit when the old-platform baseline is missing."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/migration/parity")

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["status"] == "baseline_needed"
    assert data["baseline_required"] is True
    metrics = {metric["key"]: metric for metric in data["metrics"]}
    assert metrics["reports"]["dmarq_display"] == "1"
    assert metrics["messages"]["dmarq_display"] == "10"
    assert metrics["sources"]["dmarq_display"] == "1"
    assert metrics["alignment"]["dmarq_display"] == "100.0%"
    assert metrics["policy"]["dmarq_display"] == "reject"
    assert {metric["status"] for metric in data["metrics"]} == {"baseline_needed"}


def test_get_domain_migration_parity_matches_legacy_baseline(seeded_client: TestClient):
    """Matching legacy values mark migration parity as matched."""
    response = seeded_client.get(
        f"/api/v1/domains/{DOMAIN}/migration/parity"
        "?baseline_report_count=1"
        "&baseline_total_emails=10"
        "&baseline_source_count=1"
        "&baseline_compliance_rate=100"
        "&baseline_policy=reject"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "matched"
    assert data["baseline_required"] is False
    assert {metric["status"] for metric in data["metrics"]} == {"matched"}
    assert data["metrics"][0]["baseline_display"] == "1"


def test_get_domain_migration_parity_flags_legacy_mismatch(seeded_client: TestClient):
    """Parity dashboard calls out mismatched legacy baseline values."""
    response = seeded_client.get(
        f"/api/v1/domains/{DOMAIN}/migration/parity"
        "?baseline_report_count=0"
        "&baseline_total_emails=20"
        "&baseline_source_count=0"
        "&baseline_compliance_rate=80"
        "&baseline_policy=none"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "attention"
    assert data["baseline_required"] is False
    assert data["summary"] == (
        "Some migration parity signals differ from the legacy-platform baseline."
    )
    assert data["next_steps"][0] == (
        "Review attention metrics before removing legacy reporting routes."
    )
    metrics = {metric["key"]: metric for metric in data["metrics"]}
    assert metrics["reports"]["status"] == "attention"
    assert metrics["reports"]["delta"] == 100.0
    assert metrics["messages"]["status"] == "attention"
    assert metrics["messages"]["delta"] == -50.0
    assert metrics["alignment"]["status"] == "attention"
    assert metrics["alignment"]["delta"] == 20.0
    assert metrics["policy"]["status"] == "attention"
    assert metrics["policy"]["baseline_display"] == "none"


def test_preview_domain_migration_import_csv_baseline(seeded_client: TestClient):
    """Historical CSV exports are normalized without writing reports."""
    content = "\n".join(
        [
            "Domain,Report ID,Date,Source IP,Messages,DKIM,SPF,Policy,Reporter",
            "example.com,legacy-1,2026-06-01,192.0.2.10,8,pass,fail,reject,Vendor",
            "example.com,legacy-1,2026-06-01,192.0.2.20,2,fail,pass,reject,Vendor",
        ]
    )
    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/migration/import/preview",
        json={
            "format": "csv",
            "source_platform": "DMARCguard",
            "content": content,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["status"] == "ready"
    assert data["import_mode"] == "preview_only"
    assert data["row_count"] == 2
    assert data["normalized_count"] == 2
    assert data["ignored_count"] == 0
    assert data["rejected_count"] == 0
    assert data["truncated_count"] == 0
    assert data["importable_row_count"] == 2
    assert data["planned_report_count"] == 1
    assert data["existing_report_count"] == 0
    assert data["duplicate_row_count"] == 0
    assert data["needs_report_id_count"] == 0
    assert data["batch_fingerprint"].startswith("mib_")
    assert data["baseline"] == {
        "report_count": 1,
        "total_emails": 10,
        "source_count": 2,
        "compliance_rate": 100.0,
        "policy": "reject",
        "date_start": None,
        "date_end": "2026-06-01",
    }
    assert data["mapped_columns"]["source_ip"] == "Source IP"
    assert data["sample_rows"][0]["source_ip"] == "192.0.2.10"
    assert data["sample_rows"][0]["row_key"].startswith("mir_")
    assert data["sample_rows"][0]["report_import_key"].startswith("mip_")
    assert data["sample_rows"][0]["import_status"] == "planned"
    assert data["next_steps"][-1] == (
        "Keep the old DMARC platform active until mismatches are explained."
    )


def test_preview_domain_migration_import_marks_existing_workspace_reports(
    seeded_client: TestClient,
):
    """Import planning checks existing reports only in the authorized workspace."""
    content = "\n".join(
        [
            "Domain,Report ID,Date,Source IP,Messages,DKIM,SPF,Policy",
            "example.com,rpt-dict-policy,2026-06-01,192.0.2.10,8,pass,fail,reject",
            "example.com,legacy-new,2026-06-01,192.0.2.20,2,fail,pass,reject",
        ]
    )

    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/migration/import/preview",
        json={
            "format": "csv",
            "content": content,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["existing_report_count"] == 1
    assert data["planned_report_count"] == 1
    assert data["importable_row_count"] == 1
    assert data["sample_rows"][0]["import_status"] == "existing_report"
    assert data["sample_rows"][1]["import_status"] == "planned"
    assert "Export contains reports that already exist in DMARQ." in data["warnings"]


def test_preview_domain_migration_import_json_warns_on_domain_mismatch(
    seeded_client: TestClient,
):
    """Preview remains domain scoped and warns when export rows include other domains."""
    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/migration/import/preview",
        json={
            "format": "json",
            "content": {
                "rows": [
                    {
                        "domain": "other.example",
                        "report_id": "legacy-2",
                        "source_ip": "198.51.100.10",
                        "count": 5,
                        "dkim_result": "fail",
                        "spf_result": "pass",
                        "policy": "p=none",
                    }
                ]
            },
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["baseline"]["policy"] == "none"
    assert data["baseline"]["compliance_rate"] == 100.0
    assert data["warnings"][0] == "Export contains rows for other domains: other.example"


def test_preview_domain_migration_import_rejects_invalid_json(seeded_client: TestClient):
    """Invalid vendor export payloads return a clear 400 without side effects."""
    response = seeded_client.post(
        f"/api/v1/domains/{DOMAIN}/migration/import/preview",
        json={"format": "json", "content": "{not-json"},
    )

    assert response.status_code == 400
    assert response.json()["detail"].startswith("JSON content could not be parsed:")


def test_get_domain_migration_readiness_blocks_empty_domain(
    authed_client: TestClient,
    db_session,
    monkeypatch: pytest.MonkeyPatch,
):
    """A pre-created domain remains migration-blocked until reports arrive."""
    db_session.add(Domain(name="empty.example", active=True))
    db_session.commit()

    async def fake_guidance(*_args, **_kwargs):
        return {
            "domain": "empty.example",
            "status": "attention",
            "findings": [
                {
                    "code": "dmarc_missing",
                    "severity": "error",
                    "title": "Publish DMARC",
                    "detail": "No DMARC record was found.",
                    "action": "Publish a DMARC record before cutover.",
                    "record_type": "TXT",
                    "record_name": "_dmarc.empty.example",
                    "evidence": [],
                    "remediation_steps": [],
                }
            ],
            "target_records": [],
            "change_plans": [],
        }

    monkeypatch.setattr(domains_endpoint, "_build_domain_dns_guidance", fake_guidance)

    response = authed_client.get("/api/v1/domains/empty.example/migration/readiness")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "blocked"
    assert data["readiness_score"] == 0
    assert data["report_count"] == 0
    assert data["source_count"] == 0
    assert all(item["status"] == "blocked" for item in data["checklist"])


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
    assert source["first_seen"] == REPORT_DICT_POLICY["begin_timestamp"]
    assert source["last_seen"] == REPORT_DICT_POLICY["end_timestamp"]
    assert source["active_days"] == 1
    assert source["report_count"] == 1
    assert source["volume_history"] == [
        {
            "date": "2020-08-15",
            "count": 10,
            "passed": 4,
            "failed": 6,
        }
    ]


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
    assert {"unknown_sender", "full_fail", "policy_not_enforced"}.issubset(recommendation_types)
    assert source["sender"]["name"] == "Unknown sender"
    assert source["sender"]["status"] == "unknown"
    assert source["spf_fix_hint"] is None


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


def test_single_domain_report_store_resolves_numeric_domain_id(db_session):
    """Single-domain report hydration accepts persisted numeric domain IDs."""
    workspace = get_or_create_default_workspace(db_session)
    domain = Domain(name="numeric-source.example", workspace_id=workspace.id, active=True)
    db_session.add(domain)
    db_session.commit()

    domain_name, store = domains_endpoint._single_domain_report_store_for_read(
        db_session,
        str(domain.id),
        workspace,
    )

    assert domain_name == "numeric-source.example"
    assert store.get_domain_reports(domain_name) == []


def test_single_domain_report_store_rejects_missing_domain_when_fallback_disabled(db_session):
    """Multi-workspace setups must not fall back to legacy report-only global cache."""
    alpha = Workspace(slug="source-alpha", name="Source Alpha", active=True)
    beta = Workspace(slug="source-beta", name="Source Beta", active=True)
    db_session.add_all([alpha, beta])
    db_session.commit()

    with pytest.raises(domains_endpoint.HTTPException) as exc_info:
        domains_endpoint._single_domain_report_store_for_read(
            db_session,
            "missing-source.example",
            alpha,
        )

    assert exc_info.value.status_code == 404


def test_get_domain_source_intelligence_returns_regions_and_anomalies(
    seeded_client: TestClient,
):
    """Source intelligence summarizes regions and notable sending-source changes."""

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/source-intelligence?days=30")

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["summary"]["regions"] >= 1
    assert data["summary"]["sources"] >= 1
    assert data["summary"]["messages"] >= 10
    assert any(region["message_count"] == 10 for region in data["regions"])
    assert any(
        anomaly["type"] == "new_sender" and anomaly["source_ip"] == "209.85.220.1"
        for anomaly in data["anomalies"]
    )


def test_get_domain_source_intelligence_unknown_domain_returns_404(
    authed_client: TestClient,
):
    """Source intelligence returns 404 for unknown domains."""

    response = authed_client.get("/api/v1/domains/missing.example/source-intelligence")

    assert response.status_code == 404


def test_get_domain_sources_includes_geo_and_anomaly_hints(seeded_client: TestClient):
    """Source rows carry coarse geo data and anomaly recommendations."""

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=30")

    assert response.status_code == 200
    source = next(item for item in response.json()["sources"] if item["anomalies"])
    assert source["geo"]["region"]
    assert any(anomaly["type"] == "new_sender" for anomaly in source["anomalies"])
    recommendation_types = {item["type"] for item in source["recommendations"]}
    assert "anomaly_new_sender" in recommendation_types


def test_get_domain_sources_includes_ip_intelligence_and_reputation(
    seeded_client: TestClient, db_session, monkeypatch: pytest.MonkeyPatch
):
    """Source rows include PTR, geo/ASN, and reputation details for UI guidance."""

    source_ip = "193.138.195.141"

    async def fake_ptr_lookup(_provider, ip, timeout=3.0):  # pylint: disable=unused-argument
        return "smtp.customer.example" if ip == source_ip else None

    async def fake_reputation(*_args, **_kwargs):
        return (
            DomainReputation(
                domain=DOMAIN,
                status="attention",
                checked_at="2026-07-02T08:00:00Z",
                summary={"listed": 1, "suspicious": 0, "clean": 0, "unknown": 0},
                sources=[
                    SourceReputation(
                        ip=source_ip,
                        status="listed",
                        risk_score=85,
                        summary="Observed source is listed by a reputation feed.",
                        listings=["Spamhaus Zen"],
                        evidence=[
                            ReputationEvidence(
                                label="External feed",
                                value="Spamhaus Zen",
                                source="dnsbl",
                            )
                        ],
                        recommendations=[
                            "Review the listed IP with the named reputation provider.",
                        ],
                        checked_at="2026-07-02T08:00:00Z",
                    )
                ],
            ),
            False,
            None,
        )

    async def fake_networks(*_args, **_kwargs):
        return {
            source_ip: SourceNetworkIntelligence(
                ip=source_ip,
                asn="AS24940",
                as_name="Hetzner Online GmbH",
                bgp_prefix="193.138.192.0/19",
                country_code="DE",
                country="Germany",
                region="Europe",
                registry="ripencc",
                allocated="2004-02-17",
                source="team-cymru",
                checked_at="2026-07-02T08:00:00Z",
            )
        }

    monkeypatch.setattr(domains_endpoint, "_safe_ptr_lookup", fake_ptr_lookup)
    monkeypatch.setattr(domains_endpoint, "build_source_reputation_cached", fake_reputation)
    monkeypatch.setattr(domains_endpoint, "lookup_sources_network_cached", fake_networks)
    workspace = get_or_create_default_workspace(db_session)
    report = {
        **REPORT_DICT_POLICY,
        "report_id": "rpt-source-intelligence",
        "records": [
            {
                "source_ip": source_ip,
                "count": 20,
                "disposition": "reject",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": DOMAIN,
            }
        ],
        "summary": {"total_count": 20, "passed_count": 0, "failed_count": 20},
    }
    report_persistence.save_parsed_report(db_session, report, workspace_id=workspace.id)
    db_session.commit()

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=30")

    assert response.status_code == 200
    source = next(item for item in response.json()["sources"] if item["ip"] == source_ip)
    assert source["hostname"] == "smtp.customer.example"
    assert source["geo"]["country"] == "Germany"
    assert source["geo"]["country_code"] == "DE"
    assert source["geo"]["region"] == "Europe"
    assert source["geo"]["asn"] == "AS24940"
    assert source["geo"]["network"] == "Hetzner Online GmbH"
    assert source["geo"]["bgp_prefix"] == "193.138.192.0/19"
    assert source["geo"]["registry"] == "ripencc"
    assert source["geo"]["allocated"] == "2004-02-17"
    assert source["geo"]["network_source"] == "team-cymru"
    assert source["reputation"]["status"] == "listed"
    assert source["reputation"]["status_label"] == "Listed"
    assert source["reputation"]["feed_status"] == "listed"
    assert "Spamhaus Zen" in source["reputation"]["feed_summary"]
    assert source["reputation"]["risk_score"] == 85
    assert source["reputation"]["listings"] == ["Spamhaus Zen"]
    recommendation_types = {item["type"] for item in source["recommendations"]}
    assert "source_reputation" in recommendation_types


def test_get_domain_sources_continues_when_enrichment_times_out(
    seeded_client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    """Slow enrichment providers must not block the sending-source table."""

    async def timeout_networks(*_args, **_kwargs):
        raise asyncio.TimeoutError

    async def timeout_reputation(*_args, **_kwargs):
        raise asyncio.TimeoutError

    monkeypatch.setattr(domains_endpoint, "lookup_sources_network_cached", timeout_networks)
    monkeypatch.setattr(domains_endpoint, "build_source_reputation_cached", timeout_reputation)

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=30")

    assert response.status_code == 200
    sources = response.json()["sources"]
    assert sources
    assert all("ip" in source for source in sources)
    assert all(source["reputation"] is None for source in sources)


def test_get_domain_sources_refreshes_reputation_cache(
    seeded_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    """The detail-page reload path forces reputation evidence refresh for sources."""
    captured_refresh = []

    async def fake_reputation(*_args, **kwargs):
        captured_refresh.append(kwargs.get("refresh"))
        return (
            DomainReputation(
                domain=DOMAIN,
                status="clean",
                checked_at="2026-07-02T08:00:00Z",
                summary={"listed": 0, "suspicious": 0, "clean": 1, "unknown": 0},
                sources=[],
            ),
            False,
            None,
        )

    monkeypatch.setattr(domains_endpoint, "build_source_reputation_cached", fake_reputation)

    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=30&refresh=true")

    assert response.status_code == 200
    assert captured_refresh == [True]


def test_source_detail_endpoints_use_single_domain_persisted_reports(
    authed_client: TestClient,
    db_session,
    monkeypatch: pytest.MonkeyPatch,
):
    """Source detail endpoints avoid workspace-wide report-store hydration."""
    workspace = get_or_create_default_workspace(db_session)
    report_persistence.save_parsed_report(
        db_session,
        {
            **REPORT_DICT_POLICY,
            "domain": "fast-sources.example",
            "report_id": "fast-sources-001",
            "records": [
                {
                    "source_ip": "203.0.113.42",
                    "count": 4,
                    "disposition": "none",
                    "dkim_result": "pass",
                    "spf_result": "pass",
                    "header_from": "fast-sources.example",
                }
            ],
            "summary": {"total_count": 4, "passed_count": 4, "failed_count": 0},
        },
        workspace_id=workspace.id,
    )
    db_session.commit()

    def fail_hydrate(*_args, **_kwargs):
        raise AssertionError("source detail routes should not hydrate the full ReportStore")

    async def fake_ptr_lookup(*_args, **_kwargs):
        return "mail.fast-sources.example"

    async def fake_reputation(*_args, **_kwargs):
        return (
            DomainReputation(
                domain="fast-sources.example",
                status="clean",
                checked_at="2026-07-02T08:00:00Z",
                summary={"listed": 0, "suspicious": 0, "clean": 1, "unknown": 0},
                sources=[],
            ),
            False,
            None,
        )

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fail_hydrate)
    monkeypatch.setattr(domains_endpoint, "_safe_ptr_lookup", fake_ptr_lookup)
    monkeypatch.setattr(domains_endpoint, "build_source_reputation_cached", fake_reputation)

    sources = authed_client.get("/api/v1/domains/fast-sources.example/sources?days=30")
    intelligence = authed_client.get(
        "/api/v1/domains/fast-sources.example/source-intelligence?days=30"
    )
    reputation = authed_client.get("/api/v1/domains/fast-sources.example/source-reputation?days=30")

    assert sources.status_code == 200
    assert sources.json()["sources"][0]["ip"] == "203.0.113.42"
    assert intelligence.status_code == 200
    assert intelligence.json()["summary"]["messages"] == 4
    assert reputation.status_code == 200
    assert reputation.json()["domain"] == "fast-sources.example"


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


def test_source_recommendations_do_not_suggest_raw_spf_ip_for_unknown_forwarder():
    """DKIM-preserving forwarders should not produce copy-paste SPF IP changes."""
    source = {
        "source_ip": "74.6.131.41",
        "spf_result": "fail",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "dmarc_pass_count": 1,
        "dmarc_fail_count": 0,
        "disposition": "none",
    }
    sender = {
        "id": "unknown-sender",
        "name": "Unknown sender",
        "status": "unknown",
        "reason": "No known provider profile matched this source.",
        "remediation_hint": "Identify the business owner before authorizing it.",
    }

    recommendations = domains_endpoint._source_recommendations(  # pylint: disable=protected-access
        "74.6.131.41",
        source,
        "sonic303-2.consmr.mail.bf2.yahoo.com",
        "ip4:74.6.131.41",
        sender,
    )

    dkim_only = next(item for item in recommendations if item.type == "dkim_only_pass")
    assert "ip4:74.6.131.41" not in dkim_only.action
    assert dkim_only.action == (
        "Authorize this service in SPF, or confirm SPF is intentionally handled elsewhere."
    )


@pytest.mark.asyncio
async def test_safe_ptr_lookup_skips_invalid_ips(monkeypatch: pytest.MonkeyPatch):
    """PTR lookup refuses invalid source addresses before querying DNS."""

    class InvalidProvider:
        async def lookup_ptr(self, _ip):
            raise AssertionError("lookup_ptr should not be called")

    class FailingProvider:
        async def lookup_ptr(self, _ip):
            raise LookupError("no PTR")

    class EmptyFallbackProvider:
        async def lookup_ptr(self, _ip):
            return None

    monkeypatch.setattr(
        domains_endpoint,
        "PublicRecursiveDNSProvider",
        lambda: EmptyFallbackProvider(),
    )
    monkeypatch.setattr(
        domains_endpoint,
        "CloudflareDNSProvider",
        lambda: EmptyFallbackProvider(),
    )

    assert (
        await domains_endpoint._safe_ptr_lookup(  # pylint: disable=protected-access
            InvalidProvider(), "not-an-ip"
        )
        is None
    )
    assert (
        await domains_endpoint._safe_ptr_lookup(  # pylint: disable=protected-access
            InvalidProvider(), "10.0.0.1"
        )
        is None
    )
    assert (
        await domains_endpoint._safe_ptr_lookup(  # pylint: disable=protected-access
            FailingProvider(), "203.0.113.7"
        )
        is None
    )


@pytest.mark.asyncio
async def test_safe_ptr_lookup_uses_public_fallback(monkeypatch: pytest.MonkeyPatch):
    """PTR lookup falls back when the selected deployment resolver has no answer."""

    class EmptyPrimaryProvider:
        async def lookup_ptr(self, _ip):
            return None

    class WorkingFallbackProvider:
        async def lookup_ptr(self, ip):
            assert ip == "104.245.209.200"
            return "mta200a-ord.mtasv.net."

    monkeypatch.setattr(
        domains_endpoint,
        "PublicRecursiveDNSProvider",
        lambda: WorkingFallbackProvider(),
    )

    hostname = await domains_endpoint._safe_ptr_lookup(  # pylint: disable=protected-access
        EmptyPrimaryProvider(), "104.245.209.200"
    )

    assert hostname == "mta200a-ord.mtasv.net"


@pytest.mark.asyncio
async def test_safe_ptr_lookup_propagates_cancellation(monkeypatch: pytest.MonkeyPatch):
    """Request cancellation must not be hidden as a recoverable DNS miss."""

    class CancelledProvider:
        async def lookup_ptr(self, _ip):
            raise asyncio.CancelledError()

    class UnexpectedFallbackProvider:
        async def lookup_ptr(self, _ip):
            raise AssertionError("fallback should not run after cancellation")

    monkeypatch.setattr(
        domains_endpoint,
        "PublicRecursiveDNSProvider",
        lambda: UnexpectedFallbackProvider(),
    )
    monkeypatch.setattr(
        domains_endpoint,
        "CloudflareDNSProvider",
        lambda: UnexpectedFallbackProvider(),
    )

    with pytest.raises(asyncio.CancelledError):
        await domains_endpoint._safe_ptr_lookup(  # pylint: disable=protected-access
            CancelledProvider(), "104.245.209.200"
        )


@pytest.mark.asyncio
async def test_source_networks_by_ip_handles_disabled_and_failed_enrichment(
    db_session,
    monkeypatch: pytest.MonkeyPatch,
):
    """Network enrichment helper falls back to core source data when optional lookups fail."""

    disabled_settings = SimpleNamespace(SOURCE_NETWORK_ENRICHMENT_ENABLED=False)
    assert (
        await domains_endpoint._source_networks_by_ip(  # pylint: disable=protected-access
            db_session, object(), ["203.0.113.7"], disabled_settings
        )
        == {}
    )

    async def failing_network_lookup(*_args, **_kwargs):
        raise RuntimeError("network provider unavailable")

    monkeypatch.setattr(
        domains_endpoint,
        "lookup_sources_network_cached",
        failing_network_lookup,
    )
    enabled_settings = SimpleNamespace(
        SOURCE_NETWORK_ENRICHMENT_ENABLED=True,
        SOURCE_NETWORK_ENRICHMENT_CACHE_SECONDS=3600,
        SOURCE_NETWORK_ENRICHMENT_MAX_IPS=10,
        SOURCE_NETWORK_ENRICHMENT_DETAIL_TIMEOUT_SECONDS=1.0,
    )

    assert (
        await domains_endpoint._source_networks_by_ip(  # pylint: disable=protected-access
            db_session, object(), ["203.0.113.7"], enabled_settings
        )
        == {}
    )


@pytest.mark.asyncio
async def test_source_reputations_by_ip_handles_failed_enrichment(
    db_session,
    monkeypatch: pytest.MonkeyPatch,
):
    """Reputation helper falls back to no reputation data when optional lookups fail."""

    async def failing_reputation_lookup(*_args, **_kwargs):
        raise RuntimeError("reputation provider unavailable")

    monkeypatch.setattr(
        domains_endpoint,
        "build_source_reputation_cached",
        failing_reputation_lookup,
    )

    assert (
        await domains_endpoint._source_reputations_by_ip(  # pylint: disable=protected-access
            db_session,
            DOMAIN,
            [],
            [],
            {},
            {},
            30,
            False,
            SimpleNamespace(SOURCE_REPUTATION_DETAIL_TIMEOUT_SECONDS=1.0),
        )
        == {}
    )


def test_get_domain_sources_days_param_accepted(seeded_client: TestClient):
    """The 'days' query parameter is accepted without raising a TypeError."""
    response = seeded_client.get(f"/api/v1/domains/{DOMAIN}/sources?days=7")
    assert response.status_code == 200


def test_get_domain_sources_unknown_domain_returns_404(authed_client: TestClient):
    """Returns 404 when the requested domain has no reports."""
    response = authed_client.get("/api/v1/domains/no-such-domain.example.com/sources")
    assert response.status_code == 404
