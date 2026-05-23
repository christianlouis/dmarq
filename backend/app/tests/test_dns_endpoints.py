"""
Integration tests for the DKIM selector management API endpoints.

These tests use the in-memory SQLite test database via the ``client`` fixture
(which overrides ``get_db``) and populate the ``ReportStore`` singleton so
that the endpoints can find the test domain.

DNS lookups are mocked so no real network calls are made.
"""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.api.api_v1.endpoints.domains import _spf_fix_hint
from app.models.dns_cache import DNSCache, DNSRecordChange
from app.models.domain import Domain
from app.services.bimi import BIMIResult
from app.services.dns_cache import _selectors_key, resolve_domain_dns_cached
from app.services.dns_resolver import DomainDNSResult
from app.services.mta_sts import MTAStsResult
from app.services.report_store import ReportStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOMAIN = "example.com"

# A minimal parsed DMARC report that populates the ReportStore
MINIMAL_REPORT = {
    "domain": DOMAIN,
    "report_id": "test-001",
    "org_name": "Test Org",
    "policy": {"p": "none", "sp": "", "pct": "100"},
    "records": [
        {
            "source_ip": "1.2.3.4",
            "count": 5,
            "disposition": "none",
            "dkim_result": "pass",
            "spf_result": "pass",
            "dkim": [{"domain": DOMAIN, "result": "pass", "selector": "google"}],
            "spf": [{"domain": DOMAIN, "result": "pass"}],
        }
    ],
    "summary": {"total_count": 5, "passed_count": 5, "failed_count": 0, "pass_rate": 100.0},
}

# DomainDNSResult returned by the mocked DNS provider
MOCK_DNS_RESULT = DomainDNSResult(
    dmarc=True,
    dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
    spf=True,
    spf_record="v=spf1 include:_spf.google.com ~all",
    dkim=True,
    dkim_selectors=["google"],
    dkim_record="v=DKIM1; k=rsa; p=ABC",
)


@pytest.fixture(autouse=True)
def _seed_report_store():
    """Put a domain into the ReportStore for every test in this module."""
    store = ReportStore.get_instance()
    store.add_report(MINIMAL_REPORT)
    yield


def _mock_dns(result: DomainDNSResult = MOCK_DNS_RESULT):
    """Return a context manager that patches the DNS provider's check_domain."""
    provider = AsyncMock()
    provider.check_domain = AsyncMock(return_value=result)
    provider.lookup_txt = AsyncMock(side_effect=LookupError("MTA-STS not configured"))
    return patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=provider,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/selectors
# ---------------------------------------------------------------------------


def test_get_selectors_empty(client: TestClient):
    """Returns an empty list when no selectors have been configured."""
    response = client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert response.status_code == 200
    data = response.json()
    assert data["selectors"] == []
    assert "report_selectors" in data


def test_get_selectors_unknown_domain(client: TestClient):
    """Returns 404 for a domain not in the ReportStore."""
    response = client.get("/api/v1/domains/unknown.example.com/selectors")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/domains/{domain_id}/selectors
# ---------------------------------------------------------------------------


def test_add_selector(authed_client: TestClient):
    """Adding a selector persists it and returns the updated list."""
    response = authed_client.post(
        f"/api/v1/domains/{DOMAIN}/selectors",
        json={"selector": "mysel"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "mysel" in data["selectors"]


def test_add_selector_deduplication(authed_client: TestClient):
    """Adding the same selector twice should not create duplicates."""
    authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "dup"})
    response = authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "dup"})
    assert response.status_code == 201
    assert response.json()["selectors"].count("dup") == 1


def test_add_selector_invalid_empty(authed_client: TestClient):
    """An empty selector string should be rejected."""
    response = authed_client.post(
        f"/api/v1/domains/{DOMAIN}/selectors",
        json={"selector": "   "},
    )
    assert response.status_code == 422


def test_add_selector_unknown_domain(authed_client: TestClient):
    """Adding a selector to an unknown domain returns 404."""
    response = authed_client.post(
        "/api/v1/domains/unknown.example.com/selectors",
        json={"selector": "google"},
    )
    assert response.status_code == 404


def test_add_multiple_selectors(authed_client: TestClient):
    """Multiple distinct selectors can be added and all are returned."""
    for sel in ("sel1", "sel2", "sel3"):
        r = authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": sel})
        assert r.status_code == 201

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert response.status_code == 200
    selectors = response.json()["selectors"]
    assert "sel1" in selectors
    assert "sel2" in selectors
    assert "sel3" in selectors


# ---------------------------------------------------------------------------
# DELETE /api/v1/domains/{domain_id}/selectors/{selector}
# ---------------------------------------------------------------------------


def test_delete_selector(authed_client: TestClient):
    """Deleting a selector removes it from the persisted list."""
    authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "todelete"})
    response = authed_client.delete(f"/api/v1/domains/{DOMAIN}/selectors/todelete")
    assert response.status_code == 200
    assert "todelete" not in response.json()["selectors"]


def test_delete_nonexistent_selector(authed_client: TestClient):
    """Deleting a selector that was never added returns 404."""
    # Ensure the domain exists in DB (via add then delete)
    authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "dummy"})
    response = authed_client.delete(f"/api/v1/domains/{DOMAIN}/selectors/ghost")
    assert response.status_code == 404


def test_delete_selector_unknown_domain(authed_client: TestClient):
    """Deleting from an unknown domain returns 404."""
    response = authed_client.delete("/api/v1/domains/unknown.example.com/selectors/google")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/dns  (real DNS replaced by mock)
# ---------------------------------------------------------------------------


def test_get_selectors_includes_report_selectors(client: TestClient):
    """Report selectors (from DMARC report records) are returned in report_selectors."""
    response = client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert response.status_code == 200
    data = response.json()
    # The MINIMAL_REPORT has a record with selector "google" in its dkim auth results
    assert "google" in data["report_selectors"]


def test_get_selectors_ignores_missing_dkim_detail_lists(client: TestClient):
    """Missing or malformed DKIM auth-detail arrays should not break selectors."""
    ReportStore.get_instance().add_report(
        {
            **MINIMAL_REPORT,
            "report_id": "missing-dkim-details",
            "records": [
                {
                    "source_ip": "203.0.113.10",
                    "count": 1,
                    "disposition": "none",
                    "dkim_result": "pass",
                    "spf_result": "pass",
                    "dkim": ["not-a-dict", {"selector": "mail"}],
                    "spf": None,
                }
            ],
        }
    )

    response = client.get(f"/api/v1/domains/{DOMAIN}/selectors")

    assert response.status_code == 200
    assert "mail" in response.json()["report_selectors"]


def test_get_selectors_report_selector_moves_to_manual_when_added(authed_client: TestClient):
    """A selector discovered from reports should appear only in 'selectors' once added manually."""
    # Confirm it's in report_selectors before adding
    r1 = authed_client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert "google" in r1.json()["report_selectors"]

    # Add it as a manual selector
    authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "google"})

    r2 = authed_client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    data = r2.json()
    assert "google" in data["selectors"]
    # It must not appear in both lists
    assert "google" not in data["report_selectors"]


def test_dns_endpoint_returns_dkim_selectors_as_list(client: TestClient):
    """The /dns endpoint should return dkimSelectors as a list."""
    with _mock_dns():
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["dkimSelectors"], list)
    assert "google" in data["dkimSelectors"]


def test_dns_endpoint_returns_real_data(client: TestClient):
    """The /dns endpoint should return the mocked DNS check result."""
    with _mock_dns():
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert response.status_code == 200
    data = response.json()
    assert data["dmarc"] is True
    assert data["spf"] is True
    assert data["dkim"] is True
    assert "p=none" in data["dmarcRecord"]
    assert data["cached"] is False
    assert data["checkedAt"] is not None


def test_dns_endpoint_uses_cached_result(client: TestClient, db_session):
    """Repeated DNS checks reuse a fresh cached result."""
    mock_provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=mock_provider,
    ):
        first = client.get(f"/api/v1/domains/{DOMAIN}/dns")
        second = client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["cached"] is False
    assert second.json()["cached"] is True
    assert mock_provider.check_domain.await_count == 1
    assert db_session.query(DNSCache).count() == 1


@pytest.mark.asyncio
async def test_dns_cache_recovers_from_concurrent_insert(db_session, monkeypatch):
    """Concurrent DNS widgets should not fail on a duplicate cache insert."""
    mock_provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))
    selectors = ["google"]
    original_commit = db_session.commit
    original_rollback = db_session.rollback
    commit_calls = 0

    def fake_commit():
        nonlocal commit_calls
        commit_calls += 1
        if commit_calls == 1:
            raise IntegrityError("insert", {}, Exception("duplicate"))
        original_commit()

    def fake_rollback():
        original_rollback()
        db_session.add(
            DNSCache(
                domain=DOMAIN,
                provider=mock_provider.__class__.__name__,
                selectors_key=_selectors_key(selectors),
                result_json=(
                    '{"dmarc":false,"spf":false,"dkim":false,'
                    '"dkim_selectors":[],"selectors_checked":[]}'
                ),
                checked_at=datetime(2026, 5, 23, 12, 0, 0),
            )
        )
        original_commit()

    monkeypatch.setattr(db_session, "commit", fake_commit)
    monkeypatch.setattr(db_session, "rollback", fake_rollback)

    result, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        mock_provider,
        DOMAIN,
        selectors=selectors,
    )

    assert result == MOCK_DNS_RESULT
    assert cached is False
    assert db_session.query(DNSCache).count() == 1


@pytest.mark.asyncio
async def test_dns_cache_reraises_when_conflict_row_missing(db_session, monkeypatch):
    """Unexpected cache collisions should still surface when no row can be recovered."""
    mock_provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))

    def fake_commit():
        raise IntegrityError("insert", {}, Exception("duplicate"))

    monkeypatch.setattr(db_session, "commit", fake_commit)

    with pytest.raises(IntegrityError):
        await resolve_domain_dns_cached(
            db_session,
            mock_provider,
            DOMAIN,
            selectors=["google"],
        )


def test_dns_endpoint_refresh_bypasses_cache(client: TestClient):
    """The refresh query parameter forces a new DNS lookup."""
    mock_provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=mock_provider,
    ):
        client.get(f"/api/v1/domains/{DOMAIN}/dns")
        refreshed = client.get(f"/api/v1/domains/{DOMAIN}/dns?refresh=true")

    assert refreshed.status_code == 200
    assert refreshed.json()["cached"] is False
    assert mock_provider.check_domain.await_count == 2


def test_dns_endpoint_uses_manual_selectors(authed_client: TestClient):
    """Manually added selectors should be forwarded to check_domain."""
    # Add a custom selector
    authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "customsel"})

    captured_selectors = []

    async def _fake_check_domain(domain, selectors=None):
        captured_selectors.extend(selectors or [])
        return MOCK_DNS_RESULT

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=AsyncMock(check_domain=_fake_check_domain),
    ):
        authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert "customsel" in captured_selectors


def test_dns_endpoint_404_for_unknown_domain(client: TestClient):
    with _mock_dns():
        response = client.get("/api/v1/domains/unknown.example.com/dns")
    assert response.status_code == 404


def test_dns_endpoint_supports_manually_configured_domain(client: TestClient, db_session):
    """A domain created before reports arrive can still run DNS checks."""
    db_session.add(Domain(name="manual.example", active=True))
    db_session.commit()

    with _mock_dns():
        response = client.get("/api/v1/domains/manual.example/dns")

    assert response.status_code == 200
    assert response.json()["dmarc"] is True


def test_dns_health_404_for_unknown_domain(client: TestClient):
    with _mock_dns():
        response = client.get("/api/v1/domains/unknown.example.com/dns/health")
    assert response.status_code == 404


def test_dns_health_links_checks_to_evidence(client: TestClient):
    """DNS health returns provider-neutral checks, recommendations, and evidence links."""
    missing_dkim = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 include:_spf.google.com ~all",
        dkim=False,
        selectors_checked=["google"],
    )

    mta_sts = MTAStsResult(
        status="pass",
        dns_record="v=STSv1; id=20260523",
        policy_url="https://mta-sts.example.com/.well-known/mta-sts.txt",
        mode="enforce",
        max_age=86400,
        mx=["*.example.com"],
    )
    bimi = BIMIResult(
        status="pass",
        dns_record="v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
        logo_url="https://example.com/logo.svg",
        certificate_url="https://example.com/vmc.pem",
    )
    with (
        _mock_dns(result=missing_dkim),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    dkim_check = next(check for check in data["checks"] if check["key"] == "dkim")
    mta_sts_check = next(check for check in data["checks"] if check["key"] == "mta_sts")
    bimi_check = next(check for check in data["checks"] if check["key"] == "bimi")
    assert dkim_check["status"] == "fail"
    assert dkim_check["evidence"][0]["href"] == "#dns-records"
    assert mta_sts_check["status"] == "pass"
    assert mta_sts_check["evidence"][1]["href"] == "#mta-sts-posture"
    assert bimi_check["status"] == "fail"
    assert bimi_check["evidence"][0]["href"] == "#bimi-posture"
    assert any(item["type"] == "bimi_dmarc_not_ready" for item in data["recommendations"])
    assert any(item["type"] == "missing_dkim" for item in data["recommendations"])


def test_dns_health_recommends_enforcement_when_evidence_supports_it(client: TestClient):
    """High-volume p=none domains with strong compliance get plan-only guidance."""
    store = ReportStore.get_instance()
    store.clear()
    store.add_report(
        {
            **MINIMAL_REPORT,
            "summary": {"total_count": 500, "passed_count": 495, "failed_count": 5},
            "records": [
                {
                    **MINIMAL_REPORT["records"][0],
                    "count": 500,
                    "dkim_result": "pass",
                    "spf_result": "pass",
                }
            ],
        }
    )

    with _mock_dns():
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns/health")

    assert response.status_code == 200
    recommendations = response.json()["recommendations"]
    readiness = next(item for item in recommendations if item["type"] == "policy_enforcement_ready")
    assert "low pct" in readiness["action"]
    assert any(item["label"] == "Compliance" for item in readiness["evidence"])


def test_dns_health_marks_all_missing_records_critical(client: TestClient):
    """Missing DMARC, SPF, and DKIM produce specific repair recommendations."""
    missing_all = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["google"],
    )

    with _mock_dns(result=missing_all):
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "critical"
    recommendation_types = [item["type"] for item in data["recommendations"]]
    assert {"missing_dmarc", "missing_spf", "missing_dkim"}.issubset(set(recommendation_types))
    assert recommendation_types.count("missing_mta_sts") == 1
    assert recommendation_types.count("missing_bimi") == 1
    assert any(item["type"] == "policy_needs_more_data" for item in data["recommendations"])


def test_mta_sts_endpoint_returns_cached_posture(client: TestClient):
    """The domain detail page can fetch MTA-STS posture with cache metadata."""
    checked_at = datetime(2026, 5, 23, 12, 0, 0)
    result = MTAStsResult(
        status="fail",
        dns_record=None,
        policy_url=f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt",
        errors=["No _mta-sts TXT record was found."],
    )

    with patch(
        "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
        new=AsyncMock(return_value=(result, True, checked_at)),
    ):
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns/mta-sts")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "fail"
    assert data["cached"] is True
    assert data["checked_at"] == checked_at.isoformat()
    assert data["errors"] == ["No _mta-sts TXT record was found."]


def test_mta_sts_endpoint_returns_404_for_unknown_domain(client: TestClient):
    response = client.get("/api/v1/domains/unknown.example.com/dns/mta-sts")

    assert response.status_code == 404


def test_bimi_endpoint_returns_cached_posture(client: TestClient):
    """The domain detail page can fetch BIMI posture with cache metadata."""
    checked_at = datetime(2026, 5, 23, 12, 0, 0)
    result = BIMIResult(
        status="pass",
        selector="default",
        query_name=f"default._bimi.{DOMAIN}",
        dns_record="v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
        logo_url="https://example.com/logo.svg",
        certificate_url="https://example.com/vmc.pem",
    )

    with patch(
        "app.api.api_v1.endpoints.domains.check_bimi_cached",
        new=AsyncMock(return_value=(result, True, checked_at)),
    ):
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns/bimi")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pass"
    assert data["query_name"] == f"default._bimi.{DOMAIN}"
    assert data["logo_url"] == "https://example.com/logo.svg"
    assert data["cached"] is True
    assert data["checked_at"] == checked_at.isoformat()


def test_bimi_endpoint_returns_404_for_unknown_domain(client: TestClient):
    response = client.get("/api/v1/domains/unknown.example.com/dns/bimi")

    assert response.status_code == 404


def test_posture_dashboard_links_recommendations_changes_and_playbooks(
    client: TestClient, db_session
):
    """The posture dashboard is actionable and links back to underlying evidence."""
    db_session.add(
        DNSRecordChange(
            domain=DOMAIN,
            provider="cloudflare",
            zone_id="zone-1",
            record_key="dmarc",
            record_type="TXT",
            record_name=f"_dmarc.{DOMAIN}",
            change_type="modified",
            previous_content="v=DMARC1; p=none",
            current_content="v=DMARC1; p=quarantine; pct=100",
            observed_at=datetime(2026, 5, 23, 12, 0, 0),
        )
    )
    db_session.commit()

    missing_spf = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com",
        spf=False,
        dkim=True,
        dkim_selectors=["google"],
        dkim_record="v=DKIM1; k=rsa; p=ABC",
    )
    mta_sts = MTAStsResult(
        status="pass",
        dns_record="v=STSv1; id=20260523",
        policy_url="https://mta-sts.example.com/.well-known/mta-sts.txt",
        mode="enforce",
        max_age=86400,
        mx=["*.example.com"],
    )
    bimi = BIMIResult(
        status="pass",
        dns_record="v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
        logo_url="https://example.com/logo.svg",
        certificate_url="https://example.com/vmc.pem",
    )

    with (
        _mock_dns(result=missing_spf),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = client.get(f"/api/v1/domains/{DOMAIN}/posture")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert data["score"] == 80
    assert any(item["key"] == "spf" and item["href"] == "#dns-records" for item in data["coverage"])
    missing_spf_recommendation = next(
        item for item in data["recommendations"] if item["type"] == "missing_spf"
    )
    assert missing_spf_recommendation["evidence"][0]["href"] == "#dns-records"
    assert data["changes"][0]["title"] == f"TXT _dmarc.{DOMAIN} modified"
    assert data["changes"][0]["evidence"][0]["value"] == "v=DMARC1; p=none"
    assert any(playbook["key"] == "missing_spf" for playbook in data["playbooks"])


def test_posture_dashboard_returns_404_for_unknown_domain(client: TestClient):
    response = client.get("/api/v1/domains/unknown.example.com/posture")

    assert response.status_code == 404


def test_domain_detail_data_endpoints_support_manually_configured_domain(
    client: TestClient, db_session
):
    """Manually monitored domains should render empty detail data instead of 404s."""
    db_session.add(Domain(name="manual.example", active=True))
    db_session.commit()

    reports = client.get("/api/v1/domains/manual.example/reports")
    sources = client.get("/api/v1/domains/manual.example/sources")
    selectors = client.get("/api/v1/domains/manual.example/selectors")

    assert reports.status_code == 200
    assert reports.json()["reports"] == []
    assert sources.status_code == 200
    assert sources.json()["sources"] == []
    assert selectors.status_code == 200
    assert selectors.json() == {"selectors": [], "report_selectors": []}


@pytest.mark.parametrize(
    ("policy", "summary", "expected_type", "expected_severity"),
    [
        (
            "quarantine",
            {"total_count": 1000, "failed_count": 50, "compliance_rate": 95.0},
            "policy_already_enforced",
            "info",
        ),
        (
            "none",
            {"total_count": 50, "failed_count": 0, "compliance_rate": 100.0},
            "policy_needs_more_data",
            "warning",
        ),
        (
            "none",
            {"total_count": 200, "failed_count": 15, "compliance_rate": 92.5},
            "policy_enforcement_review",
            "warning",
        ),
        (
            "none",
            {"total_count": 200, "failed_count": 80, "compliance_rate": 60.0},
            "policy_not_ready",
            "error",
        ),
    ],
)
def test_enforcement_recommendation_common_states(
    policy, summary, expected_type, expected_severity
):
    """Policy guidance covers enforced, low-volume, review, and not-ready states."""
    recommendation = domains_endpoint._enforcement_recommendation(policy, summary)

    assert recommendation.type == expected_type
    assert recommendation.severity == expected_severity
    assert recommendation.evidence[0].value == f"p={policy}"


# ---------------------------------------------------------------------------
# GET /api/v1/domains/summary  (DNS fields included)
# ---------------------------------------------------------------------------


def test_summary_includes_dns_fields(client: TestClient):
    """The summary endpoint should include dmarc_status, spf_status, dkim_status."""
    with _mock_dns():
        response = client.get("/api/v1/domains/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["total_domains"] == 1
    domain = data["domains"][0]
    assert "dmarc_status" in domain
    assert "spf_status" in domain
    assert "dkim_status" in domain
    assert domain["dmarc_status"] is True
    assert domain["spf_status"] is True
    assert domain["dkim_status"] is True
    assert domain["dmarc_policy"] == "none"


def test_summary_dns_failure_defaults_false(client: TestClient):
    """If DNS check fails, status fields default to False rather than crashing."""
    empty_result = DomainDNSResult()

    with _mock_dns(result=empty_result):
        response = client.get("/api/v1/domains/summary")

    assert response.status_code == 200
    domain = response.json()["domains"][0]
    assert domain["dmarc_status"] is False
    assert domain["spf_status"] is False
    assert domain["dkim_status"] is False


def test_summary_endpoint_uses_manual_selectors(authed_client: TestClient):
    """Manually configured selectors are forwarded by the summary endpoint."""
    authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "manualsel"})
    captured_selectors = []

    async def _fake_check_domain(domain, selectors=None):
        captured_selectors.extend(selectors or [])
        return MOCK_DNS_RESULT

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=AsyncMock(check_domain=_fake_check_domain),
    ):
        response = authed_client.get("/api/v1/domains/summary")

    assert response.status_code == 200
    assert "manualsel" in captured_selectors
    assert "google" in captured_selectors


def test_selector_map_lookup_chunks_domain_names(db_session, monkeypatch):
    """Large summary batches are split to avoid database parameter limits."""
    monkeypatch.setattr(domains_endpoint, "DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE", 2)
    db_session.add_all(
        [
            Domain(name="one.example", dkim_selectors="a,b"),
            Domain(name="two.example", dkim_selectors="c"),
            Domain(name="three.example", dkim_selectors="d"),
        ]
    )
    db_session.commit()

    selectors = domains_endpoint._get_domain_selectors_map_from_db(
        db_session,
        ["one.example", "two.example", "three.example", "one.example"],
    )

    assert selectors == {
        "one.example": ["a", "b"],
        "two.example": ["c"],
        "three.example": ["d"],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/sources  (PTR + fix hints)
# ---------------------------------------------------------------------------

# A failing-source report used for sources tests
FAILING_SOURCE_REPORT = {
    "domain": DOMAIN,
    "report_id": "fail-src-001",
    "org_name": "Fail Org",
    "policy": {"p": "reject", "sp": "", "pct": "100"},
    "records": [
        {
            "source_ip": "10.0.0.1",
            "count": 3,
            "disposition": "reject",
            "dkim_result": "fail",
            "spf_result": "fail",
            "dkim": [],
            "spf": [],
        }
    ],
    "summary": {"total_count": 3, "passed_count": 0, "failed_count": 3, "pass_rate": 0.0},
}


def _mock_provider(hostname=None):
    """Return a context manager that patches get_default_provider with a PTR mock."""
    mock_prov = AsyncMock()
    mock_prov.check_domain = AsyncMock(return_value=MOCK_DNS_RESULT)
    mock_prov.lookup_ptr = AsyncMock(return_value=hostname)
    return patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=mock_prov,
    )


def test_sources_endpoint_includes_hostname(client: TestClient):
    """The /sources endpoint should return the rDNS hostname when available."""
    store = ReportStore.get_instance()
    store.add_report(FAILING_SOURCE_REPORT)

    with _mock_provider(hostname="mail.example.com"):
        response = client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    # Find the failing source
    failing = next((s for s in sources if s["ip"] == "10.0.0.1"), None)
    assert failing is not None
    assert failing["hostname"] == "mail.example.com"


def test_sources_endpoint_hostname_none_when_no_ptr(client: TestClient):
    """The /sources endpoint should return null hostname when no PTR record exists."""
    with _mock_provider(hostname=None):
        response = client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    for source in sources:
        # hostname may be null; it must not crash
        assert "hostname" in source


def test_sources_endpoint_spf_fix_hint_for_failing_ip(client: TestClient):
    """A source with spf=fail should receive an spf_fix_hint containing its IP."""
    store = ReportStore.get_instance()
    store.add_report(FAILING_SOURCE_REPORT)

    with _mock_provider():
        response = client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    failing = next((s for s in sources if s["ip"] == "10.0.0.1"), None)
    assert failing is not None
    assert failing["spf_fix_hint"] == "ip4:10.0.0.1"


def test_sources_endpoint_no_fix_hint_when_spf_passes(client: TestClient):
    """A source with spf=pass should not receive an spf_fix_hint."""
    with _mock_provider():
        response = client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    passing = next((s for s in sources if s["ip"] == "1.2.3.4"), None)
    if passing is not None:
        assert passing["spf_fix_hint"] is None


def test_spf_fix_hint_returns_none_for_invalid_ip_with_failures():
    """Invalid source IP values should not generate SPF snippets."""
    assert _spf_fix_hint("not-an-ip", "mixed", failed_count=3) is None
