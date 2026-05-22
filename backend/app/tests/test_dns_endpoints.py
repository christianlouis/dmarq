"""
Integration tests for the DKIM selector management API endpoints.

These tests use the in-memory SQLite test database via the ``client`` fixture
(which overrides ``get_db``) and populate the ``ReportStore`` singleton so
that the endpoints can find the test domain.

DNS lookups are mocked so no real network calls are made.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.api.api_v1.endpoints.domains import _spf_fix_hint
from app.models.dns_cache import DNSCache
from app.models.domain import Domain
from app.services.dns_resolver import DomainDNSResult
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
    return patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=AsyncMock(check_domain=AsyncMock(return_value=result)),
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


def test_add_selector(client: TestClient):
    """Adding a selector persists it and returns the updated list."""
    response = client.post(
        f"/api/v1/domains/{DOMAIN}/selectors",
        json={"selector": "mysel"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "mysel" in data["selectors"]


def test_add_selector_deduplication(client: TestClient):
    """Adding the same selector twice should not create duplicates."""
    client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "dup"})
    response = client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "dup"})
    assert response.status_code == 201
    assert response.json()["selectors"].count("dup") == 1


def test_add_selector_invalid_empty(client: TestClient):
    """An empty selector string should be rejected."""
    response = client.post(
        f"/api/v1/domains/{DOMAIN}/selectors",
        json={"selector": "   "},
    )
    assert response.status_code == 422


def test_add_selector_unknown_domain(client: TestClient):
    """Adding a selector to an unknown domain returns 404."""
    response = client.post(
        "/api/v1/domains/unknown.example.com/selectors",
        json={"selector": "google"},
    )
    assert response.status_code == 404


def test_add_multiple_selectors(client: TestClient):
    """Multiple distinct selectors can be added and all are returned."""
    for sel in ("sel1", "sel2", "sel3"):
        r = client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": sel})
        assert r.status_code == 201

    response = client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert response.status_code == 200
    selectors = response.json()["selectors"]
    assert "sel1" in selectors
    assert "sel2" in selectors
    assert "sel3" in selectors


# ---------------------------------------------------------------------------
# DELETE /api/v1/domains/{domain_id}/selectors/{selector}
# ---------------------------------------------------------------------------


def test_delete_selector(client: TestClient):
    """Deleting a selector removes it from the persisted list."""
    client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "todelete"})
    response = client.delete(f"/api/v1/domains/{DOMAIN}/selectors/todelete")
    assert response.status_code == 200
    assert "todelete" not in response.json()["selectors"]


def test_delete_nonexistent_selector(client: TestClient):
    """Deleting a selector that was never added returns 404."""
    # Ensure the domain exists in DB (via add then delete)
    client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "dummy"})
    response = client.delete(f"/api/v1/domains/{DOMAIN}/selectors/ghost")
    assert response.status_code == 404


def test_delete_selector_unknown_domain(client: TestClient):
    """Deleting from an unknown domain returns 404."""
    response = client.delete("/api/v1/domains/unknown.example.com/selectors/google")
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


def test_get_selectors_report_selector_moves_to_manual_when_added(client: TestClient):
    """A selector discovered from reports should appear only in 'selectors' once added manually."""
    # Confirm it's in report_selectors before adding
    r1 = client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert "google" in r1.json()["report_selectors"]

    # Add it as a manual selector
    client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "google"})

    r2 = client.get(f"/api/v1/domains/{DOMAIN}/selectors")
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


def test_dns_endpoint_uses_manual_selectors(client: TestClient):
    """Manually added selectors should be forwarded to check_domain."""
    # Add a custom selector
    client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "customsel"})

    captured_selectors = []

    async def _fake_check_domain(domain, selectors=None):
        captured_selectors.extend(selectors or [])
        return MOCK_DNS_RESULT

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=AsyncMock(check_domain=_fake_check_domain),
    ):
        client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert "customsel" in captured_selectors


def test_dns_endpoint_404_for_unknown_domain(client: TestClient):
    with _mock_dns():
        response = client.get("/api/v1/domains/unknown.example.com/dns")
    assert response.status_code == 404


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


def test_summary_endpoint_uses_manual_selectors(client: TestClient):
    """Manually configured selectors are forwarded by the summary endpoint."""
    client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "manualsel"})
    captured_selectors = []

    async def _fake_check_domain(domain, selectors=None):
        captured_selectors.extend(selectors or [])
        return MOCK_DNS_RESULT

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=AsyncMock(check_domain=_fake_check_domain),
    ):
        response = client.get("/api/v1/domains/summary")

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
