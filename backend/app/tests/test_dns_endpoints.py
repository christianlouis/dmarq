"""
Integration tests for the DKIM selector management API endpoints.

These tests use the in-memory SQLite test database via the ``client`` fixture
(which overrides ``get_db``) and populate the ``ReportStore`` singleton so
that the endpoints can find the test domain.

DNS lookups are mocked so no real network calls are made.
"""

import asyncio
import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.api.api_v1.endpoints.domains import (
    _domain_names_for_summary,
    _remediation_loop_state,
    _spf_fix_hint,
)
from app.models.dns_cache import DNSCache, DNSRecordChange
from app.models.domain import Domain
from app.models.organization import Entitlement, Organization
from app.models.report import DMARCReport, ReportRecord
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog
from app.services.bimi import BIMIResult
from app.services.dane import DANEResult, TLSARecord, TLSASuggestion
from app.services.dns_cache import _selectors_key, resolve_domain_dns_cached
from app.services.dns_provider_detection import detect_dns_provider
from app.services.dns_resolver import (
    CloudflareDNSProvider,
    ConfiguredRecursiveDNSProvider,
    DomainDNSResult,
    PublicRecursiveDNSProvider,
    SystemDNSProvider,
)
from app.services.mta_sts import MTAStsResult
from app.services.remediation_dispatch import summarize_remediation_activity
from app.services.report_persistence import save_parsed_report
from app.services.report_store import ReportStore
from app.services.source_reputation import DomainReputation
from app.services.workspaces import get_or_create_default_workspace

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
    provider.lookup_cname = AsyncMock(return_value=None)
    return patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=provider,
    )


def _persist_minimal_report(db_session, domain_name: str = DOMAIN):
    """Persist the default report fixture into the workspace-scoped report tables."""
    save_parsed_report(
        db_session,
        {
            **MINIMAL_REPORT,
            "domain": domain_name,
            "report_id": f"{domain_name}-summary-fixture",
        },
    )
    db_session.commit()


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/selectors
# ---------------------------------------------------------------------------


def test_get_selectors_empty(authed_client: TestClient):
    """Returns an empty list when no selectors have been configured."""
    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert response.status_code == 200
    data = response.json()
    assert data["selectors"] == []
    assert "report_selectors" in data


def test_get_selectors_unknown_domain(authed_client: TestClient):
    """Returns 404 for a domain not in the ReportStore."""
    response = authed_client.get("/api/v1/domains/unknown.example.com/selectors")
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


def test_get_selectors_includes_report_selectors(authed_client: TestClient):
    """Report selectors (from DMARC report records) are returned in report_selectors."""
    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/selectors")
    assert response.status_code == 200
    data = response.json()
    # The MINIMAL_REPORT has a record with selector "google" in its dkim auth results
    assert "google" in data["report_selectors"]


def test_get_selectors_ignores_missing_dkim_detail_lists(authed_client: TestClient):
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

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/selectors")

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
    assert "google" not in data["report_selectors"]


def test_get_source_reputation_returns_listed_source(authed_client: TestClient, db_session):
    """Source reputation exposes listed sender IP evidence for domain detail views."""
    report = {
        **MINIMAL_REPORT,
        "report_id": "listed-source-reputation",
        "records": [
            {
                "source_ip": "198.51.100.199",
                "count": 12,
                "disposition": "none",
                "dkim_result": "fail",
                "spf_result": "fail",
                "dkim": [{"domain": DOMAIN, "result": "fail", "selector": "legacy"}],
                "spf": [{"domain": DOMAIN, "result": "fail"}],
                "extensions": {
                    "demo:source": "unknown-forwarder",
                    "demo:reputation": "listed",
                    "demo:blacklists": "Demo RBL",
                },
            }
        ],
    }
    save_parsed_report(db_session, report)
    db_session.commit()

    response = authed_client.get(f"/api/v1/domains/{DOMAIN}/source-reputation")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "listed"
    assert data["summary"]["listed"] == 1
    assert data["feeds"]["spamhaus_dqs"]["enabled"] is False
    assert data["feeds"]["spamcop_scbl"]["default_enabled"] is False
    listed = next(source for source in data["sources"] if source["ip"] == "198.51.100.199")
    assert listed["status"] == "listed"
    assert listed["listings"] == ["Demo RBL"]


def test_dns_endpoint_returns_dkim_selectors_as_list(authed_client: TestClient):
    """The /dns endpoint should return dkimSelectors as a list."""
    with _mock_dns():
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["dkimSelectors"], list)
    assert "google" in data["dkimSelectors"]


def test_dns_endpoint_returns_real_data(authed_client: TestClient):
    """The /dns endpoint should return the mocked DNS check result."""
    with _mock_dns():
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert response.status_code == 200
    data = response.json()
    assert data["dmarc"] is True
    assert data["spf"] is True
    assert data["dkim"] is True
    assert "p=none" in data["dmarcRecord"]
    assert data["cached"] is False
    assert data["checkedAt"] is not None


def test_dns_endpoint_labels_lookup_failure_without_claiming_records_are_missing(
    authed_client: TestClient,
):
    """A resolver exception should surface as lookup failure evidence."""
    provider = AsyncMock()
    provider.check_domain = AsyncMock(side_effect=LookupError("resolver unavailable"))
    provider.lookup_txt = AsyncMock(side_effect=LookupError("resolver unavailable"))
    provider.lookup_cname = AsyncMock(return_value=None)

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=provider,
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns?refresh=true")

    assert response.status_code == 200
    data = response.json()
    assert data["dmarc"] is False
    assert data["spf"] is False
    assert data["dkim"] is False
    assert data["lookupStatus"] == "failed"
    assert "LookupError" in data["lookupError"]
    assert data["dmarcRecord"] is None
    assert data["spfRecord"] is None


def test_dns_endpoint_labels_backend_fallback_evidence(authed_client: TestClient):
    """The UI can surface that backend resolver fallback supplied DNS evidence."""
    result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        lookup_status="fallback",
        lookup_error="No DNS evidence from PublicRecursiveDNSProvider; using CloudflareDNSProvider.",
    )

    with _mock_dns(result):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns?refresh=true")

    assert response.status_code == 200
    data = response.json()
    assert data["lookupStatus"] == "fallback"
    assert "CloudflareDNSProvider" in data["lookupError"]
    assert data["dmarc"] is True
    assert data["spf"] is True


def test_dns_endpoint_returns_dmarc_lint_findings(
    authed_client: TestClient,
    monkeypatch,
):
    result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@reports.example.net",
        spf=True,
        spf_record="v=spf1 include:_spf.example.com -all",
        dkim=False,
        dmarc_warnings=["External rua destination reports.example.net is missing authorization."],
        dmarc_suggestions=["Policy is monitoring-only."],
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )

    monkeypatch.setattr(
        domains_endpoint,
        "get_cloudflare_credentials",
        lambda db: SimpleNamespace(configured=False),
    )

    with _mock_dns(result):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert response.status_code == 200
    data = response.json()
    assert data["dmarcWarnings"] == result.dmarc_warnings
    assert data["dmarcSuggestions"] == result.dmarc_suggestions
    assert data["nameservers"] == ["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]
    assert data["dnsProvider"]["provider_id"] == "cloudflare"
    assert data["dnsProvider"]["connector_available"] is True
    assert data["providerContext"]["status"] == "connect"
    assert data["providerContext"]["detected_provider_id"] == "cloudflare"
    assert data["providerContext"]["connected"] is False
    assert data["providerContext"]["can_import_zones"] is True
    assert data["providerContext"]["can_preview_repairs"] is True
    assert data["providerContext"]["can_apply_repairs"] is False
    assert data["providerContext"]["cta_href"] == "/settings#provider-integrations"


def test_dns_endpoint_marks_connected_provider_repair_ready(
    authed_client: TestClient,
    monkeypatch,
):
    result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 include:_spf.example.com -all",
        dkim=True,
        dkim_selectors=["google"],
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )
    monkeypatch.setattr(
        domains_endpoint,
        "get_cloudflare_credentials",
        lambda db: SimpleNamespace(configured=True),
    )

    with _mock_dns(result):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")

    assert response.status_code == 200
    context = response.json()["providerContext"]
    assert context["status"] == "connected"
    assert context["connected"] is True
    assert context["can_apply_repairs"] is True
    assert context["cta_href"] == "#dns-guidance"


def test_dns_lint_endpoint_returns_typed_findings_and_targets(authed_client: TestClient):
    result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 include:_spf.example.com ~all",
        dkim=False,
        selectors_checked=["selector1"],
        nameservers=["ns1.digitalocean.com", "ns2.digitalocean.com"],
        dns_provider=detect_dns_provider(["ns1.digitalocean.com", "ns2.digitalocean.com"]),
    )
    mta_sts = MTAStsResult(errors=["No _mta-sts TXT record was found."])
    bimi = BIMIResult(errors=["No BIMI TXT record was found at the selector."])

    with (
        _mock_dns(result),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/lint")

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["status"] == "attention"
    assert data["dns_provider"]["provider_id"] == "digitalocean"
    assert data["dns_provider"]["confidence"] == "high"
    codes = {finding["code"] for finding in data["findings"]}
    assert {"dkim_selector_missing", "tls_rpt_missing", "bimi_dmarc_not_enforced"}.issubset(codes)
    assert {record["code"] for record in data["target_records"]} >= {
        "target_dmarc",
        "target_spf",
        "target_dkim",
        "target_tls_rpt",
    }
    dkim_finding = next(
        finding for finding in data["findings"] if finding["code"] == "dkim_selector_missing"
    )
    assert dkim_finding["remediation_steps"]
    assert "Publish" in " ".join(dkim_finding["remediation_steps"])
    change_plan = next(
        plan for plan in data["change_plans"] if plan["finding_code"] == "dkim_selector_missing"
    )
    assert change_plan["operation"] == "create"
    assert change_plan["record_type"] == "TXT"
    assert change_plan["requires_approval"] is True
    assert change_plan["applies_automatically"] is False
    assert change_plan["provider_write_available"] is False
    assert change_plan["provider_value_required"] is True
    assert change_plan["manual_steps"]


def test_dns_lint_endpoint_uses_configured_mail_auth_defaults(
    authed_client: TestClient,
    db_session,
):
    db_session.add_all(
        [
            Setting(
                key="dmarc.report_mailbox",
                value="dmarc-reports@cklnet.com",
                description="Central DMARC report mailbox",
                value_type="string",
                category="dmarc",
            ),
            Setting(
                key="dmarc.tls_report_mailbox",
                value="tls-reports@cklnet.com",
                description="Central TLS report mailbox",
                value_type="string",
                category="dmarc",
            ),
            Setting(
                key="dmarc.default_policy",
                value="quarantine",
                description="Default DMARC policy",
                value_type="string",
                category="dmarc",
            ),
            Setting(
                key="dmarc.default_percentage",
                value="25",
                description="Default DMARC percentage",
                value_type="integer",
                category="dmarc",
            ),
        ]
    )
    db_session.commit()
    result = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
        nameservers=["ns1.digitalocean.com", "ns2.digitalocean.com"],
        dns_provider=detect_dns_provider(["ns1.digitalocean.com", "ns2.digitalocean.com"]),
    )

    with (
        _mock_dns(result),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(MTAStsResult(status="pass"), False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(BIMIResult(status="pass"), False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/lint")

    assert response.status_code == 200
    targets = {record["code"]: record for record in response.json()["target_records"]}
    assert targets["target_dmarc"]["value"] == (
        "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@cklnet.com; " "pct=25; adkim=r; aspf=r"
    )
    assert targets["target_tls_rpt"]["value"] == "v=TLSRPTv1; rua=mailto:tls-reports@cklnet.com"


def test_dns_lint_endpoint_prefers_domain_dmarc_mailbox_override(
    authed_client: TestClient,
    db_session,
):
    db_session.add_all(
        [
            Setting(
                key="dmarc.report_mailbox",
                value="dmarc-reports@central.example",
                description="Central DMARC report mailbox",
                value_type="string",
                category="dmarc",
            ),
            Domain(
                name=DOMAIN,
                active=True,
                dmarc_report_mailbox="dmarc-example@tenant.example",
            ),
        ]
    )
    db_session.commit()
    result = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
    )

    with (
        _mock_dns(result),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(MTAStsResult(status="pass"), False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(BIMIResult(status="pass"), False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/lint")

    assert response.status_code == 200
    targets = {record["code"]: record for record in response.json()["target_records"]}
    assert targets["target_dmarc"]["value"] == (
        "v=DMARC1; p=none; rua=mailto:dmarc-example@tenant.example; " "pct=100; adkim=r; aspf=r"
    )


def test_update_domain_persists_dmarc_report_mailbox_override(authed_client: TestClient):
    create_response = authed_client.post("/api/v1/domains/domains", json={"name": DOMAIN})
    assert create_response.status_code == 201

    response = authed_client.patch(
        f"/api/v1/domains/domains/{DOMAIN}",
        json={"dmarc_report_mailbox": "mailto:dmarc-example@tenant.example"},
    )

    assert response.status_code == 200
    assert response.json()["dmarc_report_mailbox"] == "dmarc-example@tenant.example"

    read_response = authed_client.get(f"/api/v1/domains/domains/{DOMAIN}")
    assert read_response.status_code == 200
    assert read_response.json()["dmarc_report_mailbox"] == "dmarc-example@tenant.example"

    response = authed_client.patch(
        f"/api/v1/domains/domains/{DOMAIN}",
        json={"dmarc_report_mailbox": ""},
    )
    assert response.status_code == 200
    assert response.json()["dmarc_report_mailbox"] is None

    response = authed_client.patch(
        f"/api/v1/domains/domains/{DOMAIN}",
        json={"dmarc_report_mailbox": "dmarc-example@tenant.example"},
    )
    assert response.status_code == 200

    response = authed_client.patch(
        f"/api/v1/domains/domains/{DOMAIN}",
        json={"dmarc_report_mailbox": None},
    )
    assert response.status_code == 200
    assert response.json()["dmarc_report_mailbox"] is None


def test_update_domain_rejects_invalid_dmarc_report_mailbox(authed_client: TestClient):
    create_response = authed_client.post("/api/v1/domains/domains", json={"name": DOMAIN})
    assert create_response.status_code == 201

    for mailbox in ("not a mailbox", "dmarc@example.com; pct=0", "a@example.com,b@example.com"):
        response = authed_client.patch(
            f"/api/v1/domains/domains/{DOMAIN}",
            json={"dmarc_report_mailbox": mailbox},
        )

        assert response.status_code == 422


def test_int_setting_value_preserves_zero_and_falls_back(db_session):
    db_session.add_all(
        [
            Setting(
                key="dmarc.default_percentage_zero",
                value="0",
                description="Zero percentage",
                value_type="integer",
                category="dmarc",
            ),
            Setting(
                key="dmarc.default_percentage_invalid",
                value="not-an-int",
                description="Invalid percentage",
                value_type="integer",
                category="dmarc",
            ),
        ]
    )
    db_session.commit()

    assert (
        domains_endpoint._int_setting_value(
            db_session,
            "dmarc.default_percentage_zero",
            100,
        )
        == 0
    )
    assert (
        domains_endpoint._int_setting_value(
            db_session,
            "dmarc.default_percentage_invalid",
            100,
        )
        == 100
    )
    assert (
        domains_endpoint._int_setting_value(
            db_session,
            "dmarc.default_percentage_missing",
            100,
        )
        == 100
    )


def test_dns_lint_endpoint_accepts_locale_for_operator_guidance(authed_client: TestClient):
    result = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
        nameservers=["ns1.digitalocean.com", "ns2.digitalocean.com"],
        dns_provider=detect_dns_provider(["ns1.digitalocean.com", "ns2.digitalocean.com"]),
    )
    mta_sts = MTAStsResult(status="pass")
    bimi = BIMIResult(status="pass")

    with (
        _mock_dns(result),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/lint?locale=de")

    assert response.status_code == 200
    findings = {finding["code"]: finding for finding in response.json()["findings"]}
    assert "Oeffne die DNS-Zone" in findings["dmarc_missing"]["remediation_steps"][0]
    assert "Veroeffentliche genau einen TXT-Record" in (
        findings["spf_missing"]["remediation_steps"][1]
    )


def test_dns_change_plan_endpoint_returns_apply_gated_plans(authed_client: TestClient):
    result = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
        nameservers=["ns1.example.net"],
        dns_provider=detect_dns_provider(["ns1.example.net"]),
    )
    mta_sts = MTAStsResult(errors=["No _mta-sts TXT record was found."])
    bimi = BIMIResult(errors=["No BIMI TXT record was found at the selector."])

    with (
        _mock_dns(result),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/change-plan")

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == DOMAIN
    assert data["read_only"] is False
    assert data["provider_write_available"] is True
    assert data["dns_provider"]["provider_id"] == "custom"
    assert data["apply_endpoint"].endswith("/dns/change-plan/apply")
    plan = next(plan for plan in data["plans"] if plan["finding_code"] == "dmarc_missing")
    assert plan["operation"] == "create"
    assert plan["proposed_value"].startswith("v=DMARC1")
    assert plan["rollback"]
    assert plan["expected_health_impact"]


def test_dns_change_plan_endpoint_includes_postmark_records(authed_client: TestClient):
    result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
        nameservers=["ns1.example.net"],
        dns_provider=detect_dns_provider(["ns1.example.net"]),
    )
    mta_sts = MTAStsResult(status="pass")
    bimi = BIMIResult(status="pass")

    with (
        _mock_dns(result),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.mail_service_dns_records_for_domain",
            new=AsyncMock(
                return_value=[
                    {
                        "provider": "postmark",
                        "provider_name": "Postmark",
                        "record_type": "CNAME",
                        "name": "pm-bounces.example.com",
                        "value": "pm.mtasv.net",
                        "purpose": "return_path",
                    }
                ]
            ),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/change-plan")

    assert response.status_code == 200
    plan = next(
        plan
        for plan in response.json()["plans"]
        if plan["finding_code"] == "mail_service_record_missing"
    )
    assert plan["operation"] == "create"
    assert plan["record_type"] == "CNAME"
    assert plan["name"] == "pm-bounces.example.com"
    assert plan["proposed_value"] == "pm.mtasv.net"
    assert plan["provider_write_available"] is True


def test_dns_lint_endpoint_flags_advanced_spf_lookup_findings(
    authed_client: TestClient,
):
    spf_record = (
        "v=spf1 "
        "include:_spf.one.example include:_spf.one.example "
        "include:_spf.two.example include:_spf.three.example "
        "include:_spf.four.example include:_spf.five.example "
        "include:_spf.six.example include:_spf.seven.example "
        "include:_spf.eight.example include:_spf.nine.example "
        "include:_spf.ten.example include:missing.example -all"
    )
    result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record=spf_record,
        dkim=True,
        dkim_selectors=["selector1"],
    )
    provider = AsyncMock()
    provider.check_domain = AsyncMock(return_value=result)

    async def _lookup_txt(name):
        if name == DOMAIN:
            return [spf_record]
        if name == "_smtp._tls.example.com":
            return ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"]
        if name == "missing.example":
            raise LookupError("missing SPF include")
        return ["v=spf1 -all"]

    provider.lookup_txt = AsyncMock(side_effect=_lookup_txt)

    with (
        patch(
            "app.api.api_v1.endpoints.domains.get_default_provider",
            return_value=provider,
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(MTAStsResult(status="pass"), False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(BIMIResult(status="pass"), False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/lint")

    assert response.status_code == 200
    data = response.json()
    findings = {finding["code"]: finding for finding in data["findings"]}
    assert data["status"] == "critical"
    assert "spf_dns_lookup_limit_exceeded" in findings
    assert "spf_duplicate_include" in findings
    assert "spf_void_lookup" in findings
    assert "_spf.one.example" in findings["spf_duplicate_include"]["evidence"]
    assert "include:missing.example" in findings["spf_void_lookup"]["evidence"]


def test_dns_lint_bulk_and_export(authed_client: TestClient):
    mta_sts = MTAStsResult(status="pass")
    bimi = BIMIResult(status="pass")

    with (
        _mock_dns(),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = authed_client.get("/api/v1/domains/dns/lint")
        export = authed_client.get("/api/v1/domains/dns/lint/export")

    assert response.status_code == 200
    data = response.json()
    assert data["domains"][0]["domain"] == DOMAIN
    assert data["domains"][0]["finding_count"] >= 1
    assert export.status_code == 200
    assert "domain,status,severity,code" in export.text
    assert DOMAIN in export.text


def test_dns_endpoint_uses_cached_result(authed_client: TestClient, db_session):
    """Repeated DNS checks reuse a fresh cached result."""
    mock_provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=mock_provider,
    ):
        first = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")
        second = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")

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
async def test_dns_cache_preserves_provider_detection(db_session):
    """Cached DNS results should keep nameserver and provider detection evidence."""
    result_with_provider = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=False,
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )
    mock_provider = AsyncMock(check_domain=AsyncMock(return_value=result_with_provider))

    first, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        mock_provider,
        DOMAIN,
        selectors=[],
    )
    second, cached_again, _checked_again = await resolve_domain_dns_cached(
        db_session,
        mock_provider,
        DOMAIN,
        selectors=[],
    )

    assert cached is False
    assert first.dns_provider is not None
    assert cached_again is True
    assert second.nameservers == ["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]
    assert second.dns_provider is not None
    assert second.dns_provider.provider_id == "cloudflare"


@pytest.mark.asyncio
async def test_dns_cache_uses_public_fallback_for_configured_resolver(db_session, monkeypatch):
    """Configured resolver misses should not hide positive public DNS evidence."""

    class EmptyConfiguredProvider(ConfiguredRecursiveDNSProvider):
        async def check_domain(self, domain, selectors=None):  # pylint: disable=unused-argument
            return DomainDNSResult(dmarc=False, spf=False, dkim=False)

    async def positive_public_result(
        self,
        domain,
        selectors=None,
    ):  # pylint: disable=unused-argument
        return DomainDNSResult(
            dmarc=True,
            dmarc_record="v=DMARC1; p=reject",
            spf=True,
            spf_record="v=spf1 -all",
            nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
            dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
        )

    primary = EmptyConfiguredProvider()
    monkeypatch.setattr(
        PublicRecursiveDNSProvider,
        "check_domain",
        positive_public_result,
    )
    monkeypatch.setattr(
        CloudflareDNSProvider,
        "check_domain",
        AsyncMock(return_value=DomainDNSResult(dmarc=False, spf=False, dkim=False)),
    )

    result, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        primary,
        DOMAIN,
        selectors=[],
        refresh=True,
    )

    assert cached is False
    assert result.lookup_status == "fallback"
    assert result.lookup_error == (
        "No DNS evidence from EmptyConfiguredProvider; using PublicRecursiveDNSProvider."
    )
    assert result.dmarc is True
    assert result.spf is True
    assert result.dns_provider is not None
    assert result.dns_provider.provider_id == "cloudflare"


@pytest.mark.asyncio
async def test_dns_cache_refreshes_stale_empty_dns_result(db_session):
    """Resolver failures with no DNS evidence should not poison posture for the full TTL."""
    stale_empty = DomainDNSResult(dmarc=False, spf=False, dkim=False)
    healthy = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )
    provider = AsyncMock(check_domain=AsyncMock(return_value=healthy))
    db_session.add(
        DNSCache(
            domain=DOMAIN,
            provider=provider.__class__.__name__,
            selectors_key=_selectors_key([]),
            result_json=json.dumps(asdict(stale_empty), sort_keys=True, separators=(",", ":")),
            checked_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=120),
        )
    )
    db_session.commit()

    result, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        provider,
        DOMAIN,
        selectors=[],
    )

    assert cached is False
    assert result.dmarc is True
    assert result.spf is True
    assert result.dns_provider is not None
    assert provider.check_domain.await_count == 1


@pytest.mark.asyncio
async def test_dns_cache_keeps_recent_positive_evidence_when_lookup_turns_empty(db_session):
    """Transient resolver misses should not overwrite known-good DNS posture."""
    healthy = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )
    empty = DomainDNSResult(dmarc=False, spf=False, dkim=False)
    provider = AsyncMock(check_domain=AsyncMock(return_value=empty))
    db_session.add(
        DNSCache(
            domain=DOMAIN,
            provider=provider.__class__.__name__,
            selectors_key=_selectors_key([]),
            result_json=json.dumps(asdict(healthy), sort_keys=True, separators=(",", ":")),
            checked_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=30),
        )
    )
    db_session.commit()

    result, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        provider,
        DOMAIN,
        selectors=[],
    )

    assert cached is True
    assert result.dmarc is True
    assert result.spf is True
    assert result.nameservers == ["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]
    assert provider.check_domain.await_count == 1


@pytest.mark.asyncio
async def test_dns_cache_uses_positive_evidence_from_previous_selector_set(db_session):
    """Selector changes should not let a transient empty lookup hide known DNS records."""
    healthy = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )
    empty = DomainDNSResult(dmarc=False, spf=False, dkim=False)
    provider = AsyncMock(check_domain=AsyncMock(return_value=empty))
    db_session.add(
        DNSCache(
            domain=DOMAIN,
            provider=provider.__class__.__name__,
            selectors_key=_selectors_key(["pm20250806"]),
            result_json=json.dumps(asdict(healthy), sort_keys=True, separators=(",", ":")),
            checked_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=30),
        )
    )
    db_session.add(
        DNSCache(
            domain=DOMAIN,
            provider=provider.__class__.__name__,
            selectors_key=_selectors_key(["pm20250806", "ab20250324"]),
            result_json=json.dumps(asdict(empty), sort_keys=True, separators=(",", ":")),
            checked_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=30),
        )
    )
    db_session.commit()

    result, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        provider,
        DOMAIN,
        selectors=["pm20250806", "ab20250324"],
        refresh=True,
    )

    assert cached is True
    assert result.lookup_status == "stale_cache"
    assert result.dmarc is True
    assert result.spf is True
    assert result.nameservers == ["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]
    assert provider.check_domain.await_count == 1


@pytest.mark.asyncio
async def test_dns_cache_uses_stale_positive_evidence_when_lookup_raises(db_session):
    """Transient resolver exceptions should keep known-good evidence with an explicit label."""
    healthy = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )
    provider = AsyncMock()
    provider.check_domain = AsyncMock(side_effect=TimeoutError("resolver timed out"))
    db_session.add(
        DNSCache(
            domain=DOMAIN,
            provider=provider.__class__.__name__,
            selectors_key=_selectors_key([]),
            result_json=json.dumps(asdict(healthy), sort_keys=True, separators=(",", ":")),
            checked_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=30),
        )
    )
    db_session.commit()

    result, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        provider,
        DOMAIN,
        selectors=[],
    )

    assert cached is True
    assert result.lookup_status == "stale_cache"
    assert "TimeoutError" in (result.lookup_error or "")
    assert result.dmarc is True
    assert result.spf is True
    assert result.nameservers == ["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]
    assert provider.check_domain.await_count == 1


@pytest.mark.asyncio
async def test_dns_cache_allows_old_positive_evidence_to_expire(db_session):
    """Very old DNS evidence should not mask a persistently empty resolver result."""
    healthy = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )
    empty = DomainDNSResult(dmarc=False, spf=False, dkim=False)
    provider = AsyncMock(check_domain=AsyncMock(return_value=empty))
    db_session.add(
        DNSCache(
            domain=DOMAIN,
            provider=provider.__class__.__name__,
            selectors_key=_selectors_key([]),
            result_json=json.dumps(asdict(healthy), sort_keys=True, separators=(",", ":")),
            checked_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2),
        )
    )
    db_session.commit()

    result, cached, _checked = await resolve_domain_dns_cached(
        db_session,
        provider,
        DOMAIN,
        selectors=[],
    )

    assert cached is False
    assert result.dmarc is False
    assert result.spf is False
    assert provider.check_domain.await_count == 1


@pytest.mark.asyncio
async def test_dns_cache_uses_public_fallback_for_empty_primary_result(db_session):
    """A primary resolver with no evidence should not force a false F grade."""
    primary_provider = PublicRecursiveDNSProvider()
    primary_check = AsyncMock(return_value=DomainDNSResult(dmarc=False, spf=False, dkim=False))
    fallback_result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )

    with (
        patch.object(primary_provider, "check_domain", new=primary_check),
        patch(
            "app.services.dns_cache.CloudflareDNSProvider.check_domain",
            new=AsyncMock(return_value=fallback_result),
        ) as cloudflare_fallback,
    ):
        result, cached, _checked = await resolve_domain_dns_cached(
            db_session,
            primary_provider,
            DOMAIN,
            selectors=[],
        )

    assert cached is False
    assert result.dmarc is True
    assert result.spf is True
    assert result.dns_provider is not None
    assert result.lookup_status == "fallback"
    assert "CloudflareDNSProvider" in (result.lookup_error or "")
    primary_check.assert_awaited_once()
    cloudflare_fallback.assert_awaited_once()


@pytest.mark.asyncio
async def test_dns_cache_replaces_system_provider_with_public_resolver(db_session):
    """Host/Kubernetes DNS must not be used for domain evidence lookups."""
    system_provider = SystemDNSProvider()
    system_check = AsyncMock(
        return_value=DomainDNSResult(
            dmarc=False,
            spf=False,
            dkim=False,
            lookup_status="lookup_failed",
            lookup_error="local resolver timeout",
        )
    )
    public_result = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject",
        spf=True,
        spf_record="v=spf1 -all",
        nameservers=["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"],
        dns_provider=detect_dns_provider(["ada.ns.cloudflare.com", "ian.ns.cloudflare.com"]),
    )

    with (
        patch.object(system_provider, "check_domain", new=system_check),
        patch(
            "app.services.dns_cache.PublicRecursiveDNSProvider.check_domain",
            new=AsyncMock(return_value=public_result),
        ) as public_check,
    ):
        result, cached, _checked = await resolve_domain_dns_cached(
            db_session,
            system_provider,
            DOMAIN,
            selectors=[],
        )

    assert cached is False
    assert result.dmarc is True
    assert result.spf is True
    cache_row = db_session.query(DNSCache).one()
    assert cache_row.provider == "PublicRecursiveDNSProvider"
    system_check.assert_not_awaited()
    public_check.assert_awaited_once()


@pytest.mark.asyncio
async def test_dns_cache_propagates_fallback_cancellation(db_session):
    """Request cancellation must not be swallowed by defensive fallback handling."""
    primary_provider = PublicRecursiveDNSProvider()
    primary_check = AsyncMock(return_value=DomainDNSResult(dmarc=False, spf=False, dkim=False))
    fallback_check = AsyncMock(side_effect=asyncio.CancelledError())

    with (
        patch.object(primary_provider, "check_domain", new=primary_check),
        patch(
            "app.services.dns_cache.CloudflareDNSProvider.check_domain",
            new=fallback_check,
        ),
        pytest.raises(asyncio.CancelledError),
    ):
        await resolve_domain_dns_cached(
            db_session,
            primary_provider,
            DOMAIN,
            selectors=[],
        )

    primary_check.assert_awaited_once()
    fallback_check.assert_awaited_once()


@pytest.mark.asyncio
async def test_dns_cache_fallback_failure_log_omits_user_values(db_session, caplog):
    """Fallback failure logging should not echo domains or exception messages."""
    domain = "bad.example\nforged-log-line"
    primary_provider = PublicRecursiveDNSProvider()
    primary_check = AsyncMock(return_value=DomainDNSResult(dmarc=False, spf=False, dkim=False))
    fallback_check = AsyncMock(side_effect=RuntimeError(f"resolver failed for {domain}"))
    caplog.set_level(logging.DEBUG, logger="app.services.dns_cache")

    with (
        patch.object(primary_provider, "check_domain", new=primary_check),
        patch(
            "app.services.dns_cache.CloudflareDNSProvider.check_domain",
            new=fallback_check,
        ),
    ):
        result, cached, _checked = await resolve_domain_dns_cached(
            db_session,
            primary_provider,
            domain,
            selectors=[],
        )

    assert cached is False
    assert result.dmarc is False
    assert result.lookup_status == "partial"
    assert "RuntimeError" in caplog.text
    assert domain not in caplog.text
    assert f"resolver failed for {domain}" not in caplog.text
    primary_check.assert_awaited_once()
    fallback_check.assert_awaited_once()


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


def test_dns_endpoint_refresh_bypasses_cache(authed_client: TestClient):
    """The refresh query parameter forces a new DNS lookup."""
    mock_provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=mock_provider,
    ):
        authed_client.get(f"/api/v1/domains/{DOMAIN}/dns")
        refreshed = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns?refresh=true")

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


def test_dns_endpoint_404_for_unknown_domain(authed_client: TestClient):
    with _mock_dns():
        response = authed_client.get("/api/v1/domains/unknown.example.com/dns")
    assert response.status_code == 404


def test_dns_endpoint_supports_manually_configured_domain(authed_client: TestClient, db_session):
    """A domain created before reports arrive can still run DNS checks."""
    db_session.add(Domain(name="manual.example", active=True))
    db_session.commit()

    with _mock_dns():
        response = authed_client.get("/api/v1/domains/manual.example/dns")

    assert response.status_code == 200
    assert response.json()["dmarc"] is True


def test_dns_health_404_for_unknown_domain(authed_client: TestClient):
    with _mock_dns():
        response = authed_client.get("/api/v1/domains/unknown.example.com/dns/health")
    assert response.status_code == 404


def test_dns_health_links_checks_to_evidence(authed_client: TestClient):
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
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/health")

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


def test_dns_health_recommends_enforcement_when_evidence_supports_it(authed_client: TestClient):
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
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/health")

    assert response.status_code == 200
    recommendations = response.json()["recommendations"]
    readiness = next(item for item in recommendations if item["type"] == "policy_enforcement_ready")
    assert "low pct" in readiness["action"]
    assert any(item["label"] == "Compliance" for item in readiness["evidence"])


def test_dns_health_marks_all_missing_records_critical(authed_client: TestClient):
    """Missing DMARC, SPF, and DKIM produce specific repair recommendations."""
    missing_all = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["google"],
    )

    with _mock_dns(result=missing_all):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "critical"
    recommendation_types = [item["type"] for item in data["recommendations"]]
    assert {"missing_dmarc", "missing_spf", "missing_dkim"}.issubset(set(recommendation_types))
    assert recommendation_types.count("missing_mta_sts") == 1
    assert recommendation_types.count("missing_bimi") == 1
    assert any(item["type"] == "policy_needs_more_data" for item in data["recommendations"])


def test_mta_sts_endpoint_returns_cached_posture(authed_client: TestClient):
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
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/mta-sts")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "fail"
    assert data["cached"] is True
    assert data["checked_at"] == checked_at.isoformat()
    assert data["errors"] == ["No _mta-sts TXT record was found."]


def test_mta_sts_endpoint_returns_404_for_unknown_domain(authed_client: TestClient):
    response = authed_client.get("/api/v1/domains/unknown.example.com/dns/mta-sts")

    assert response.status_code == 404


def test_bimi_endpoint_returns_cached_posture(authed_client: TestClient):
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
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/bimi")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pass"
    assert data["query_name"] == f"default._bimi.{DOMAIN}"
    assert data["logo_url"] == "https://example.com/logo.svg"
    assert data["cached"] is True
    assert data["checked_at"] == checked_at.isoformat()


def test_bimi_endpoint_returns_404_for_unknown_domain(authed_client: TestClient):
    response = authed_client.get("/api/v1/domains/unknown.example.com/dns/bimi")

    assert response.status_code == 404


def test_dane_endpoint_returns_cached_posture(authed_client: TestClient):
    """The domain detail page can fetch DANE/TLSA posture with cache metadata."""
    checked_at = datetime(2026, 5, 23, 12, 0, 0)
    passive_result = DANEResult(
        status="pass",
        port=25,
        mx_hosts=["mx.example.com"],
        records=[
            TLSARecord(
                query_name="_25._tcp.mx.example.com",
                mx_host="mx.example.com",
                record=(
                    "3 1 1 " "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                ),
                certificate_usage=3,
                selector=1,
                matching_type=1,
                association_data=(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                ),
                valid=True,
            )
        ],
    )
    live_result = DANEResult(
        **{
            **passive_result.__dict__,
            "suggested_records": [
                TLSASuggestion(
                    query_name="_25._tcp.mx.example.com",
                    mx_host="mx.example.com",
                    record=(
                        "3 1 1 " "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    ),
                    association_data=(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    ),
                    status="ready",
                )
            ],
        }
    )
    calls = []

    async def fake_check(db, provider, domain, *, port=25, refresh=False, derive_suggestions=False):
        calls.append(
            {
                "domain": domain,
                "port": port,
                "refresh": refresh,
                "derive_suggestions": derive_suggestions,
            }
        )
        return (live_result if derive_suggestions else passive_result), True, checked_at

    with patch(
        "app.api.api_v1.endpoints.domains.check_dane_cached",
        new=fake_check,
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/dane")
        live_response = authed_client.get(
            f"/api/v1/domains/{DOMAIN}/dns/dane?derive_suggestions=true"
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pass"
    assert data["mx_hosts"] == ["mx.example.com"]
    assert data["records"][0]["query_name"] == "_25._tcp.mx.example.com"
    assert data["records"][0]["certificate_usage"] == 3
    assert data["records"][0]["valid"] is True
    assert data["suggested_records"] == []
    assert data["cached"] is True
    assert data["checked_at"] == checked_at.isoformat()
    assert live_response.status_code == 200
    live_data = live_response.json()
    assert live_data["suggested_records"][0]["record"].startswith("3 1 1 ")
    assert live_data["suggested_records"][0]["status"] == "ready"
    assert calls == [
        {"domain": DOMAIN, "port": 25, "refresh": False, "derive_suggestions": False},
        {"domain": DOMAIN, "port": 25, "refresh": False, "derive_suggestions": True},
    ]


def test_dane_endpoint_returns_404_for_unknown_domain(authed_client: TestClient):
    response = authed_client.get("/api/v1/domains/unknown.example.com/dns/dane")

    assert response.status_code == 404


def test_posture_dashboard_links_recommendations_changes_and_playbooks(
    authed_client: TestClient, db_session
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
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/posture")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert data["score"] == 75
    assert data["health"]["domain"] == DOMAIN
    assert data["health"]["grade"] in {"A+", "A", "A-", "B+", "B", "B-", "C", "D", "F"}
    assert isinstance(data["health"]["score"], int)
    assert any(item["key"] == "spf" and item["href"] == "#dns-records" for item in data["coverage"])
    missing_spf_recommendation = next(
        item for item in data["recommendations"] if item["type"] == "missing_spf"
    )
    assert missing_spf_recommendation["evidence"][0]["href"] == "#dns-records"
    assert data["changes"][0]["title"] == f"TXT _dmarc.{DOMAIN} modified"
    assert data["changes"][0]["evidence"][0]["value"] == "v=DMARC1; p=none"
    assert any(playbook["key"] == "missing_spf" for playbook in data["playbooks"])


def test_posture_dashboard_distinguishes_mta_sts_policy_hosting_failure(
    authed_client: TestClient,
):
    """A published _mta-sts TXT with an unreachable policy needs hosting guidance."""
    mta_sts = MTAStsResult(
        status="fail",
        dns_record="v=STSv1; id=20260523",
        policy_url=f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt",
        errors=[
            f"MTA-STS policy host mta-sts.{DOMAIN} could not be resolved. "
            f"Publish DNS for mta-sts.{DOMAIN} and serve "
            f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt over HTTPS."
        ],
    )
    bimi = BIMIResult(status="pass", dns_record=f"v=BIMI1; l=https://{DOMAIN}/logo.svg; a=")

    with (
        _mock_dns(),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/posture")

    assert response.status_code == 200
    data = response.json()
    recommendation = next(
        item for item in data["recommendations"] if item["type"] == "mta_sts_policy_unreachable"
    )
    assert recommendation["title"] == "Host the MTA-STS policy"
    assert "existing _mta-sts TXT record" in recommendation["action"]
    assert f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt" in recommendation["action"]
    assert "Rotate the TXT id" in recommendation["action"]
    assert any(playbook["key"] == "mta_sts_policy_unreachable" for playbook in data["playbooks"])
    assert all(item["type"] != "missing_mta_sts" for item in data["recommendations"])
    assert data["score"] == 85
    assert data["health"]["grade"] != "F"


def test_posture_dashboard_weights_optional_controls_below_core_authentication(
    authed_client: TestClient,
):
    """Missing optional posture checks should not collapse a core-authenticated domain."""
    mta_sts = MTAStsResult(errors=["No _mta-sts TXT record was found."])
    bimi = BIMIResult(errors=["No BIMI TXT record was found at the selector."])

    with (
        _mock_dns(result=MOCK_DNS_RESULT),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/posture")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert data["score"] == 85
    assert data["health"]["grade"] != "F"
    recommendation_types = {item["type"] for item in data["recommendations"]}
    assert {"missing_mta_sts", "missing_bimi"}.issubset(recommendation_types)


def test_posture_dashboard_refreshes_health_grade_dns(
    authed_client: TestClient,
):
    """refresh=true must refresh both posture checks and the domain health grade."""
    checked_at = datetime(2026, 5, 23, 12, 0, 0)
    resolver = AsyncMock(return_value=(MOCK_DNS_RESULT, False, checked_at))
    mta_sts = MTAStsResult(status="missing")
    bimi = BIMIResult(status="missing")

    with (
        patch(
            "app.api.api_v1.endpoints.domains.resolve_domain_dns_cached",
            new=resolver,
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_mta_sts_cached",
            new=AsyncMock(return_value=(mta_sts, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.check_bimi_cached",
            new=AsyncMock(return_value=(bimi, False, None)),
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/posture?refresh=true")

    assert response.status_code == 200
    assert response.json()["health"]["domain"] == DOMAIN
    assert resolver.await_count == 2
    assert all(call.kwargs["refresh"] is True for call in resolver.await_args_list)


def test_posture_dashboard_returns_404_for_unknown_domain(authed_client: TestClient):
    response = authed_client.get("/api/v1/domains/unknown.example.com/posture")

    assert response.status_code == 404


def test_domain_detail_data_endpoints_support_manually_configured_domain(
    authed_client: TestClient, db_session
):
    """Manually monitored domains should render empty detail data instead of 404s."""
    db_session.add(Domain(name="manual.example", active=True))
    db_session.commit()

    reports = authed_client.get("/api/v1/domains/manual.example/reports")
    sources = authed_client.get("/api/v1/domains/manual.example/sources")
    selectors = authed_client.get("/api/v1/domains/manual.example/selectors")

    assert reports.status_code == 200
    assert reports.json()["reports"] == []
    assert sources.status_code == 200
    assert sources.json()["sources"] == []
    assert selectors.status_code == 200
    assert selectors.json() == {"selectors": [], "report_selectors": []}


def test_create_domain_respects_monitored_domain_plan_limit(
    authed_client: TestClient,
    db_session,
):
    organization = Organization(slug="default", name="Default Organization", active=True)
    workspace = Workspace(
        slug="default",
        name="Default Workspace",
        organization=organization,
        active=True,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Domain(name="first.example", workspace=workspace, active=True),
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="1",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    second = authed_client.post("/api/v1/domains/domains", json={"name": "second.example"})

    assert second.status_code == 402
    detail = second.json()["detail"]
    assert detail["code"] == "plan_limit_exceeded"
    assert detail["metric"] == "monitored_domains"
    assert detail["current"] == 1
    assert detail["limit"] == 1
    assert detail["attempted"] == 1
    assert detail["can_export"] is True


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


def test_summary_includes_dns_fields(authed_client: TestClient, db_session):
    """The summary endpoint should include dmarc_status, spf_status, dkim_status."""
    _persist_minimal_report(db_session)

    with _mock_dns():
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

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


def test_summary_includes_remediation_activity(authed_client: TestClient, db_session):
    """Dashboard summaries include remediation-loop audit state without rebuilding queues."""
    _persist_minimal_report(db_session)
    workspace = get_or_create_default_workspace(db_session)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db_session.add_all(
        [
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_dispatch_enqueued",
                entity_type="remediation_notification",
                entity_id="dns:dmarc-missing",
                entity_name=f" {DOMAIN.upper()}. ",
                details=json.dumps(
                    {
                        "delivery_enqueued": True,
                        "delivery_count": 1,
                        "dns_write_attempted": False,
                        "sent": False,
                    }
                ),
                created_at=now,
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:dmarc-missing",
                entity_name=f" {DOMAIN.upper()}. ",
                details=json.dumps({"lifecycle_state": "resolved"}),
                created_at=now + timedelta(seconds=1),
            ),
            WorkspaceAuditLog(
                workspace_id=workspace.id,
                actor_type="operator",
                action="remediation.notification_lifecycle_recorded",
                entity_type="remediation_notification",
                entity_id="dns:quiet-domain",
                entity_name=" Quiet.Example. ",
                details=json.dumps({"lifecycle_state": "acknowledged"}),
                created_at=now - timedelta(days=1),
            ),
        ]
    )
    db_session.commit()

    with _mock_dns():
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

    assert response.status_code == 200
    data = response.json()
    domain = data["domains"][0]
    assert domain["remediation"]["status"] == "resolved"
    assert domain["remediation"]["latest_state"] == "resolved"
    assert domain["remediation"]["latest_at"].endswith("Z")
    assert domain["remediation"]["resolved"] == 1
    assert domain["remediation"]["dispatch_enqueued"] == 1
    assert data["health_summary"]["remediation"]["domains_with_activity"] == 1
    assert data["health_summary"]["remediation"]["resolved"] == 1
    assert data["health_summary"]["remediation"]["delivery_count"] == 1
    assert data["health_summary"]["remediation_loop"]["fixed"] == 1

    activity = summarize_remediation_activity(
        db_session,
        workspace=workspace,
        domains=[DOMAIN, "quiet.example"],
        row_limit=1,
    )
    assert activity["domains"]["quiet.example"]["latest_state"] == "acknowledged"


def test_summary_includes_current_remediation_loop(
    authed_client: TestClient,
    db_session,
):
    """Dashboard summaries expose current operator work, not only historic audit rows."""
    _persist_minimal_report(db_session)
    degraded_dns = DomainDNSResult(
        dmarc=False,
        dmarc_record=None,
        spf=False,
        spf_record=None,
        dkim=True,
        dkim_selectors=["google"],
        dkim_record="v=DKIM1; k=rsa; p=ABC",
    )

    with _mock_dns(degraded_dns):
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

    assert response.status_code == 200
    loop = response.json()["health_summary"]["remediation_loop"]
    assert loop["status"] == "needs_attention"
    assert loop["needs_approval"] >= 2
    assert loop["total_open"] >= 2
    assert loop["items"][0]["domain"] == DOMAIN
    assert loop["items"][0]["state"] == "needs_approval"
    assert loop["items"][0]["title"]
    assert loop["items"][0]["next_step"]
    domain = response.json()["domains"][0]
    assert domain["remediation_workload"]["status"] == "needs_attention"
    assert domain["remediation_workload"]["needs_approval"] >= 2
    assert domain["remediation_workload"]["total_open"] >= 2
    assert domain["remediation_workload"]["primary"]["state"] == "needs_approval"
    assert domain["remediation_workload"]["primary"]["title"]


@pytest.mark.parametrize(
    "action_type",
    ["source_reputation_listed", "source_reputation_review"],
)
def test_remediation_loop_classifies_reputation_actions_as_investigate(action_type: str):
    """Reputation health actions should remain investigation work, not manual tasks."""
    assert _remediation_loop_state({"type": action_type, "severity": "high"}) == "investigate"


def test_summary_dns_failure_defaults_false(authed_client: TestClient, db_session):
    """Empty DNS results stay false without being labeled resolver failures."""
    _persist_minimal_report(db_session)
    empty_result = DomainDNSResult()

    with _mock_dns(result=empty_result):
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

    assert response.status_code == 200
    domain = response.json()["domains"][0]
    assert domain["dmarc_status"] is False
    assert domain["spf_status"] is False
    assert domain["dkim_status"] is False
    assert domain["dns_lookup_status"] == "ok"
    assert domain["dns_lookup_failed"] is False


def test_summary_refresh_dns_exception_marks_lookup_failed(authed_client: TestClient, db_session):
    """Resolver failures should not become misleading missing-DNS recommendations."""
    _persist_minimal_report(db_session)

    with patch(
        "app.api.api_v1.endpoints.domains.resolve_domain_dns_cached",
        new=AsyncMock(side_effect=LookupError("resolver unavailable")),
    ):
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

    assert response.status_code == 200
    domain = response.json()["domains"][0]
    assert domain["dmarc_status"] is False
    assert domain["spf_status"] is False
    assert domain["dkim_status"] is False
    assert domain["dns_pending"] is False
    assert domain["dns_lookup_status"] == "failed"
    assert domain["dns_lookup_failed"] is True
    assert "resolver unavailable" in domain["dns_lookup_error"]
    assert domain["dmarc_policy_source"] == "report"
    assert domain["dns_evidence_source"] == "lookup_failed"
    action_types = [action["type"] for action in domain["health"]["actions"]]
    assert "dns_evidence_unavailable" in action_types
    dns_action = next(
        action
        for action in domain["health"]["actions"]
        if action["type"] == "dns_evidence_unavailable"
    )
    evidence = {item["label"]: item["value"] for item in dns_action["evidence"]}
    assert evidence["dns_evidence"] == "DNS lookup failed"
    assert evidence["policy_source"] == "DMARC report policy"
    assert "missing_dmarc" not in action_types
    assert "missing_spf" not in action_types
    assert "missing_dkim" not in action_types


def test_summary_prefers_report_policy_when_dns_cache_is_stale(
    authed_client: TestClient,
    db_session,
):
    """Stale DNS evidence should not override the policy observed in reports."""
    save_parsed_report(
        db_session,
        {
            **MINIMAL_REPORT,
            "report_id": "stale-dns-policy-fixture",
            "policy": {"p": "reject", "sp": "", "pct": "100"},
        },
    )
    db_session.commit()
    stale_dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 include:_spf.google.com ~all",
        dkim=True,
        dkim_selectors=["google"],
        dkim_record="v=DKIM1; k=rsa; p=ABC",
        lookup_status="stale_cache",
    )

    with _mock_dns(result=stale_dns):
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

    assert response.status_code == 200
    domain = response.json()["domains"][0]
    assert domain["dmarc_policy"] == "reject"
    assert domain["dmarc_policy_source"] == "report"
    assert domain["dns_evidence_source"] == "stale_cache"


def test_summary_dns_evidence_source_uses_any_live_dns_evidence(
    authed_client: TestClient,
    db_session,
):
    """SPF/DKIM evidence should not be reported as an empty DNS lookup."""
    _persist_minimal_report(db_session)
    partial_dns = DomainDNSResult(
        dmarc=False,
        spf=True,
        spf_record="v=spf1 include:_spf.google.com ~all",
        dkim=True,
        dkim_selectors=["google"],
        dkim_record="v=DKIM1; k=rsa; p=ABC",
    )

    with _mock_dns(result=partial_dns):
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

    assert response.status_code == 200
    domain = response.json()["domains"][0]
    assert domain["dmarc_policy_source"] == "report"
    assert domain["dns_evidence_source"] == "live_dns"


@pytest.mark.asyncio
async def test_domain_health_grade_treats_pending_dns_as_unavailable(db_session):
    """Domain detail health should match summary behavior while DNS is pending."""
    _persist_minimal_report(db_session)
    pending_dns = DomainDNSResult(lookup_status="pending")
    pending_dns.pending = True  # type: ignore[attr-defined]
    reputation = DomainReputation(
        domain=DOMAIN,
        status="clean",
        checked_at="2026-07-03T15:00:00Z",
        summary={"total_sources": 0, "highest_risk_score": 0},
    )

    with (
        patch(
            "app.api.api_v1.endpoints.domains.resolve_domain_dns_cached",
            new=AsyncMock(return_value=(pending_dns, False, None)),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.build_source_reputation_cached",
            new=AsyncMock(return_value=(reputation, False, None)),
        ),
    ):
        health = (
            await domains_endpoint._build_domain_health_grade(  # pylint: disable=protected-access
                db_session,
                DOMAIN,
                ReportStore.get_instance(),
            )
        )

    action_types = [action["type"] for action in health["actions"]]
    assert "dns_evidence_pending" in action_types
    assert "missing_dmarc" not in action_types
    assert "missing_spf" not in action_types
    assert "missing_dkim" not in action_types


def test_summary_endpoint_uses_manual_selectors(authed_client: TestClient, db_session):
    """Manually configured selectors are forwarded by the summary endpoint."""
    _persist_minimal_report(db_session)
    authed_client.post(f"/api/v1/domains/{DOMAIN}/selectors", json={"selector": "manualsel"})
    captured_selectors = []

    async def _fake_check_domain(domain, selectors=None):
        captured_selectors.extend(selectors or [])
        return MOCK_DNS_RESULT

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=AsyncMock(check_domain=_fake_check_domain),
    ):
        response = authed_client.get("/api/v1/domains/summary?refresh=true")

    assert response.status_code == 200
    assert "manualsel" in captured_selectors
    assert "google" in captured_selectors


def test_summary_endpoint_uses_database_aggregates_without_hydration(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    """Production summary reads persisted aggregates instead of rebuilding the report store."""
    _persist_minimal_report(db_session)

    def fail_hydration(*args, **kwargs):
        raise AssertionError("summary should not hydrate the full report store")

    provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))
    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fail_hydration)

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=provider,
    ):
        response = authed_client.get("/api/v1/domains/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["total_domains"] == 1
    assert data["total_emails"] == 5
    assert data["reports_processed"] == 1
    assert data["domains"][0]["pass_rate"] == 100.0
    assert data["domains"][0]["dns_pending"] is True
    assert provider.check_domain.await_count == 0


def test_summary_endpoint_refresh_bypasses_dns_cache(authed_client: TestClient, db_session):
    """The summary reload action forces DNS recomputation without report-store hydration."""
    _persist_minimal_report(db_session)
    provider = AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT))

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=provider,
    ):
        first = authed_client.get("/api/v1/domains/summary")
        refreshed = authed_client.get("/api/v1/domains/summary?refresh=true")
        second = authed_client.get("/api/v1/domains/summary")

    assert first.status_code == 200
    assert second.status_code == 200
    assert refreshed.status_code == 200
    assert first.json()["domains"][0]["dns_pending"] is True
    assert provider.check_domain.await_count == 1
    assert second.json()["domains"][0]["dns_cached"] is True
    assert second.json()["domains"][0]["dns_pending"] is False
    assert refreshed.json()["domains"][0]["dns_cached"] is False


def test_summary_endpoint_returns_demo_domains_in_demo_mode(
    authed_client: TestClient,
    monkeypatch,
):
    """Demo mode should surface generated dmarq.org and dmarq.com reports."""
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.domains.get_settings",
        lambda: SimpleNamespace(DEMO_MODE=True),
    )
    monkeypatch.setattr(
        "app.services.report_persistence.get_settings",
        lambda: SimpleNamespace(DEMO_MODE=True),
    )

    with patch(
        "app.api.api_v1.endpoints.domains.get_default_provider",
        return_value=AsyncMock(check_domain=AsyncMock(return_value=MOCK_DNS_RESULT)),
    ):
        response = authed_client.get("/api/v1/domains/summary")

    assert response.status_code == 200
    data = response.json()
    domains = {item["domain_name"] for item in data["domains"]}
    assert {"dmarq.org", "dmarq.com"} <= domains
    assert data["health_summary"]["score"] > 0
    assert data["health_summary"]["grade"] in {"A+", "A", "A-", "B+", "B", "B-", "C", "D", "F"}
    assert all("health" in item for item in data["domains"])


def test_summary_endpoint_respects_selected_workspace_header(
    authed_client: TestClient,
    db_session,
):
    """The dashboard domain summary only returns domains in the selected workspace."""
    alpha = Workspace(slug="summary-alpha", name="Summary Alpha", active=True)
    beta = Workspace(slug="summary-beta", name="Summary Beta", active=True)
    db_session.add_all([alpha, beta])
    db_session.flush()
    alpha_domain = Domain(name="alpha-summary.example", workspace_id=alpha.id, active=True)
    beta_domain = Domain(name="beta-summary.example", workspace_id=beta.id, active=True)
    db_session.add_all(
        [
            alpha_domain,
            beta_domain,
        ]
    )
    db_session.flush()
    for domain, count in ((alpha_domain, 7), (beta_domain, 13)):
        report = DMARCReport(
            domain_id=domain.id,
            report_id=f"{domain.name}-summary-report",
            org_name="Summary Org",
            begin_date=1597449600,
            end_date=1597535999,
            policy="none",
        )
        db_session.add(report)
        db_session.flush()
        db_session.add(
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.200",
                count=count,
                disposition="none",
                dkim="pass",
                spf="pass",
            )
        )
    db_session.commit()

    with _mock_dns():
        response = authed_client.get(
            "/api/v1/domains/summary",
            headers={"X-DMARQ-Workspace-ID": str(alpha.id)},
        )

    assert response.status_code == 200
    domains = response.json()["domains"]
    assert [item["domain_name"] for item in domains] == ["alpha-summary.example"]
    assert domains[0]["total_emails"] == 7


def test_domain_names_for_selected_workspace_excludes_unscoped_report_cache(db_session):
    """Selected workspace summaries must not inherit unrelated in-memory report domains."""
    workspace = Workspace(slug="summary-cache-scope", name="Summary Cache Scope", active=True)
    db_session.add(workspace)
    db_session.flush()
    db_session.add(Domain(name="scoped-cache-summary.example", workspace_id=workspace.id))
    db_session.commit()

    store = ReportStore()
    store.add_report({**MINIMAL_REPORT, "domain": "ghost-cache-summary.example"})

    assert _domain_names_for_summary(
        db_session,
        store,
        workspace,
        include_unscoped_report_domains=False,
    ) == ["scoped-cache-summary.example"]


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


def test_report_selector_map_handles_empty_and_malformed_details(db_session):
    """Report selector lookups tolerate malformed persisted DKIM auth details."""
    assert domains_endpoint._get_report_selectors_map_from_db(db_session, []) == {}

    domain = Domain(name="malformed-report-selectors.example", active=True)
    db_session.add(domain)
    db_session.flush()
    report = DMARCReport(
        domain_id=domain.id,
        report_id="malformed-report-selectors",
        org_name="Selector Org",
        begin_date=1597449600,
        end_date=1597535999,
        policy="none",
    )
    db_session.add(report)
    db_session.flush()
    db_session.add_all(
        [
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.201",
                count=1,
                disposition="none",
                dkim="pass",
                spf="pass",
                dkim_auth_details=json.dumps(["bad", {"selector": "mail"}, {"selector": "mail"}]),
            ),
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.202",
                count=1,
                disposition="none",
                dkim="pass",
                spf="pass",
                dkim_auth_details="{",
            ),
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.203",
                count=1,
                disposition="none",
                dkim="pass",
                spf="pass",
                dkim_auth_details="{}",
            ),
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.204",
                count=1,
                disposition="none",
                dkim="pass",
                spf="pass",
                dkim_auth_details=json.dumps([{"selector": "zeta"}]),
            ),
        ]
    )
    db_session.commit()

    selectors = domains_endpoint._get_report_selectors_map_from_db(
        db_session,
        ["malformed-report-selectors.example", "malformed-report-selectors.example"],
    )

    assert selectors == {"malformed-report-selectors.example": ["mail", "zeta"]}


# ---------------------------------------------------------------------------
# GET /api/v1/domains/{domain_id}/sources  (PTR + fix hints)
# ---------------------------------------------------------------------------

# A failing-source report used for sources tests
FAILING_SOURCE_IP = "104.245.209.200"
FAILING_SOURCE_REPORT = {
    "domain": DOMAIN,
    "report_id": "fail-src-001",
    "org_name": "Fail Org",
    "policy": {"p": "reject", "sp": "", "pct": "100"},
    "records": [
        {
            "source_ip": FAILING_SOURCE_IP,
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


def test_sources_endpoint_includes_hostname(authed_client: TestClient):
    """The /sources endpoint should return the rDNS hostname when available."""
    store = ReportStore.get_instance()
    store.add_report(FAILING_SOURCE_REPORT)

    with _mock_provider(hostname="mail.example.com"):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    # Find the failing source
    failing = next((s for s in sources if s["ip"] == FAILING_SOURCE_IP), None)
    assert failing is not None
    assert failing["hostname"] == "mail.example.com"


def test_sources_endpoint_hostname_none_when_no_ptr(authed_client: TestClient):
    """The /sources endpoint should return null hostname when no PTR record exists."""
    with _mock_provider(hostname=None):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    for source in sources:
        # hostname may be null; it must not crash
        assert "hostname" in source


def test_sources_endpoint_omits_spf_fix_hint_for_unknown_failing_ip(
    authed_client: TestClient,
):
    """Unknown failing sources should not receive copy-paste SPF IP changes."""
    store = ReportStore.get_instance()
    store.add_report(FAILING_SOURCE_REPORT)

    with _mock_provider():
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    failing = next((s for s in sources if s["ip"] == FAILING_SOURCE_IP), None)
    assert failing is not None
    assert failing["spf_fix_hint"] is None


def test_sources_endpoint_no_fix_hint_when_spf_passes(authed_client: TestClient):
    """A source with spf=pass should not receive an spf_fix_hint."""
    with _mock_provider():
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/sources")

    assert response.status_code == 200
    sources = response.json()["sources"]
    passing = next((s for s in sources if s["ip"] == "1.2.3.4"), None)
    if passing is not None:
        assert passing["spf_fix_hint"] is None


def test_spf_fix_hint_returns_none_for_invalid_ip_with_failures():
    """Invalid source IP values should not generate SPF snippets."""
    assert _spf_fix_hint("not-an-ip", "mixed", failed_count=3) is None
