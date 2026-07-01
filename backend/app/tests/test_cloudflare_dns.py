"""Tests for Cloudflare DNS discovery, analysis, and change tracking."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints.domains import _policy_enforcement_suggestions
from app.core.credential_encryption import encrypt_secret
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.dns_cache import DNSRecordChange, DNSRecordSnapshot
from app.models.domain import Domain
from app.models.organization import Entitlement, Organization
from app.models.setting import Setting
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog
from app.services import cloudflare_dns, dns_provider_imports, dns_provider_writes
from app.services.cloudflare_dns import analyze_dns_records, sync_dns_record_changes
from app.services.dns_provider_writes import (
    CloudflareDNSWriteProvider,
    DNSProviderWriteError,
    DNSWriteMutation,
    LexiconDNSWriteProvider,
)
from app.services.organizations import OrganizationPlanLimitError
from app.services.workspaces import get_or_create_default_workspace

DOMAIN = "example.com"


def _record(record_id: str, record_type: str, name: str, content: str, ttl: int = 1):
    return {
        "id": record_id,
        "type": record_type,
        "name": name,
        "content": content,
        "ttl": ttl,
        "proxied": False,
        "modified_on": "2026-05-23T00:00:00Z",
    }


class FakeCloudflareProvider:
    def __init__(self, *, zones=None, records=None, fail_zone_lookup=False):
        self.zones = zones or []
        self.records = records or []
        self.fail_zone_lookup = fail_zone_lookup

    async def list_zones(self):
        return self.zones

    async def list_dns_records(self, *, zone_id=None, name=None, record_type=None):
        return self.records

    async def find_zone_for_domain(self, domain):
        if self.fail_zone_lookup:
            raise LookupError("zone list forbidden")
        for zone in self.zones:
            zone_name = zone["name"]
            if domain == zone_name or domain.endswith(f".{zone_name}"):
                return zone
        return None


class FakeWriteCloudflareProvider(FakeCloudflareProvider):
    def __init__(self, *, zones=None, records=None, fail_zone_lookup=False):
        super().__init__(zones=zones, records=records, fail_zone_lookup=fail_zone_lookup)
        self.created = []
        self.updated = []

    async def create_dns_record(self, *, zone_id, record_type, name, content, ttl=1):
        record = _record(f"created-{len(self.created) + 1}", record_type, name, content, ttl)
        self.created.append({"zone_id": zone_id, **record})
        self.records.append(record)
        return record

    async def update_dns_record(
        self,
        *,
        zone_id,
        record_id,
        record_type,
        name,
        content,
        ttl=1,
    ):
        updated = _record(record_id, record_type, name, content, ttl)
        self.updated.append({"zone_id": zone_id, **updated})
        for index, record in enumerate(self.records):
            if record.get("id") == record_id:
                self.records[index] = updated
                break
        return updated


class FakeUnverifiedWriteCloudflareProvider(FakeWriteCloudflareProvider):
    async def list_dns_records(self, *, zone_id=None, name=None, record_type=None):
        return []


def test_analyze_dns_records_reports_healthy_auth_records():
    records = [
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
        _record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=quarantine"),
        _record("dkim", "TXT", f"google._domainkey.{DOMAIN}", "v=DKIM1; p=abc"),
    ]

    result = analyze_dns_records(DOMAIN, records)

    assert result["checks"]["dmarc"] is True
    assert result["checks"]["dmarc_policy"] == "quarantine"
    assert result["checks"]["spf"] is True
    assert result["checks"]["dkim"] is True
    assert result["suggestions"] == []


def test_analyze_dns_records_suggests_missing_and_duplicate_fixes():
    records = [
        _record("spf-1", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
        _record("spf-2", "TXT", DOMAIN, "v=spf1 ip4:192.0.2.10 ~all"),
    ]

    result = analyze_dns_records(DOMAIN, records)
    suggestion_types = {item["type"] for item in result["suggestions"]}

    assert "missing_dmarc" in suggestion_types
    assert "duplicate_spf" in suggestion_types
    assert "missing_dkim" in suggestion_types


def test_analyze_dns_records_suggests_duplicate_dmarc_fix():
    records = [
        _record("dmarc-1", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=none"),
        _record("dmarc-2", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=reject"),
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
    ]

    result = analyze_dns_records(DOMAIN, records)

    assert {item["type"] for item in result["suggestions"]} == {
        "duplicate_dmarc",
        "missing_dkim",
    }


def test_analyze_dns_records_suggests_malformed_dmarc_fix():
    records = [
        _record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "p=none; v=DMARC1"),
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
    ]

    result = analyze_dns_records(DOMAIN, records)

    assert "malformed_dmarc" in {item["type"] for item in result["suggestions"]}


def test_analyze_dns_records_treats_reporting_only_dmarc_as_monitoring_mode():
    records = [
        _record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; rua=mailto:dmarc@example.com"),
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
        _record("dkim", "TXT", f"google._domainkey.{DOMAIN}", "v=DKIM1; p=abc"),
    ]

    result = analyze_dns_records(DOMAIN, records)

    assert result["checks"]["dmarc"] is True
    assert result["checks"]["dmarc_policy"] == "none"
    assert "malformed_dmarc" not in {item["type"] for item in result["suggestions"]}


def test_analyze_dns_records_suggests_missing_spf_with_valid_dmarc():
    records = [
        _record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=reject"),
        _record("dkim", "TXT", f"google._domainkey.{DOMAIN}", "v=DKIM1; p=abc"),
    ]

    result = analyze_dns_records(DOMAIN, records)

    assert "missing_spf" in {item["type"] for item in result["suggestions"]}


def test_sync_dns_record_changes_tracks_add_modify_and_remove(db_session):
    first_records = [
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
        _record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=none"),
    ]
    initial_changes = sync_dns_record_changes(
        db_session,
        domain=DOMAIN,
        zone_id="zone-1",
        records=first_records,
    )

    assert [change["change_type"] for change in initial_changes] == ["added", "added"]
    assert db_session.query(DNSRecordSnapshot).count() == 2

    no_changes = sync_dns_record_changes(
        db_session,
        domain=DOMAIN,
        zone_id="zone-1",
        records=first_records,
    )

    assert no_changes == []

    second_records = [
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com -all"),
    ]
    later_changes = sync_dns_record_changes(
        db_session,
        domain=DOMAIN,
        zone_id="zone-1",
        records=second_records,
    )
    change_types = {change["change_type"] for change in later_changes}

    assert change_types == {"modified", "removed"}
    assert db_session.query(DNSRecordChange).count() == 4
    removed_snapshot = (
        db_session.query(DNSRecordSnapshot)
        .filter(DNSRecordSnapshot.record_name == f"_dmarc.{DOMAIN}")
        .first()
    )
    assert removed_snapshot.active is False


def test_sync_dns_record_changes_ignores_incomplete_records(db_session):
    changes = sync_dns_record_changes(
        db_session,
        domain=DOMAIN,
        zone_id="zone-1",
        records=[{"id": "bad", "type": "TXT", "content": "v=spf1 -all"}],
    )

    assert changes == []
    assert db_session.query(DNSRecordSnapshot).count() == 0


def test_list_dns_record_changes_clamps_limit(db_session):
    sync_dns_record_changes(
        db_session,
        domain=DOMAIN,
        zone_id="zone-1",
        records=[_record("spf", "TXT", DOMAIN, "v=spf1 ~all")],
    )

    history = cloudflare_dns.list_dns_record_changes(db_session, DOMAIN, limit=0)

    assert len(history) == 1
    assert history[0]["change_type"] == "added"


def test_cloudflare_credentials_read_encrypted_settings(db_session):
    db_session.add_all(
        [
            Setting(
                key="cloudflare.api_token",
                value=encrypt_secret("cf-token"),
                category="cloudflare",
            ),
            Setting(key="cloudflare.zone_id", value="zone-1", category="cloudflare"),
        ]
    )
    db_session.commit()

    credentials = cloudflare_dns.get_cloudflare_credentials(db_session)

    assert credentials.configured is True
    assert credentials.api_token == "cf-token"
    assert credentials.zone_id == "zone-1"


def test_build_cloudflare_provider_requires_token(db_session):
    try:
        cloudflare_dns.build_cloudflare_provider(db_session)
    except LookupError as exc:
        assert "Cloudflare API token" in str(exc)
    else:
        raise AssertionError("Expected LookupError")


def test_discover_cloudflare_zones_marks_imported_and_filters_invalid(db_session):
    default_workspace = get_or_create_default_workspace(db_session)
    selected_workspace = Workspace(slug="cf-selected", name="CF Selected", active=True)
    db_session.add(selected_workspace)
    db_session.flush()
    db_session.add(Domain(name=DOMAIN, workspace_id=default_workspace.id))
    db_session.commit()
    provider = FakeCloudflareProvider(
        zones=[
            {
                "id": "zone-1",
                "name": DOMAIN,
                "status": "active",
                "account": {"name": "Example"},
            },
            {"id": None, "name": "invalid.example"},
        ]
    )

    with patch("app.services.cloudflare_dns.build_cloudflare_provider", return_value=provider):
        zones = asyncio.run(cloudflare_dns.discover_cloudflare_zones(db_session))
        selected_zones = asyncio.run(
            cloudflare_dns.discover_cloudflare_zones(
                db_session,
                workspace_id=selected_workspace.id,
            )
        )

    assert zones == [
        {
            "id": "zone-1",
            "name": DOMAIN,
            "status": "active",
            "account_name": "Example",
            "imported": True,
        }
    ]
    assert selected_zones[0]["imported"] is False


def test_import_cloudflare_domains_imports_requested_and_skips_others(db_session):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()

    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "zone-1", "name": DOMAIN, "imported": True},
            {"id": "zone-2", "name": "new.example", "imported": False},
            {"id": "zone-3", "name": "skip.example", "imported": False},
        ]

    with patch("app.services.cloudflare_dns.discover_cloudflare_zones", new=fake_discover):
        result = asyncio.run(
            cloudflare_dns.import_cloudflare_domains(
                db_session,
                requested_domains=["new.example"],
            )
        )

    assert result["imported"] == ["new.example"]
    assert result["existing"] == []
    assert sorted(result["skipped"]) == [DOMAIN, "skip.example"]
    imported = db_session.query(Domain).filter(Domain.name == "new.example").first()
    assert imported is not None
    assert imported.description == "DNS-discovered from Cloudflare zone import"


def test_dns_provider_import_preview_wraps_cloudflare_zones(db_session):
    async def fake_discover(_db, workspace_id=None):
        assert workspace_id == 123
        return [
            {
                "id": "zone-1",
                "name": DOMAIN,
                "status": "active",
                "account_name": "Example",
                "imported": False,
            },
            {
                "id": "zone-2",
                "name": "existing.example",
                "status": "active",
                "account_name": "Example",
                "imported": True,
            },
        ]

    with patch("app.services.dns_provider_imports.discover_cloudflare_zones", new=fake_discover):
        result = asyncio.run(
            dns_provider_imports.preview_dns_provider_import(
                db_session,
                provider="cloudflare",
                workspace_id=123,
            )
        )

    assert result["provider"] == "cloudflare"
    assert result["provider_name"] == "Cloudflare"
    assert result["total_discovered"] == 2
    assert result["importable_count"] == 1
    assert result["zones"][0]["domain"] == DOMAIN
    assert result["zones"][0]["importable"] is True
    assert result["zones"][1]["next_action"] == "Already monitored in this workspace."


def test_dns_provider_import_rejects_unsupported_provider(db_session):
    with pytest.raises(LookupError, match="Unsupported DNS provider import"):
        asyncio.run(
            dns_provider_imports.preview_dns_provider_import(
                db_session,
                provider="unsupported",
            )
        )


def test_dns_provider_import_apply_rejects_unsupported_provider(db_session):
    with pytest.raises(LookupError, match="Unsupported DNS provider import"):
        asyncio.run(
            dns_provider_imports.import_dns_provider_domains(
                db_session,
                provider="unsupported",
            )
        )


def test_dns_provider_import_creates_empty_report_domain_state(
    authed_client: TestClient,
    db_session,
):
    async def fake_discover(_db, workspace_id=None):
        return [{"id": "zone-1", "name": "dns-only.example", "imported": False}]

    with patch("app.services.cloudflare_dns.discover_cloudflare_zones", new=fake_discover):
        result = asyncio.run(
            dns_provider_imports.import_dns_provider_domains(
                db_session,
                provider="cloudflare",
                requested_domains=["dns-only.example"],
            )
        )

    assert result["imported"] == ["dns-only.example"]
    response = authed_client.get("/api/v1/domains/domains")
    assert response.status_code == 200
    imported = next(item for item in response.json() if item["name"] == "dns-only.example")
    assert imported["reports_count"] == 0
    assert imported["emails_count"] == 0
    assert imported["policy"] == "unknown"


def test_import_cloudflare_domains_respects_monitored_domain_plan_limit(db_session):
    organization = Organization(slug="cf-quota", name="CF Quota", active=True)
    workspace = Workspace(slug="cf-quota", name="CF Quota", organization=organization, active=True)
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="monitored_domains",
                value="1",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.flush()
    db_session.add(Domain(name="existing.example", workspace_id=workspace.id, active=True))
    db_session.commit()

    async def fake_discover(_db, workspace_id=None):
        return [{"id": "zone-1", "name": "new.example", "imported": False}]

    with patch("app.services.cloudflare_dns.discover_cloudflare_zones", new=fake_discover):
        try:
            asyncio.run(
                cloudflare_dns.import_cloudflare_domains(
                    db_session,
                    requested_domains=["new.example"],
                    workspace_id=workspace.id,
                )
            )
        except OrganizationPlanLimitError as exc:
            assert exc.to_detail()["metric"] == "monitored_domains"
            assert exc.to_detail()["current"] == 1
            assert exc.to_detail()["limit"] == 1
        else:
            raise AssertionError("Expected monitored domain plan limit")


def test_get_zone_for_domain_uses_configured_zone_id_even_if_zone_lookup_fails(db_session):
    db_session.add_all(
        [
            Setting(
                key="cloudflare.api_token",
                value=encrypt_secret("cf-token"),
                category="cloudflare",
            ),
            Setting(key="cloudflare.zone_id", value="zone-1", category="cloudflare"),
        ]
    )
    db_session.commit()
    provider = FakeCloudflareProvider(
        records=[_record("spf", "TXT", DOMAIN, "v=spf1 ~all")],
        fail_zone_lookup=True,
    )

    with patch("app.services.cloudflare_dns.build_cloudflare_provider", return_value=provider):
        result = asyncio.run(cloudflare_dns.get_zone_for_domain(db_session, DOMAIN))

    assert result["id"] == "zone-1"
    assert result["name"] == DOMAIN
    assert result["records"][0]["id"] == "spf"


def test_get_zone_for_domain_finds_best_matching_zone(db_session):
    db_session.add(
        Setting(
            key="cloudflare.api_token",
            value=encrypt_secret("cf-token"),
            category="cloudflare",
        )
    )
    db_session.commit()
    provider = FakeCloudflareProvider(
        zones=[
            {"id": "zone-root", "name": "example.com"},
            {"id": "zone-sub", "name": "mail.example.com"},
        ],
        records=[_record("spf", "TXT", "mail.example.com", "v=spf1 ~all")],
    )

    with patch("app.services.cloudflare_dns.build_cloudflare_provider", return_value=provider):
        result = asyncio.run(cloudflare_dns.get_zone_for_domain(db_session, "mail.example.com"))

    assert result["id"] == "zone-root"
    assert result["name"] == "example.com"


def test_get_zone_for_domain_raises_when_no_zone_matches(db_session):
    db_session.add(
        Setting(
            key="cloudflare.api_token",
            value=encrypt_secret("cf-token"),
            category="cloudflare",
        )
    )
    db_session.commit()
    provider = FakeCloudflareProvider(zones=[])

    with patch("app.services.cloudflare_dns.build_cloudflare_provider", return_value=provider):
        try:
            asyncio.run(cloudflare_dns.get_zone_for_domain(db_session, DOMAIN))
        except LookupError as exc:
            assert DOMAIN in str(exc)
        else:
            raise AssertionError("Expected LookupError")


def test_policy_enforcement_suggestion_requires_high_compliance():
    suggestions = _policy_enforcement_suggestions(
        "none",
        {"total_count": 250, "compliance_rate": 99.2},
    )

    assert suggestions[0]["type"] == "policy_enforcement_ready"


def test_policy_enforcement_suggestion_ignores_enforced_policy():
    suggestions = _policy_enforcement_suggestions(
        "reject",
        {"total_count": 250, "compliance_rate": 99.2},
    )

    assert suggestions == []


def test_cloudflare_discover_endpoint_returns_zones(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.discover_cloudflare_zones",
        new=AsyncMock(
            return_value=[
                {
                    "id": "zone-1",
                    "name": DOMAIN,
                    "status": "active",
                    "account_name": "Example",
                    "imported": False,
                }
            ]
        ),
    ):
        response = authed_client.get("/api/v1/domains/cloudflare/discover")

    assert response.status_code == 200
    assert response.json()[0]["name"] == DOMAIN


def test_dns_provider_import_preview_endpoint_returns_zones(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.preview_dns_provider_import",
        new=AsyncMock(
            return_value={
                "provider": "cloudflare",
                "provider_name": "Cloudflare",
                "zones": [
                    {
                        "provider": "cloudflare",
                        "provider_name": "Cloudflare",
                        "zone_id": "zone-1",
                        "domain": DOMAIN,
                        "status": "active",
                        "account_name": "Example",
                        "imported": False,
                        "importable": True,
                        "source": "dns_zone",
                        "next_action": "Import this Cloudflare zone.",
                    }
                ],
                "total_discovered": 1,
                "importable_count": 1,
            }
        ),
    ):
        response = authed_client.get("/api/v1/domains/dns/import/cloudflare/preview")

    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "cloudflare"
    assert data["zones"][0]["domain"] == DOMAIN
    assert data["zones"][0]["importable"] is True


def test_dns_provider_import_endpoint_returns_import_summary(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.import_dns_provider_domains",
        new=AsyncMock(
            return_value={
                "provider": "cloudflare",
                "provider_name": "Cloudflare",
                "imported": [DOMAIN],
                "existing": [],
                "skipped": [],
                "total_discovered": 1,
            }
        ),
    ):
        response = authed_client.post(
            "/api/v1/domains/dns/import/cloudflare",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "cloudflare"
    assert data["imported"] == [DOMAIN]


def test_dns_provider_import_endpoint_rejects_unknown_provider(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.preview_dns_provider_import",
        new=AsyncMock(side_effect=LookupError("Unsupported DNS provider import: example")),
    ):
        response = authed_client.get("/api/v1/domains/dns/import/example/preview")

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported DNS provider import: example"


def test_dns_provider_import_endpoint_rejects_unknown_provider_on_apply(
    authed_client: TestClient,
):
    with patch(
        "app.api.api_v1.endpoints.domains.import_dns_provider_domains",
        new=AsyncMock(side_effect=LookupError("Unsupported DNS provider import: example")),
    ):
        response = authed_client.post("/api/v1/domains/dns/import/example", json={})

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported DNS provider import: example"


def test_dns_provider_import_endpoint_surfaces_plan_limit(
    authed_client: TestClient,
):
    plan_error = OrganizationPlanLimitError(
        metric="monitored_domains",
        current=1,
        limit=1,
        attempted=1,
        unit="domains",
        entitlement_key="monitored_domains",
    )
    with patch(
        "app.api.api_v1.endpoints.domains.import_dns_provider_domains",
        new=AsyncMock(side_effect=plan_error),
    ):
        response = authed_client.post(
            "/api/v1/domains/dns/import/cloudflare",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 402
    assert response.json()["detail"]["code"] == "plan_limit_exceeded"
    assert response.json()["detail"]["metric"] == "monitored_domains"


def test_dns_provider_capabilities_mark_cloudflare_import_available(authed_client: TestClient):
    response = authed_client.get("/api/v1/domains/dns/providers")

    assert response.status_code == 200
    providers = {provider["id"]: provider for provider in response.json()["providers"]}
    assert providers["cloudflare"]["import_available"] is True
    assert providers["route53"]["import_available"] is False


def test_cloudflare_import_endpoint_returns_import_summary(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.import_cloudflare_domains",
        new=AsyncMock(
            return_value={
                "imported": [DOMAIN],
                "existing": [],
                "skipped": [],
                "total_discovered": 1,
            }
        ),
    ):
        response = authed_client.post(
            "/api/v1/domains/cloudflare/import",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 200
    assert response.json()["imported"] == [DOMAIN]


def test_cloudflare_dns_analysis_endpoint_persists_history(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    records = [
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
        _record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=reject"),
    ]

    with patch(
        "app.api.api_v1.endpoints.domains.get_zone_for_domain",
        new=AsyncMock(return_value={"id": "zone-1", "name": DOMAIN, "records": records}),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/cloudflare")

    assert response.status_code == 200
    data = response.json()
    assert data["zone"]["id"] == "zone-1"
    assert data["checks"]["dmarc_policy"] == "reject"
    assert len(data["changes"]) == 2
    assert len(data["history"]) == 2

    history_response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/history")
    assert history_response.status_code == 200
    assert len(history_response.json()["history"]) == 2


def test_cloudflare_dns_analysis_endpoint_returns_configuration_errors(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.get_zone_for_domain",
        new=AsyncMock(side_effect=LookupError("Cloudflare API token is not configured")),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/cloudflare")

    assert response.status_code == 400
    assert "Cloudflare API token" in response.json()["detail"]


def _dns_plan(plan_id="dmarc-missing-example-com-txt", operation="create", proposed_value=None):
    return {
        "plan_id": plan_id,
        "finding_code": "dmarc_missing",
        "severity": "error",
        "operation": operation,
        "record_type": "TXT",
        "name": f"_dmarc.{DOMAIN}",
        "proposed_value": proposed_value or f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}",
        "current_values": [],
        "rationale": "Publish a DMARC TXT record in monitoring mode before tightening policy.",
        "risk": "Low delivery risk when starting with p=none.",
        "rollback": f"Delete the newly created TXT record at _dmarc.{DOMAIN}.",
        "expected_health_impact": "Expected to remove a critical DNS-health finding.",
        "manual_steps": ["Publish the planned TXT record."],
        "requires_approval": True,
        "applies_automatically": False,
        "provider_write_available": False,
        "provider_value_required": False,
    }


def _dns_guidance_with_plan(plan):
    return {
        "domain": DOMAIN,
        "status": "critical",
        "findings": [],
        "target_records": [],
        "dns_provider": None,
        "change_plans": [plan],
    }


def test_dns_provider_capabilities_include_cloudflare_and_lexicon(authed_client: TestClient):
    response = authed_client.get("/api/v1/domains/dns/providers")

    assert response.status_code == 200
    providers = {provider["id"]: provider for provider in response.json()["providers"]}
    assert providers["cloudflare"]["mode"] == "native"
    assert "route53" in providers
    assert "googleclouddns" in providers


def test_dns_provider_capabilities_report_available_lexicon_runtime():
    with patch("app.services.dns_provider_writes.lexicon_runtime_available", return_value=True):
        providers = {
            provider["id"]: provider for provider in dns_provider_writes.provider_capabilities()
        }

    assert providers["cloudflare"]["status"] == "ready"
    assert providers["route53"]["status"] == "ready"
    assert providers["route53"]["mode"] == "lexicon"


def test_dns_write_provider_registry_normalizes_supported_provider_ids():
    cloudflare_provider = dns_provider_writes.build_dns_write_provider(" CloudFlare ")
    route53_provider = dns_provider_writes.build_dns_write_provider("ROUTE53")

    assert cloudflare_provider.provider_id == "cloudflare"
    assert route53_provider.provider_id == "route53"


def test_dns_write_provider_registry_rejects_unknown_provider():
    try:
        dns_provider_writes.build_dns_write_provider("unknown-dns")
    except DNSProviderWriteError as exc:
        assert "Unsupported DNS provider" in str(exc)
    else:
        raise AssertionError("Expected unsupported DNS provider error")


def test_dns_change_plan_marks_apply_ready_records(authed_client: TestClient, db_session):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan()
    plan["current_values"] = ["v=DMARC1; p=none"]

    with patch(
        "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
        new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/change-plan")

    assert response.status_code == 200
    data = response.json()
    assert data["read_only"] is False
    assert data["provider_write_available"] is True
    assert data["apply_endpoint"].endswith("/dns/change-plan/apply")
    assert "cloudflare" in data["available_write_providers"]
    assert data["recommended_provider"] == "cloudflare"
    assert data["safety_notes"]
    assert data["plans"][0]["provider_write_available"] is True
    assert data["plans"][0]["safety_notes"] == [
        "Preview the provider mutation before applying this DNS change.",
        "Existing provider values will be shown in the preview before approval.",
    ]


def test_dns_change_plan_recommends_detected_provider(authed_client: TestClient, db_session):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan(operation="update")
    guidance = _dns_guidance_with_plan(plan)
    guidance["dns_provider"] = {
        "provider_id": "digitalocean",
        "provider_name": "DigitalOcean DNS",
        "confidence": "high",
        "evidence": ["ns1.digitalocean.com"],
    }

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=guidance),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.provider_capabilities",
            return_value=[
                {
                    "id": "cloudflare",
                    "name": "Cloudflare",
                    "mode": "native",
                    "record_types": ["CNAME", "TXT"],
                    "operations": ["create", "update"],
                    "credentials": "settings",
                    "status": "ready",
                },
                {
                    "id": "digitalocean",
                    "name": "digitalocean",
                    "mode": "lexicon",
                    "record_types": ["CNAME", "TXT"],
                    "operations": ["create", "update"],
                    "credentials": "environment",
                    "status": "ready",
                },
            ],
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/change-plan")

    assert response.status_code == 200
    data = response.json()
    assert data["recommended_provider"] == "digitalocean"
    assert data["available_write_providers"] == ["cloudflare", "digitalocean"]
    assert "Recommended provider for this domain: digitalocean." in data["safety_notes"]


def test_dns_change_plan_avoids_wrong_provider_recommendation(
    authed_client: TestClient, db_session
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    guidance = _dns_guidance_with_plan(_dns_plan(operation="update"))
    guidance["dns_provider"] = {
        "provider_id": "exampledns",
        "provider_name": "ExampleDNS",
        "confidence": "medium",
        "evidence": ["ns1.exampledns.test"],
    }

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=guidance),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.provider_capabilities",
            return_value=[
                {
                    "id": "cloudflare",
                    "name": "Cloudflare",
                    "mode": "native",
                    "record_types": ["CNAME", "TXT"],
                    "operations": ["create", "update"],
                    "credentials": "settings",
                    "status": "ready",
                },
            ],
        ),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/change-plan")

    assert response.status_code == 200
    data = response.json()
    assert data["recommended_provider"] is None
    assert data["available_write_providers"] == ["cloudflare"]
    assert "does not match a ready write connector" in " ".join(data["safety_notes"])


def test_dns_change_plan_explains_manual_only_plans(authed_client: TestClient, db_session):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan(operation="rotate", proposed_value="<provider-current-dkim-key>")
    plan["provider_value_required"] = True

    with patch(
        "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
        new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
    ):
        response = authed_client.get(f"/api/v1/domains/{DOMAIN}/dns/change-plan")

    assert response.status_code == 200
    plan_response = response.json()["plans"][0]
    assert plan_response["provider_write_available"] is False
    assert "This operation is review-only" in " ".join(plan_response["safety_notes"])
    assert "provider-specific final value" in " ".join(plan_response["safety_notes"])


def test_dns_change_plan_apply_dry_run_returns_cloudflare_mutation(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan()
    records = [_record("spf", "TXT", DOMAIN, "v=spf1 -all")]

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch(
            "app.services.dns_provider_writes.get_zone_for_domain",
            new=AsyncMock(return_value={"id": "zone-1", "name": DOMAIN, "records": records}),
        ),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={"plan_id": plan["plan_id"], "provider": "cloudflare"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["dry_run"] is True
    assert data["applied"] is False
    assert data["mutation"]["operation"] == "create"
    assert data["mutation"]["name"] == f"_dmarc.{DOMAIN}"
    assert data["mutation"]["content"] == plan["proposed_value"]
    assert data["verification"]["status"] == "not_run"
    assert data["verification"]["verified"] is False
    assert data["rollback"]["summary"] == plan["rollback"]
    assert data["rollback"]["provider"] == "cloudflare"
    assert data["rollback"]["record_type"] == "TXT"
    assert data["rollback"]["name"] == f"_dmarc.{DOMAIN}"
    assert data["rollback"]["requires_manual_review"] is True
    assert "Delete the created record" in " ".join(data["rollback"]["steps"])


def test_dns_change_plan_apply_uses_resolved_domain_for_provider_calls(
    authed_client: TestClient,
    db_session,
):
    plan = _dns_plan()
    records = [_record("spf", "TXT", DOMAIN, "v=spf1 -all")]
    zone_lookup = AsyncMock(return_value={"id": "zone-1", "name": DOMAIN, "records": records})

    with (
        patch("app.api.api_v1.endpoints.domains._domain_exists", return_value=True),
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch("app.services.dns_provider_writes.get_zone_for_domain", new=zone_lookup),
    ):
        response = authed_client.post(
            "/api/v1/domains/domain-row-id/dns/change-plan/apply",
            json={"plan_id": plan["plan_id"], "provider": "cloudflare"},
        )

    assert response.status_code == 200
    zone_lookup.assert_awaited_once_with(db_session, DOMAIN)


def test_dns_change_plan_apply_dry_run_returns_noop_for_unchanged_cloudflare_record(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan()
    records = [_record("dmarc", "TXT", f"_dmarc.{DOMAIN}", plan["proposed_value"])]

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch(
            "app.services.dns_provider_writes.get_zone_for_domain",
            new=AsyncMock(return_value={"id": "zone-1", "name": DOMAIN, "records": records}),
        ),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={"plan_id": plan["plan_id"], "provider": "cloudflare"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["dry_run"] is True
    assert data["mutation"]["operation"] == "noop"
    assert data["mutation"]["current_values"] == [plan["proposed_value"]]
    assert "No provider rollback is needed" in data["rollback"]["summary"]
    assert data["rollback"]["previous_values"] == [plan["proposed_value"]]


def test_dns_change_plan_apply_blocks_detected_provider_mismatch(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan()
    guidance = _dns_guidance_with_plan(plan)
    guidance["dns_provider"] = {
        "provider_id": "digitalocean",
        "provider_name": "DigitalOcean DNS",
        "confidence": "high",
        "evidence": ["ns1.digitalocean.com"],
    }
    zone_lookup = AsyncMock(return_value={"id": "zone-1", "name": DOMAIN, "records": []})

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=guidance),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.provider_capabilities",
            return_value=[
                {
                    "id": "cloudflare",
                    "name": "Cloudflare",
                    "mode": "native",
                    "record_types": ["CNAME", "TXT"],
                    "operations": ["create", "update"],
                    "credentials": "settings",
                    "status": "ready",
                },
            ],
        ),
        patch("app.services.dns_provider_writes.get_zone_for_domain", new=zone_lookup),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={"plan_id": plan["plan_id"], "provider": "cloudflare"},
        )

    assert response.status_code == 422
    assert "does not match the detected provider" in response.json()["detail"]
    zone_lookup.assert_not_awaited()


def test_dns_change_plan_apply_blocks_multiple_matching_cloudflare_records(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan()
    records = [
        _record("dmarc-1", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=none"),
        _record("dmarc-2", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=reject"),
    ]

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch(
            "app.services.dns_provider_writes.get_zone_for_domain",
            new=AsyncMock(return_value={"id": "zone-1", "name": DOMAIN, "records": records}),
        ),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={"plan_id": plan["plan_id"], "provider": "cloudflare"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["mutation"]["applicable"] is False
    assert "Multiple provider records" in data["mutation"]["blocked_reason"]


def test_dns_change_plan_apply_rejects_unconfirmed_real_write(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan()

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch(
            "app.services.dns_provider_writes.get_zone_for_domain",
            new=AsyncMock(return_value={"id": "zone-1", "name": DOMAIN, "records": []}),
        ),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={"plan_id": plan["plan_id"], "provider": "cloudflare", "dry_run": False},
        )

    assert response.status_code == 200
    assert response.json()["dry_run"] is True
    assert db_session.query(WorkspaceAuditLog).count() == 0


def test_dns_change_plan_apply_updates_cloudflare_and_audits(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan(operation="update")
    provider = FakeWriteCloudflareProvider(
        zones=[{"id": "zone-1", "name": DOMAIN}],
        records=[_record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=none")],
    )

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch(
            "app.services.dns_provider_writes.get_zone_for_domain",
            new=AsyncMock(
                return_value={"id": "zone-1", "name": DOMAIN, "records": list(provider.records)}
            ),
        ),
        patch(
            "app.services.dns_provider_writes.build_cloudflare_provider",
            return_value=provider,
        ),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={
                "plan_id": plan["plan_id"],
                "provider": "cloudflare",
                "dry_run": False,
                "confirm": True,
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["applied"] is True
    assert data["verification"]["status"] == "verified"
    assert data["verification"]["verified"] is True
    assert data["verification"]["checked_values"] == [plan["proposed_value"]]
    assert data["rollback"]["previous_values"] == ["v=DMARC1; p=none"]
    assert "Restore the previous value" in " ".join(data["rollback"]["steps"])
    assert provider.updated[0]["content"] == plan["proposed_value"]
    assert db_session.query(DNSRecordChange).count() == 1
    audit = db_session.query(WorkspaceAuditLog).one()
    assert audit.action == "domain.dns_change_applied"
    audit_details = json.loads(audit.details)
    assert audit_details["provider"] == "cloudflare"
    assert audit_details["provider_mismatch"] is False
    assert audit_details["verification"]["status"] == "verified"
    assert audit_details["verification"]["verified"] is True
    assert audit_details["rollback"]["previous_values"] == ["v=DMARC1; p=none"]


def test_dns_change_plan_apply_reports_unverified_provider_readback(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan(operation="update")
    provider = FakeUnverifiedWriteCloudflareProvider(
        zones=[{"id": "zone-1", "name": DOMAIN}],
        records=[_record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=none")],
    )

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch(
            "app.services.dns_provider_writes.get_zone_for_domain",
            new=AsyncMock(
                return_value={"id": "zone-1", "name": DOMAIN, "records": list(provider.records)}
            ),
        ),
        patch(
            "app.services.dns_provider_writes.build_cloudflare_provider",
            return_value=provider,
        ),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={
                "plan_id": plan["plan_id"],
                "provider": "cloudflare",
                "dry_run": False,
                "confirm": True,
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["applied"] is True
    assert data["verification"]["status"] == "failed"
    assert data["verification"]["verified"] is False
    assert "did not return the expected DNS record" in data["verification"]["message"]
    audit_details = json.loads(db_session.query(WorkspaceAuditLog).one().details)
    assert audit_details["verification"]["status"] == "failed"
    assert audit_details["verification"]["verified"] is False


def test_dns_change_plan_apply_simulates_confirmed_write_in_demo_mode(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan(operation="update")
    plan["current_values"] = ["v=DMARC1; p=none"]

    class DemoSettings:
        DEMO_MODE = True

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch("app.api.api_v1.endpoints.domains.get_settings", return_value=DemoSettings()),
        patch("app.services.dns_provider_writes.build_dns_write_provider") as build_provider,
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={
                "plan_id": plan["plan_id"],
                "provider": "cloudflare",
                "dry_run": False,
                "confirm": True,
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["applied"] is True
    assert data["dry_run"] is False
    assert data["provider_result"]["mode"] == "demo"
    assert data["mutation"]["zone_id"] == "demo-zone"
    assert data["mutation"]["current_values"] == ["v=DMARC1; p=none"]
    assert data["verification"]["status"] == "verified"
    assert data["verification"]["verified"] is True
    assert "No live DNS was changed" in data["verification"]["message"]
    assert data["rollback"]["previous_values"] == ["v=DMARC1; p=none"]
    build_provider.assert_not_called()
    audit_details = json.loads(db_session.query(WorkspaceAuditLog).one().details)
    assert audit_details["applied"] is True
    assert audit_details["verification"]["status"] == "verified"
    assert audit_details["rollback"]["previous_values"] == ["v=DMARC1; p=none"]


def test_dns_change_plan_apply_allows_explicit_provider_mismatch_override_and_audits(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan(operation="update")
    guidance = _dns_guidance_with_plan(plan)
    guidance["dns_provider"] = {
        "provider_id": "digitalocean",
        "provider_name": "DigitalOcean DNS",
        "confidence": "high",
        "evidence": ["ns1.digitalocean.com"],
    }
    provider = FakeWriteCloudflareProvider(
        zones=[{"id": "zone-1", "name": DOMAIN}],
        records=[_record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; p=none")],
    )

    with (
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=guidance),
        ),
        patch(
            "app.api.api_v1.endpoints.domains.provider_capabilities",
            return_value=[
                {
                    "id": "cloudflare",
                    "name": "Cloudflare",
                    "mode": "native",
                    "record_types": ["CNAME", "TXT"],
                    "operations": ["create", "update"],
                    "credentials": "settings",
                    "status": "ready",
                },
                {
                    "id": "digitalocean",
                    "name": "digitalocean",
                    "mode": "lexicon",
                    "record_types": ["CNAME", "TXT"],
                    "operations": ["create", "update"],
                    "credentials": "environment",
                    "status": "ready",
                },
            ],
        ),
        patch(
            "app.services.dns_provider_writes.get_zone_for_domain",
            new=AsyncMock(
                return_value={"id": "zone-1", "name": DOMAIN, "records": list(provider.records)}
            ),
        ),
        patch(
            "app.services.dns_provider_writes.build_cloudflare_provider",
            return_value=provider,
        ),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={
                "plan_id": plan["plan_id"],
                "provider": "cloudflare",
                "dry_run": False,
                "confirm": True,
                "allow_provider_mismatch": True,
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["applied"] is True
    audit = db_session.query(WorkspaceAuditLog).one()
    audit_details = json.loads(audit.details)
    assert audit_details["recommended_provider"] == "digitalocean"
    assert audit_details["selected_provider"] == "cloudflare"
    assert audit_details["provider_mismatch"] is True
    assert audit_details["provider_mismatch_override"] is True


def test_dns_change_plan_apply_blocks_provider_value_placeholders(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()
    plan = _dns_plan(proposed_value="v=DKIM1; p=<provider-public-key>")

    with patch(
        "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
        new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
    ):
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={"plan_id": plan["plan_id"], "provider": "cloudflare"},
        )

    assert response.status_code == 422
    assert "provider-specific value" in response.json()["detail"]


def test_apply_dns_write_rejects_demo_mode(db_session):
    workspace = get_or_create_default_workspace(db_session)
    plan = _dns_plan()

    class DemoSettings:
        DEMO_MODE = True

    with patch("app.services.dns_provider_writes.get_settings", return_value=DemoSettings()):
        try:
            asyncio.run(
                dns_provider_writes.apply_dns_write(
                    db_session,
                    workspace=workspace,
                    domain=DOMAIN,
                    plan=plan,
                    provider_id="cloudflare",
                )
            )
        except DNSProviderWriteError as exc:
            assert "disabled in demo mode" in str(exc)
        else:
            raise AssertionError("Expected demo mode DNS write block")


def test_apply_dns_write_rejects_unpersisted_workspace_before_provider_call(db_session):
    workspace = Workspace(slug="pending", name="Pending")
    plan = _dns_plan()

    class NonDemoSettings:
        DEMO_MODE = False

    with (
        patch("app.services.dns_provider_writes.get_settings", return_value=NonDemoSettings()),
        patch("app.services.dns_provider_writes.build_dns_write_provider") as build_provider,
    ):
        with pytest.raises(DNSProviderWriteError, match="Workspace must be persisted"):
            asyncio.run(
                dns_provider_writes.apply_dns_write(
                    db_session,
                    workspace=workspace,
                    domain=DOMAIN,
                    plan=plan,
                    provider_id="cloudflare",
                )
            )

    build_provider.assert_not_called()


def test_cloudflare_write_provider_requires_zone_id_for_apply(db_session):
    provider = CloudflareDNSWriteProvider()
    mutation = DNSWriteMutation(
        operation="create",
        record_type="TXT",
        name=f"_dmarc.{DOMAIN}",
        content=f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}",
        ttl=1,
        provider="cloudflare",
    )

    with patch(
        "app.services.dns_provider_writes.build_cloudflare_provider",
        return_value=FakeWriteCloudflareProvider(),
    ):
        try:
            asyncio.run(provider.apply_mutation(db_session, domain=DOMAIN, mutation=mutation))
        except DNSProviderWriteError as exc:
            assert "zone ID" in str(exc)
        else:
            raise AssertionError("Expected missing Cloudflare zone ID error")


def test_cloudflare_write_provider_creates_record_and_syncs_history(db_session):
    provider = CloudflareDNSWriteProvider()
    cloudflare_provider = FakeWriteCloudflareProvider(
        zones=[{"id": "zone-1", "name": DOMAIN}],
        records=[],
    )
    mutation = DNSWriteMutation(
        operation="create",
        record_type="TXT",
        name=f"_dmarc.{DOMAIN}",
        content=f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}",
        ttl=3600,
        provider="cloudflare",
        zone_id="zone-1",
    )

    with patch(
        "app.services.dns_provider_writes.build_cloudflare_provider",
        return_value=cloudflare_provider,
    ):
        result = asyncio.run(provider.apply_mutation(db_session, domain=DOMAIN, mutation=mutation))

    assert result.applied is True
    assert cloudflare_provider.created[0]["ttl"] == 3600
    assert result.provider_result["id"] == "created-1"
    assert result.verification.status == "verified"
    assert result.verification.verified is True
    assert result.changes[0]["change_type"] == "added"
    assert db_session.query(DNSRecordChange).count() == 1


def test_cloudflare_write_provider_blocks_inapplicable_mutation(db_session):
    provider = CloudflareDNSWriteProvider()
    mutation = DNSWriteMutation(
        operation="update",
        record_type="TXT",
        name=f"_dmarc.{DOMAIN}",
        content=f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}",
        ttl=1,
        provider="cloudflare",
        blocked_reason="manual merge required",
    )

    with pytest.raises(DNSProviderWriteError, match="manual merge required"):
        asyncio.run(provider.apply_mutation(db_session, domain=DOMAIN, mutation=mutation))


def test_cloudflare_write_provider_rejects_unsupported_apply_operation(db_session):
    provider = CloudflareDNSWriteProvider()
    mutation = DNSWriteMutation(
        operation="delete",
        record_type="TXT",
        name=f"_dmarc.{DOMAIN}",
        content=f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}",
        ttl=1,
        provider="cloudflare",
        zone_id="zone-1",
    )

    with patch(
        "app.services.dns_provider_writes.build_cloudflare_provider",
        return_value=FakeWriteCloudflareProvider(),
    ):
        with pytest.raises(DNSProviderWriteError, match="Unsupported Cloudflare operation"):
            asyncio.run(provider.apply_mutation(db_session, domain=DOMAIN, mutation=mutation))


def test_lexicon_write_provider_reports_missing_runtime(db_session):
    provider = LexiconDNSWriteProvider("route53")

    with patch("app.services.dns_provider_writes.lexicon_runtime_available", return_value=False):
        try:
            asyncio.run(
                provider.prepare_mutation(
                    db_session,
                    domain=DOMAIN,
                    plan=_dns_plan(),
                    value_override=None,
                    ttl=1,
                )
            )
        except DNSProviderWriteError as exc:
            assert "dns-lexicon is not installed" in str(exc)
        else:
            raise AssertionError("Expected missing Lexicon runtime error")


def test_lexicon_write_provider_prepares_update_and_applies_record(db_session):
    provider = LexiconDNSWriteProvider("route53")
    records = [{"id": "record-1", "content": "v=DMARC1; p=none"}]

    def list_records(domain, record_type, record_name):
        return records

    def apply_record(domain, mutation):
        records[0] = {
            "id": "record-1",
            "type": mutation.record_type,
            "name": mutation.name,
            "content": mutation.content,
        }
        return mutation.record_id == "record-1"

    provider._list_records = list_records  # pylint: disable=protected-access
    provider._apply_record = apply_record  # pylint: disable=protected-access

    with patch("app.services.dns_provider_writes.lexicon_runtime_available", return_value=True):
        mutation = asyncio.run(
            provider.prepare_mutation(
                db_session,
                domain=DOMAIN,
                plan=_dns_plan(operation="update"),
                value_override="v=DMARC1; p=reject",
                ttl=300,
            )
        )
        result = asyncio.run(provider.apply_mutation(db_session, domain=DOMAIN, mutation=mutation))

    assert mutation.operation == "update"
    assert mutation.record_id == "record-1"
    assert mutation.current_values == ["v=DMARC1; p=none"]
    assert result.applied is True
    assert result.provider_result == {"ok": True}
    assert result.verification.status == "verified"
    assert result.verification.verified is True


def test_lexicon_write_provider_rejects_failed_apply(db_session):
    provider = LexiconDNSWriteProvider("route53")
    provider._list_records = (
        lambda domain, record_type, record_name: []
    )  # pylint: disable=protected-access
    provider._apply_record = lambda domain, mutation: False  # pylint: disable=protected-access

    with patch("app.services.dns_provider_writes.lexicon_runtime_available", return_value=True):
        mutation = asyncio.run(
            provider.prepare_mutation(
                db_session,
                domain=DOMAIN,
                plan=_dns_plan(),
                value_override=None,
                ttl=300,
            )
        )
        with pytest.raises(DNSProviderWriteError, match="did not apply"):
            asyncio.run(provider.apply_mutation(db_session, domain=DOMAIN, mutation=mutation))


def test_lexicon_write_provider_prepares_noop_for_matching_record(db_session):
    provider = LexiconDNSWriteProvider("route53")
    expected_value = "v=DMARC1; p=none"
    provider._list_records = lambda domain, record_type, record_name: [  # pylint: disable=protected-access
        {"id": "record-1", "content": expected_value}
    ]

    with patch("app.services.dns_provider_writes.lexicon_runtime_available", return_value=True):
        mutation = asyncio.run(
            provider.prepare_mutation(
                db_session,
                domain=DOMAIN,
                plan=_dns_plan(proposed_value=expected_value),
                value_override=None,
                ttl=1,
            )
        )
        result = asyncio.run(provider.apply_mutation(db_session, domain=DOMAIN, mutation=mutation))

    assert mutation.operation == "noop"
    assert result.applied is False
    assert result.provider_result == {"status": "unchanged"}


def test_lexicon_write_provider_blocks_duplicate_records(db_session):
    provider = LexiconDNSWriteProvider("route53")
    provider._list_records = lambda domain, record_type, record_name: [  # pylint: disable=protected-access
        {"id": "record-1", "content": "v=DMARC1; p=none"},
        {"id": "record-2", "content": "v=DMARC1; p=reject"},
    ]

    with patch("app.services.dns_provider_writes.lexicon_runtime_available", return_value=True):
        mutation = asyncio.run(
            provider.prepare_mutation(
                db_session,
                domain=DOMAIN,
                plan=_dns_plan(),
                value_override=None,
                ttl=1,
            )
        )

    assert mutation.applicable is False
    assert mutation.current_values == ["v=DMARC1; p=none", "v=DMARC1; p=reject"]
    assert "Multiple provider records" in mutation.blocked_reason


def test_cloudflare_discover_denies_user_without_workspace_membership(
    test_app,
    db_session: Session,
):
    get_or_create_default_workspace(db_session)
    user = User(
        email="domain-outsider@example.com",
        is_active=True,
        is_verified=True,
        is_superuser=False,
    )
    db_session.add(user)
    db_session.commit()

    async def mock_admin_auth():
        return {"auth_type": "session", "user_id": user.id}

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    discover_mock = AsyncMock(return_value=[])
    with (
        TestClient(test_app) as client,
        patch(
            "app.api.api_v1.endpoints.domains.discover_cloudflare_zones",
            new=discover_mock,
        ),
    ):
        response = client.get("/api/v1/domains/cloudflare/discover")

    test_app.dependency_overrides.clear()
    assert response.status_code == 403
    discover_mock.assert_not_awaited()
