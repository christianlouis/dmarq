"""Tests for Cloudflare DNS discovery, analysis, and change tracking."""

import asyncio
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.api.api_v1.endpoints.domains import _policy_enforcement_suggestions
from app.core.credential_encryption import encrypt_secret
from app.models.dns_cache import DNSRecordChange, DNSRecordSnapshot
from app.models.domain import Domain
from app.models.setting import Setting
from app.services import cloudflare_dns
from app.services.cloudflare_dns import analyze_dns_records, sync_dns_record_changes

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
        _record("dmarc", "TXT", f"_dmarc.{DOMAIN}", "v=DMARC1; rua=mailto:dmarc@example.com"),
        _record("spf", "TXT", DOMAIN, "v=spf1 include:_spf.google.com ~all"),
    ]

    result = analyze_dns_records(DOMAIN, records)

    assert "malformed_dmarc" in {item["type"] for item in result["suggestions"]}


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
    db_session.add(Domain(name=DOMAIN))
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

    assert zones == [
        {
            "id": "zone-1",
            "name": DOMAIN,
            "status": "active",
            "account_name": "Example",
            "imported": True,
        }
    ]


def test_import_cloudflare_domains_imports_requested_and_skips_others(db_session):
    db_session.add(Domain(name=DOMAIN))
    db_session.commit()

    async def fake_discover(_db):
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
    assert db_session.query(Domain).filter(Domain.name == "new.example").first() is not None


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


def test_cloudflare_discover_endpoint_returns_zones(client: TestClient):
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
        response = client.get("/api/v1/domains/cloudflare/discover")

    assert response.status_code == 200
    assert response.json()[0]["name"] == DOMAIN


def test_cloudflare_import_endpoint_returns_import_summary(client: TestClient):
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
        response = client.post(
            "/api/v1/domains/cloudflare/import",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 200
    assert response.json()["imported"] == [DOMAIN]


def test_cloudflare_dns_analysis_endpoint_persists_history(client: TestClient, db_session):
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
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns/cloudflare")

    assert response.status_code == 200
    data = response.json()
    assert data["zone"]["id"] == "zone-1"
    assert data["checks"]["dmarc_policy"] == "reject"
    assert len(data["changes"]) == 2
    assert len(data["history"]) == 2

    history_response = client.get(f"/api/v1/domains/{DOMAIN}/dns/history")
    assert history_response.status_code == 200
    assert len(history_response.json()["history"]) == 2


def test_cloudflare_dns_analysis_endpoint_returns_configuration_errors(client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.get_zone_for_domain",
        new=AsyncMock(side_effect=LookupError("Cloudflare API token is not configured")),
    ):
        response = client.get(f"/api/v1/domains/{DOMAIN}/dns/cloudflare")

    assert response.status_code == 400
    assert "Cloudflare API token" in response.json()["detail"]
