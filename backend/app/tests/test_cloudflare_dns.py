"""Tests for Cloudflare DNS discovery, analysis, and change tracking."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints import domains as domains_endpoint
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
from app.services import (
    cloudflare_dns,
    cloudflare_oauth,
    dns_provider_connectors,
    dns_provider_imports,
    dns_provider_writes,
    hetzner_dns,
    linode_dns,
    route53_dns,
)
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


class FakeHetznerDNSClient:
    def __init__(self, *, zones=None):
        self.zones = zones or []

    async def list_zones(self):
        return self.zones


class FakeLinodeDNSClient:
    def __init__(self, *, domains=None):
        self.domains = domains or []

    async def list_domains(self):
        return self.domains


class FakeRoute53DNSClient:
    def __init__(self, *, zones=None, account_name="Amazon Route 53"):
        self.zones = zones or []
        self.account_name = account_name

    async def list_zones(self):
        return self.zones


class FakeRoute53Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return self.pages


class FakeRoute53BotoClient:
    def __init__(self, *, pages=None, error=None):
        self.pages = pages or []
        self.error = error

    def get_paginator(self, name):
        assert name == "list_hosted_zones"
        if self.error:
            raise self.error
        return FakeRoute53Paginator(self.pages)


class FakeHetznerResponse:
    def __init__(self, payload=None, *, json_error=False, status_error=None):
        self.payload = payload or {}
        self.json_error = json_error
        self.status_error = status_error

    def raise_for_status(self):
        if self.status_error:
            raise self.status_error

    def json(self):
        if self.json_error:
            raise ValueError("bad json")
        return self.payload


class FakeLinodeResponse(FakeHetznerResponse):
    pass


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


def test_hetzner_dns_client_list_zones_paginates(monkeypatch):
    client = hetzner_dns.HetznerDNSClient(api_token="token")

    async def fake_get(path, *, params=None):
        assert path == "/zones"
        if params["page"] == 1:
            return {
                "zones": [{"id": 1, "name": DOMAIN}],
                "meta": {"pagination": {"next_page": 2, "last_page": 2}},
            }
        return {
            "zones": [{"id": 2, "name": "second.example"}],
            "meta": {"pagination": {"last_page": 2}},
        }

    monkeypatch.setattr(client, "_api_get", fake_get)

    zones = asyncio.run(client.list_zones())

    assert [zone["name"] for zone in zones] == [DOMAIN, "second.example"]


def test_hetzner_dns_client_headers_api_get_and_error_paths(monkeypatch):
    requests = []

    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, *, params=None, headers=None):
            requests.append({"url": url, "params": params, "headers": headers})
            return FakeHetznerResponse({"zones": []})

    monkeypatch.setattr(hetzner_dns.httpx, "AsyncClient", FakeAsyncClient)
    client = hetzner_dns.HetznerDNSClient(api_token="token", api_base="https://example.test/")

    result = asyncio.run(client._api_get("/zones", params={"page": 1}))

    assert result == {"zones": []}
    assert requests == [
        {
            "url": "https://example.test/zones",
            "params": {"page": 1},
            "headers": {"Authorization": "Bearer token", "Accept": "application/json"},
        }
    ]
    with pytest.raises(LookupError, match="not configured"):
        hetzner_dns.HetznerDNSClient(api_token=None)._headers()


def test_hetzner_dns_client_api_get_maps_invalid_json(monkeypatch):
    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, *, params=None, headers=None):
            return FakeHetznerResponse(json_error=True)

    monkeypatch.setattr(hetzner_dns.httpx, "AsyncClient", FakeAsyncClient)
    client = hetzner_dns.HetznerDNSClient(api_token="token")

    with pytest.raises(LookupError, match="invalid JSON"):
        asyncio.run(client._api_get("/zones"))


def test_hetzner_dns_client_list_zones_handles_alternate_pagination(monkeypatch):
    client = hetzner_dns.HetznerDNSClient(api_token="token")

    async def fake_get(path, *, params=None):
        assert path == "/zones"
        if params["page"] == 1:
            return {
                "data": [{"id": 1, "name": DOMAIN}],
                "pagination": {"last_page": 2},
            }
        return {
            "result": [{"id": 2, "name": "second.example"}],
            "pagination": {"last_page": 2},
        }

    monkeypatch.setattr(client, "_api_get", fake_get)

    zones = asyncio.run(client.list_zones())

    assert [zone["name"] for zone in zones] == [DOMAIN, "second.example"]


def test_hetzner_dns_client_list_zones_ignores_malformed_payload(monkeypatch):
    client = hetzner_dns.HetznerDNSClient(api_token="token")

    async def fake_get(path, *, params=None):
        return {"zones": "not-a-list"}

    monkeypatch.setattr(client, "_api_get", fake_get)

    assert asyncio.run(client.list_zones()) == []


def test_hetzner_dns_credentials_and_build_client(monkeypatch):
    monkeypatch.setattr(
        hetzner_dns,
        "get_settings",
        lambda: SimpleNamespace(HETZNER_DNS_API_TOKEN="", HETZNER_API_TOKEN="fallback"),
    )

    credentials = hetzner_dns.get_hetzner_dns_credentials()
    client = hetzner_dns.build_hetzner_dns_client()

    assert credentials.configured is True
    assert client.api_token == "fallback"

    monkeypatch.setattr(
        hetzner_dns,
        "get_settings",
        lambda: SimpleNamespace(HETZNER_DNS_API_TOKEN="", HETZNER_API_TOKEN=""),
    )
    assert hetzner_dns.get_hetzner_dns_credentials().configured is False
    with pytest.raises(LookupError, match="not configured"):
        hetzner_dns.build_hetzner_dns_client()


def test_linode_dns_client_list_domains_paginates(monkeypatch):
    client = linode_dns.LinodeDNSClient(api_token="token")

    async def fake_get(path, *, params=None):
        assert path == "/domains"
        assert params["page_size"] == linode_dns.LINODE_PAGE_SIZE
        if params["page"] == 1:
            return {
                "data": [{"id": 1, "domain": DOMAIN}],
                "pages": 2,
            }
        return {
            "data": [{"id": 2, "domain": "second.example"}],
            "pages": 2,
        }

    monkeypatch.setattr(client, "_api_get", fake_get)

    domains = asyncio.run(client.list_domains())

    assert [domain["domain"] for domain in domains] == [DOMAIN, "second.example"]


def test_linode_dns_client_headers_api_get_and_error_paths(monkeypatch):
    requests = []

    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, *, params=None, headers=None):
            requests.append({"url": url, "params": params, "headers": headers})
            return FakeLinodeResponse({"data": []})

    monkeypatch.setattr(linode_dns.httpx, "AsyncClient", FakeAsyncClient)
    client = linode_dns.LinodeDNSClient(api_token="token", api_base="https://example.test/")

    result = asyncio.run(client._api_get("/domains", params={"page": 1}))

    assert result == {"data": []}
    assert requests == [
        {
            "url": "https://example.test/domains",
            "params": {"page": 1},
            "headers": {"Authorization": "Bearer token", "Accept": "application/json"},
        }
    ]
    with pytest.raises(LookupError, match="not configured"):
        linode_dns.LinodeDNSClient(api_token=None)._headers()


def test_linode_dns_client_api_get_maps_invalid_json(monkeypatch):
    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, *, params=None, headers=None):
            return FakeLinodeResponse(json_error=True)

    monkeypatch.setattr(linode_dns.httpx, "AsyncClient", FakeAsyncClient)
    client = linode_dns.LinodeDNSClient(api_token="token")

    with pytest.raises(LookupError, match="invalid JSON"):
        asyncio.run(client._api_get("/domains"))


def test_linode_dns_client_list_domains_ignores_malformed_payload(monkeypatch):
    client = linode_dns.LinodeDNSClient(api_token="token")

    async def fake_get(path, *, params=None):
        return {"data": "not-a-list"}

    monkeypatch.setattr(client, "_api_get", fake_get)

    assert asyncio.run(client.list_domains()) == []


def test_linode_dns_credentials_and_build_client(monkeypatch):
    monkeypatch.setattr(
        linode_dns,
        "get_settings",
        lambda: SimpleNamespace(LINODE_API_TOKEN="", LINODE_TOKEN="fallback"),
    )

    credentials = linode_dns.get_linode_dns_credentials()
    client = linode_dns.build_linode_dns_client()

    assert credentials.configured is True
    assert client.api_token == "fallback"

    monkeypatch.setattr(
        linode_dns,
        "get_settings",
        lambda: SimpleNamespace(LINODE_API_TOKEN="", LINODE_TOKEN=""),
    )
    assert linode_dns.get_linode_dns_credentials().configured is False
    with pytest.raises(LookupError, match="not configured"):
        linode_dns.build_linode_dns_client()


def test_route53_dns_client_list_zones_uses_boto3_paginator():
    boto_client = FakeRoute53BotoClient(
        pages=[
            {"HostedZones": [{"Id": "/hostedzone/Z1", "Name": f"{DOMAIN}."}]},
            {
                "HostedZones": [
                    {
                        "Id": "/hostedzone/Z2",
                        "Name": "private.example.",
                        "Config": {"PrivateZone": True},
                    }
                ]
            },
        ]
    )
    client = route53_dns.Route53DNSClient(route53_client=boto_client)

    zones = asyncio.run(client.list_zones())

    assert [route53_dns.Route53DNSClient._zone_id(zone) for zone in zones] == ["Z1", "Z2"]
    assert route53_dns.Route53DNSClient._zone_name(zones[0]) == DOMAIN
    assert route53_dns.Route53DNSClient._zone_status(zones[0]) == "public"
    assert route53_dns.Route53DNSClient._zone_status(zones[1]) == "private"


def test_route53_dns_client_maps_provider_errors():
    client = route53_dns.Route53DNSClient(
        route53_client=FakeRoute53BotoClient(error=route53_dns.NoCredentialsError())
    )

    with pytest.raises(LookupError, match="hosted-zone listing failed"):
        asyncio.run(client.list_zones())


def test_route53_dns_credentials_and_build_client(monkeypatch):
    created_sessions = []

    class FakeSTSClient:
        def assume_role(self, **kwargs):
            assert kwargs == {
                "RoleArn": "arn:aws:iam::123456789012:role/dmarq",
                "RoleSessionName": route53_dns.ROUTE53_ROLE_SESSION_NAME,
                "ExternalId": "external-1",
            }
            return {
                "Credentials": {
                    "AccessKeyId": "akid",
                    "SecretAccessKey": "secret",
                    "SessionToken": "session",
                }
            }

    class FakeSession:
        def __init__(self, **kwargs):
            created_sessions.append(kwargs)

        def client(self, service_name, **kwargs):
            if service_name == "sts":
                return FakeSTSClient()
            assert service_name == "route53"
            assert kwargs["aws_access_key_id"] == "akid"
            return FakeRoute53BotoClient()

    monkeypatch.setattr(
        route53_dns,
        "get_settings",
        lambda: SimpleNamespace(
            AWS_PROFILE="fallback-profile",
            AWS_REGION="eu-central-1",
            DMARQ_ROUTE53_PROFILE="route53-profile",
            DMARQ_ROUTE53_ROLE_ARN="arn:aws:iam::123456789012:role/dmarq",
            DMARQ_ROUTE53_EXTERNAL_ID="external-1",
        ),
    )
    monkeypatch.setattr(route53_dns, "boto3", SimpleNamespace(Session=FakeSession))

    credentials = route53_dns.get_route53_dns_credentials()
    client = route53_dns.build_route53_dns_client()

    assert credentials.profile_name == "route53-profile"
    assert credentials.configured is True
    assert created_sessions == [{"profile_name": "route53-profile", "region_name": "eu-central-1"}]
    assert client.account_name == "Route 53 role dmarq"


def test_route53_dns_credentials_detect_full_container_credentials(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.23/credentials")
    credentials = route53_dns.Route53DNSCredentials()

    assert credentials.configured is True


def test_discover_hetzner_zones_marks_imported_and_filters_invalid(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add(Domain(name=DOMAIN, workspace_id=workspace.id))
    db_session.commit()
    client = FakeHetznerDNSClient(
        zones=[
            {"id": 1, "name": f"{DOMAIN}.", "mode": "primary"},
            {"id": 2, "name": "new.example", "status": "active"},
            {"id": None, "name": "invalid.example"},
            {"id": 3, "name": ""},
        ]
    )

    with patch("app.services.hetzner_dns.build_hetzner_dns_client", return_value=client):
        zones = asyncio.run(
            hetzner_dns.discover_hetzner_zones(db_session, workspace_id=workspace.id)
        )

    assert zones == [
        {
            "id": "1",
            "name": DOMAIN,
            "status": "primary",
            "account_name": "Hetzner DNS",
            "imported": True,
        },
        {
            "id": "2",
            "name": "new.example",
            "status": "active",
            "account_name": "Hetzner DNS",
            "imported": False,
        },
    ]


def test_discover_hetzner_zones_scopes_default_workspace_import_state(db_session):
    default_workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(slug="hetzner-other", name="Hetzner Other", active=True)
    db_session.add(other_workspace)
    db_session.commit()
    db_session.add(Domain(name=DOMAIN, workspace_id=other_workspace.id))
    db_session.commit()
    client = FakeHetznerDNSClient(zones=[{"id": 1, "name": DOMAIN}])

    with patch("app.services.hetzner_dns.build_hetzner_dns_client", return_value=client):
        zones = asyncio.run(hetzner_dns.discover_hetzner_zones(db_session))

    assert default_workspace.id != other_workspace.id
    assert zones[0]["imported"] is False


def test_discover_linode_domains_marks_imported_and_filters_invalid(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add(Domain(name=DOMAIN, workspace_id=workspace.id))
    db_session.commit()
    client = FakeLinodeDNSClient(
        domains=[
            {"id": 1, "domain": f"{DOMAIN}.", "type": "master"},
            {"id": 2, "domain": "New.EXAMPLE", "type": "slave"},
            {"id": None, "domain": "invalid.example"},
            {"id": 3, "domain": ""},
        ]
    )

    with patch("app.services.linode_dns.build_linode_dns_client", return_value=client):
        domains = asyncio.run(
            linode_dns.discover_linode_domains(db_session, workspace_id=workspace.id)
        )

    assert domains == [
        {
            "id": "1",
            "name": DOMAIN,
            "status": "master",
            "account_name": "Linode DNS",
            "imported": True,
        },
        {
            "id": "2",
            "name": "new.example",
            "status": "slave",
            "account_name": "Linode DNS",
            "imported": False,
        },
    ]


def test_discover_linode_domains_scopes_default_workspace_import_state(db_session):
    default_workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(slug="linode-other", name="Linode Other", active=True)
    db_session.add(other_workspace)
    db_session.commit()
    db_session.add(Domain(name=DOMAIN, workspace_id=other_workspace.id))
    db_session.commit()
    client = FakeLinodeDNSClient(domains=[{"id": 1, "domain": DOMAIN}])

    with patch("app.services.linode_dns.build_linode_dns_client", return_value=client):
        domains = asyncio.run(linode_dns.discover_linode_domains(db_session))

    assert default_workspace.id != other_workspace.id
    assert domains[0]["imported"] is False


def test_discover_route53_zones_marks_imported_and_filters_invalid(db_session):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add(Domain(name=DOMAIN, workspace_id=workspace.id))
    db_session.commit()
    client = FakeRoute53DNSClient(
        zones=[
            {"Id": "/hostedzone/Z1", "Name": f"{DOMAIN}.", "Config": {"PrivateZone": False}},
            {"Id": "/hostedzone/Z2", "Name": "private.example.", "Config": {"PrivateZone": True}},
            {"Id": None, "Name": "invalid.example."},
            {"Id": "/hostedzone/Z3", "Name": ""},
        ],
        account_name="route53-profile",
    )

    with patch("app.services.route53_dns.build_route53_dns_client", return_value=client):
        zones = asyncio.run(
            route53_dns.discover_route53_zones(db_session, workspace_id=workspace.id)
        )

    assert zones == [
        {
            "id": "Z1",
            "name": DOMAIN,
            "status": "public",
            "account_name": "route53-profile",
            "imported": True,
        },
        {
            "id": "Z2",
            "name": "private.example",
            "status": "private",
            "account_name": "route53-profile",
            "imported": False,
        },
    ]


def test_discover_route53_zones_scopes_default_workspace_import_state(db_session):
    default_workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(slug="route53-other", name="Route53 Other", active=True)
    db_session.add(other_workspace)
    db_session.commit()
    db_session.add(Domain(name=DOMAIN, workspace_id=other_workspace.id))
    db_session.commit()
    client = FakeRoute53DNSClient(zones=[{"Id": "/hostedzone/Z1", "Name": f"{DOMAIN}."}])

    with patch("app.services.route53_dns.build_route53_dns_client", return_value=client):
        zones = asyncio.run(route53_dns.discover_route53_zones(db_session))

    assert default_workspace.id != other_workspace.id
    assert zones[0]["imported"] is False


def test_import_hetzner_domains_imports_requested_and_skips_others(db_session):
    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "zone-1", "name": DOMAIN, "imported": False},
            {"id": "zone-2", "name": "skip.example", "imported": False},
        ]

    with patch("app.services.hetzner_dns.discover_hetzner_zones", new=fake_discover):
        result = asyncio.run(
            hetzner_dns.import_hetzner_domains(
                db_session,
                requested_domains=[f"{DOMAIN}."],
            )
        )

    assert result["imported"] == [DOMAIN]
    assert result["existing"] == []
    assert result["skipped"] == ["skip.example"]
    imported = db_session.query(Domain).filter(Domain.name == DOMAIN).first()
    assert imported is not None
    assert imported.verified is True
    assert imported.description == "DNS-discovered from Hetzner DNS zone import"


def test_import_hetzner_domains_treats_global_duplicate_as_existing(db_session):
    workspace = Workspace(slug="hetzner-target", name="Hetzner Target")
    db_session.add(workspace)
    db_session.add(Domain(name=DOMAIN, workspace_id=None))
    db_session.commit()

    async def fake_discover(_db, workspace_id=None):
        assert workspace_id == workspace.id
        return [{"id": "zone-1", "name": DOMAIN, "imported": False}]

    with patch("app.services.hetzner_dns.discover_hetzner_zones", new=fake_discover):
        result = asyncio.run(
            hetzner_dns.import_hetzner_domains(
                db_session,
                requested_domains=[DOMAIN],
                workspace_id=workspace.id,
            )
        )

    assert result["imported"] == []
    assert result["existing"] == [DOMAIN]
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).count() == 1


def test_import_hetzner_domains_empty_selection_imports_nothing(db_session):
    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "zone-1", "name": DOMAIN, "imported": False},
            {"id": "zone-2", "name": "skip.example", "imported": False},
        ]

    with patch("app.services.hetzner_dns.discover_hetzner_zones", new=fake_discover):
        result = asyncio.run(
            hetzner_dns.import_hetzner_domains(
                db_session,
                requested_domains=[],
            )
        )

    assert result["imported"] == []
    assert result["existing"] == []
    assert sorted(result["skipped"]) == [DOMAIN, "skip.example"]
    assert db_session.query(Domain).filter(Domain.name.in_([DOMAIN, "skip.example"])).count() == 0


def test_import_hetzner_domains_reports_globally_existing_domain(db_session):
    other_workspace = Workspace(slug="hetzner-existing", name="Hetzner Existing", active=True)
    db_session.add(other_workspace)
    db_session.commit()
    db_session.add(Domain(name=DOMAIN, workspace_id=other_workspace.id))
    db_session.commit()

    async def fake_discover(_db, workspace_id=None):
        return [{"id": "zone-1", "name": DOMAIN, "imported": False}]

    with patch("app.services.hetzner_dns.discover_hetzner_zones", new=fake_discover):
        result = asyncio.run(hetzner_dns.import_hetzner_domains(db_session))

    assert result["imported"] == []
    assert result["existing"] == [DOMAIN]
    assert result["skipped"] == []
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).count() == 1


def test_import_linode_domains_imports_requested_and_skips_others(db_session):
    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "1", "name": DOMAIN, "imported": False},
            {"id": "2", "name": "skip.example", "imported": False},
        ]

    with patch("app.services.linode_dns.discover_linode_domains", new=fake_discover):
        result = asyncio.run(
            linode_dns.import_linode_domains(
                db_session,
                requested_domains=[f"{DOMAIN}."],
            )
        )

    assert result["imported"] == [DOMAIN]
    assert result["existing"] == []
    assert result["skipped"] == ["skip.example"]
    imported = db_session.query(Domain).filter(Domain.name == DOMAIN).first()
    assert imported is not None
    assert imported.verified is True
    assert imported.description == "DNS-discovered from Linode DNS domain import"


def test_import_linode_domains_reports_globally_existing_and_deduplicates(db_session):
    other_workspace = Workspace(slug="linode-existing", name="Linode Existing", active=True)
    db_session.add(other_workspace)
    db_session.commit()
    db_session.add(Domain(name=DOMAIN, workspace_id=other_workspace.id))
    db_session.commit()

    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "1", "name": DOMAIN, "imported": False},
            {"id": "2", "name": DOMAIN, "imported": False},
            {"id": "3", "name": "new.example", "imported": False},
        ]

    with patch("app.services.linode_dns.discover_linode_domains", new=fake_discover):
        result = asyncio.run(linode_dns.import_linode_domains(db_session))

    assert result["imported"] == ["new.example"]
    assert result["existing"] == [DOMAIN]
    assert result["skipped"] == []
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).count() == 1
    assert db_session.query(Domain).filter(Domain.name == "new.example").count() == 1


def test_import_route53_domains_imports_requested_and_skips_others(db_session):
    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "Z1", "name": DOMAIN, "imported": False},
            {"id": "Z2", "name": "skip.example", "imported": False},
        ]

    with patch("app.services.route53_dns.discover_route53_zones", new=fake_discover):
        result = asyncio.run(
            route53_dns.import_route53_domains(
                db_session,
                requested_domains=[f"{DOMAIN}."],
            )
        )

    assert result["imported"] == [DOMAIN]
    assert result["existing"] == []
    assert result["skipped"] == ["skip.example"]
    imported = db_session.query(Domain).filter(Domain.name == DOMAIN).first()
    assert imported is not None
    assert imported.verified is True
    assert imported.description == "DNS-discovered from Route 53 hosted-zone import"


def test_import_route53_domains_treats_global_duplicate_as_existing(db_session):
    workspace = Workspace(slug="route53-target", name="Route53 Target")
    db_session.add(workspace)
    db_session.add(Domain(name=DOMAIN, workspace_id=None))
    db_session.commit()

    async def fake_discover(_db, workspace_id=None):
        assert workspace_id == workspace.id
        return [{"id": "Z1", "name": DOMAIN, "imported": False}]

    with patch("app.services.route53_dns.discover_route53_zones", new=fake_discover):
        result = asyncio.run(
            route53_dns.import_route53_domains(
                db_session,
                requested_domains=[DOMAIN],
                workspace_id=workspace.id,
            )
        )

    assert result["imported"] == []
    assert result["existing"] == [DOMAIN]
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).count() == 1


def test_import_route53_domains_empty_selection_imports_nothing(db_session):
    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "Z1", "name": DOMAIN, "imported": False},
            {"id": "Z2", "name": "skip.example", "imported": False},
        ]

    with patch("app.services.route53_dns.discover_route53_zones", new=fake_discover):
        result = asyncio.run(
            route53_dns.import_route53_domains(
                db_session,
                requested_domains=[],
            )
        )

    assert result["imported"] == []
    assert result["existing"] == []
    assert sorted(result["skipped"]) == [DOMAIN, "skip.example"]
    assert db_session.query(Domain).filter(Domain.name.in_([DOMAIN, "skip.example"])).count() == 0


def test_import_route53_domains_reports_globally_existing_domain(db_session):
    other_workspace = Workspace(slug="route53-existing", name="Route53 Existing", active=True)
    db_session.add(other_workspace)
    db_session.commit()
    db_session.add(Domain(name=DOMAIN, workspace_id=other_workspace.id))
    db_session.commit()

    async def fake_discover(_db, workspace_id=None):
        return [{"id": "Z1", "name": DOMAIN, "imported": False}]

    with patch("app.services.route53_dns.discover_route53_zones", new=fake_discover):
        result = asyncio.run(route53_dns.import_route53_domains(db_session))

    assert result["imported"] == []
    assert result["existing"] == [DOMAIN]
    assert result["skipped"] == []
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).count() == 1


def test_import_route53_domains_deduplicates_hosted_zone_names(db_session):
    async def fake_discover(_db, workspace_id=None):
        return [
            {"id": "Z1", "name": DOMAIN, "imported": False},
            {"id": "Z2", "name": DOMAIN, "imported": False},
        ]

    with patch("app.services.route53_dns.discover_route53_zones", new=fake_discover):
        result = asyncio.run(route53_dns.import_route53_domains(db_session))

    assert result["imported"] == [DOMAIN]
    assert result["existing"] == []
    assert result["skipped"] == []
    assert db_session.query(Domain).filter(Domain.name == DOMAIN).count() == 1


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


def test_dns_provider_import_preview_wraps_hetzner_zones(db_session):
    async def fake_discover(_db, workspace_id=None):
        assert workspace_id == 123
        return [
            {
                "id": "zone-1",
                "name": DOMAIN,
                "status": "primary",
                "account_name": "Hetzner DNS",
                "imported": False,
            }
        ]

    with patch("app.services.dns_provider_imports.discover_hetzner_zones", new=fake_discover):
        result = asyncio.run(
            dns_provider_imports.preview_dns_provider_import(
                db_session,
                provider="hetzner",
                workspace_id=123,
            )
        )

    assert result["provider"] == "hetzner"
    assert result["provider_name"] == "Hetzner DNS"
    assert result["total_discovered"] == 1
    assert result["importable_count"] == 1
    assert result["zones"][0]["domain"] == DOMAIN
    assert "Hetzner DNS zone" in result["zones"][0]["next_action"]


def test_dns_provider_import_preview_wraps_linode_domains(db_session):
    async def fake_discover(_db, workspace_id=None):
        assert workspace_id == 123
        return [
            {
                "id": "1",
                "name": DOMAIN,
                "status": "master",
                "account_name": "Linode DNS",
                "imported": False,
            }
        ]

    with patch("app.services.dns_provider_imports.discover_linode_domains", new=fake_discover):
        result = asyncio.run(
            dns_provider_imports.preview_dns_provider_import(
                db_session,
                provider="linode",
                workspace_id=123,
            )
        )

    assert result["provider"] == "linode"
    assert result["provider_name"] == "Linode DNS"
    assert result["total_discovered"] == 1
    assert result["importable_count"] == 1
    assert result["zones"][0]["domain"] == DOMAIN
    assert "Linode DNS domain" in result["zones"][0]["next_action"]


def test_dns_provider_import_preview_wraps_route53_zones(db_session):
    async def fake_discover(_db, workspace_id=None):
        assert workspace_id == 123
        return [
            {
                "id": "Z1",
                "name": DOMAIN,
                "status": "public",
                "account_name": "route53-profile",
                "imported": False,
            }
        ]

    with patch("app.services.dns_provider_imports.discover_route53_zones", new=fake_discover):
        result = asyncio.run(
            dns_provider_imports.preview_dns_provider_import(
                db_session,
                provider="route53",
                workspace_id=123,
            )
        )

    assert result["provider"] == "route53"
    assert result["provider_name"] == "Amazon Route 53"
    assert result["total_discovered"] == 1
    assert result["importable_count"] == 1
    assert result["zones"][0]["domain"] == DOMAIN
    assert "Amazon Route 53 zone" in result["zones"][0]["next_action"]


def test_dns_provider_import_apply_wraps_hetzner_import(db_session):
    async def fake_import(_db, requested_domains=None, workspace_id=None):
        assert requested_domains == [DOMAIN]
        assert workspace_id == 456
        return {
            "imported": [DOMAIN],
            "existing": [],
            "skipped": [],
            "total_discovered": 1,
        }

    with patch("app.services.dns_provider_imports.import_hetzner_domains", new=fake_import):
        result = asyncio.run(
            dns_provider_imports.import_dns_provider_domains(
                db_session,
                provider="hetzner",
                requested_domains=[DOMAIN],
                workspace_id=456,
            )
        )

    assert result["provider"] == "hetzner"
    assert result["provider_name"] == "Hetzner DNS"
    assert result["imported"] == [DOMAIN]


def test_dns_provider_import_apply_wraps_linode_import(db_session):
    async def fake_import(_db, requested_domains=None, workspace_id=None):
        assert requested_domains == [DOMAIN]
        assert workspace_id == 456
        return {
            "imported": [DOMAIN],
            "existing": [],
            "skipped": [],
            "total_discovered": 1,
        }

    with patch("app.services.dns_provider_imports.import_linode_domains", new=fake_import):
        result = asyncio.run(
            dns_provider_imports.import_dns_provider_domains(
                db_session,
                provider="linode",
                requested_domains=[DOMAIN],
                workspace_id=456,
            )
        )

    assert result["provider"] == "linode"
    assert result["provider_name"] == "Linode DNS"
    assert result["imported"] == [DOMAIN]


def test_dns_provider_import_apply_wraps_route53_import(db_session):
    async def fake_import(_db, requested_domains=None, workspace_id=None):
        assert requested_domains == [DOMAIN]
        assert workspace_id == 456
        return {
            "imported": [DOMAIN],
            "existing": [],
            "skipped": [],
            "total_discovered": 1,
        }

    with patch("app.services.dns_provider_imports.import_route53_domains", new=fake_import):
        result = asyncio.run(
            dns_provider_imports.import_dns_provider_domains(
                db_session,
                provider="route53",
                requested_domains=[DOMAIN],
                workspace_id=456,
            )
        )

    assert result["provider"] == "route53"
    assert result["provider_name"] == "Amazon Route 53"
    assert result["imported"] == [DOMAIN]


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
    assert providers["cloudflare"]["zone_import_status"] == "ready"
    assert providers["cloudflare"]["record_read_status"] == "ready"
    assert providers["cloudflare"]["record_write_status"] == "ready"
    assert "Zone:Read" in providers["cloudflare"]["minimum_permissions"]
    assert providers["hetzner"]["import_available"] is True
    assert providers["hetzner"]["zone_import_status"] == "ready"
    assert providers["hetzner"]["record_read_status"] == "planned"
    assert providers["hetzner"]["record_write_status"] == "lexicon_available"
    assert "api_token" in providers["hetzner"]["auth_models"]
    assert providers["route53"]["import_available"] is True
    assert providers["route53"]["zone_import_status"] == "ready"
    assert "iam_role_external_id" in providers["route53"]["auth_models"]
    assert providers["linode"]["import_available"] is True
    assert providers["linode"]["zone_import_status"] == "ready"
    assert providers["linode"]["record_write_status"] == "lexicon_available"
    assert "personal_access_token" in providers["linode"]["auth_models"]


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


def _cloudflare_oauth_settings(**overrides):
    defaults = {
        "SECRET_KEY": "s" * 32,
        "CLOUDFLARE_OAUTH_CLIENT_ID": "client-id",
        "CLOUDFLARE_OAUTH_CLIENT_SECRET": "client-secret",
        "CLOUDFLARE_OAUTH_SCOPES": "zone.read dns.read",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _cloudflare_oauth_zone_read_settings():
    return _cloudflare_oauth_settings(CLOUDFLARE_OAUTH_SCOPES="zone.read")


def _cloudflare_oauth_empty_scope_settings():
    return _cloudflare_oauth_settings(CLOUDFLARE_OAUTH_SCOPES="")


def _cloudflare_oauth_missing_credential_settings():
    return _cloudflare_oauth_settings(
        CLOUDFLARE_OAUTH_CLIENT_ID="",
        CLOUDFLARE_OAUTH_CLIENT_SECRET="",
    )


def _encrypted_secret(value):
    return f"encrypted:{value}"


def _cloudflare_provider_factory(provider):
    def build_provider(_db):
        return provider

    return build_provider


def test_cloudflare_oauth_state_round_trips_and_sanitizes_return_to(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_settings)

    state = cloudflare_oauth.build_cloudflare_oauth_state(
        workspace_id=42,
        return_to="https://evil.example/settings",
    )
    scheme_relative_state = cloudflare_oauth.build_cloudflare_oauth_state(
        workspace_id=42,
        return_to="//evil.example/settings",
    )

    assert state.startswith("v1.")
    assert cloudflare_oauth.decode_cloudflare_oauth_state(state) == {
        "workspace_id": 42,
        "return_to": "/settings",
    }
    assert cloudflare_oauth.decode_cloudflare_oauth_state(scheme_relative_state) == {
        "workspace_id": 42,
        "return_to": "/settings",
    }
    with pytest.raises(LookupError, match="Invalid Cloudflare OAuth state"):
        cloudflare_oauth.decode_cloudflare_oauth_state("not-a-valid-token")


def test_cloudflare_oauth_authorization_url_uses_configured_scopes(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_zone_read_settings)

    result = cloudflare_oauth.build_cloudflare_authorization_url(
        redirect_uri="https://app.example.test/api/v1/domains/cloudflare/oauth/callback",
        state="state-token",
    )

    assert result["redirect_uri"].endswith("/cloudflare/oauth/callback")
    assert result["scopes"] == "zone.read"
    assert result["authorization_url"].startswith("https://dash.cloudflare.com/oauth2/auth?")
    assert "client_id=client-id" in result["authorization_url"]
    assert "scope=zone.read" in result["authorization_url"]
    assert "state=state-token" in result["authorization_url"]


def test_cloudflare_oauth_config_defaults_to_read_scopes(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_empty_scope_settings)

    assert (
        cloudflare_oauth.get_cloudflare_oauth_config().scopes
        == cloudflare_oauth.CLOUDFLARE_DEFAULT_READ_SCOPES
    )


def test_cloudflare_oauth_config_requires_client_credentials(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        cloudflare_oauth,
        "get_settings",
        _cloudflare_oauth_missing_credential_settings,
    )

    assert cloudflare_oauth.cloudflare_oauth_configured() is False
    with pytest.raises(LookupError, match="Cloudflare OAuth is not configured"):
        cloudflare_oauth.get_cloudflare_oauth_config()


def test_cloudflare_oauth_decode_rejects_state_without_workspace(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_settings)
    token = cloudflare_oauth.jwt.encode(
        {"return_to": "/settings"},
        "s" * 32 + ":cloudflare-oauth-state",
        algorithm="HS256",
    )

    with pytest.raises(LookupError, match="Invalid Cloudflare OAuth state"):
        cloudflare_oauth.decode_cloudflare_oauth_state(f"v1.{token}")


@pytest.mark.asyncio
async def test_cloudflare_oauth_exchange_posts_token_request(
    monkeypatch: pytest.MonkeyPatch,
):
    requests = []
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_settings)

    class FakeTokenResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"access_token": "provider-token", "scope": "zone.read dns.read"}

    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, *, data):
            requests.append({"url": url, "data": data})
            return FakeTokenResponse()

    monkeypatch.setattr(cloudflare_oauth.httpx, "AsyncClient", FakeAsyncClient)

    token_data = await cloudflare_oauth.exchange_cloudflare_oauth_code(
        code="oauth-code",
        redirect_uri="https://app.example.test/api/v1/domains/cloudflare/oauth/callback",
    )

    assert token_data["access_token"] == "provider-token"
    assert requests == [
        {
            "url": cloudflare_oauth.CLOUDFLARE_TOKEN_URL,
            "data": {
                "grant_type": "authorization_code",
                "code": "oauth-code",
                "redirect_uri": (
                    "https://app.example.test/api/v1/domains/cloudflare/oauth/callback"
                ),
                "client_id": "client-id",
                "client_secret": "client-secret",
            },
        }
    ]


@pytest.mark.asyncio
async def test_cloudflare_oauth_exchange_rejects_missing_access_token(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_settings)

    class FakeTokenResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"scope": "zone.read"}

    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, *, data):
            return FakeTokenResponse()

    monkeypatch.setattr(cloudflare_oauth.httpx, "AsyncClient", FakeAsyncClient)

    with pytest.raises(LookupError, match="did not return an access token"):
        await cloudflare_oauth.exchange_cloudflare_oauth_code(
            code="oauth-code",
            redirect_uri="https://app.example.test/api/v1/domains/cloudflare/oauth/callback",
        )


@pytest.mark.asyncio
async def test_cloudflare_oauth_exchange_wraps_http_errors(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_settings)

    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, *, data):
            raise cloudflare_oauth.httpx.RequestError("network unavailable")

    monkeypatch.setattr(cloudflare_oauth.httpx, "AsyncClient", FakeAsyncClient)

    with pytest.raises(LookupError, match="token exchange failed"):
        await cloudflare_oauth.exchange_cloudflare_oauth_code(
            code="oauth-code",
            redirect_uri="https://app.example.test/api/v1/domains/cloudflare/oauth/callback",
        )


def test_persist_cloudflare_oauth_tokens_stores_encrypted_provider_token(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "encrypt_secret", _encrypted_secret)

    cloudflare_oauth.persist_cloudflare_oauth_tokens(
        db_session,
        {"access_token": "provider-token", "scope": "zone.read dns.read"},
    )

    settings = {
        row.key: row.value
        for row in db_session.query(Setting)
        .filter(
            Setting.key.in_(
                [
                    "cloudflare.api_token",
                    "cloudflare.auth_mode",
                    "cloudflare.oauth_scopes",
                    "cloudflare.oauth_connected_at",
                ]
            )
        )
        .all()
    }
    assert settings["cloudflare.api_token"] == "encrypted:provider-token"
    assert settings["cloudflare.api_token"] != "provider-token"
    assert settings["cloudflare.auth_mode"] == "oauth"
    assert settings["cloudflare.oauth_scopes"] == "zone.read dns.read"
    assert settings["cloudflare.oauth_connected_at"]


def test_persist_cloudflare_oauth_tokens_requires_access_token(
    db_session: Session,
):
    with pytest.raises(LookupError, match="did not return an access token"):
        cloudflare_oauth.persist_cloudflare_oauth_tokens(db_session, {})


def test_persist_cloudflare_oauth_tokens_defaults_to_configured_scopes(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cloudflare_oauth, "encrypt_secret", _encrypted_secret)
    monkeypatch.setattr(cloudflare_oauth, "get_settings", _cloudflare_oauth_zone_read_settings)

    cloudflare_oauth.persist_cloudflare_oauth_tokens(
        db_session,
        {"access_token": "provider-token"},
    )

    scope = db_session.query(Setting).filter(Setting.key == "cloudflare.oauth_scopes").first()
    assert scope.value == "zone.read"


def test_persist_cloudflare_oauth_tokens_updates_existing_settings(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    db_session.add(
        Setting(
            key="cloudflare.auth_mode",
            value="token",
            category="legacy",
            value_type="secret",
            description="old mode",
        )
    )
    db_session.commit()
    monkeypatch.setattr(cloudflare_oauth, "encrypt_secret", _encrypted_secret)

    cloudflare_oauth.persist_cloudflare_oauth_tokens(
        db_session,
        {"access_token": "provider-token", "scope": "zone.read"},
    )

    auth_mode = db_session.query(Setting).filter(Setting.key == "cloudflare.auth_mode").one()
    assert auth_mode.value == "oauth"
    assert auth_mode.category == "cloudflare"
    assert auth_mode.value_type == "string"
    assert auth_mode.description == "Cloudflare connector authentication mode"


def test_cloudflare_oauth_authorize_url_endpoint_returns_redirect(
    authed_client: TestClient,
):
    with (
        patch(
            "app.api.api_v1.endpoints.domains.build_cloudflare_oauth_state",
            return_value="state-token",
        ) as state_mock,
        patch(
            "app.api.api_v1.endpoints.domains.build_cloudflare_authorization_url",
            return_value={
                "authorization_url": "https://dash.cloudflare.com/oauth2/auth?state=state-token",
                "redirect_uri": "https://app.example.test/api/v1/domains/cloudflare/oauth/callback",
                "scopes": "zone.read dns.read",
            },
        ) as authorize_mock,
    ):
        response = authed_client.get(
            "/api/v1/domains/cloudflare/oauth/authorize-url?return_to=/settings",
            headers={"x-forwarded-proto": "https", "host": "app.example.test"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["authorization_url"].startswith("https://dash.cloudflare.com/oauth2/auth")
    assert data["scopes"] == "zone.read dns.read"
    state_mock.assert_called_once()
    authorize_mock.assert_called_once()
    assert authorize_mock.call_args.kwargs["redirect_uri"] == (
        "https://app.example.test/api/v1/domains/cloudflare/oauth/callback"
    )


def test_cloudflare_oauth_authorize_url_endpoint_returns_setup_error(
    authed_client: TestClient,
):
    with patch(
        "app.api.api_v1.endpoints.domains.build_cloudflare_authorization_url",
        side_effect=LookupError("Cloudflare OAuth is not configured."),
    ):
        response = authed_client.get("/api/v1/domains/cloudflare/oauth/authorize-url")

    assert response.status_code == 400
    assert response.json()["detail"] == "Cloudflare OAuth is not configured."


def test_cloudflare_oauth_callback_requires_code_and_state(
    authed_client: TestClient,
):
    response = authed_client.get("/api/v1/domains/cloudflare/oauth/callback?state=state-token")

    assert response.status_code == 400
    assert "Cloudflare connection failed" in response.text


def test_cloudflare_oauth_callback_returns_failure_for_invalid_state(
    authed_client: TestClient,
):
    with patch(
        "app.api.api_v1.endpoints.domains.decode_cloudflare_oauth_state",
        side_effect=LookupError("Invalid Cloudflare OAuth state."),
    ):
        response = authed_client.get(
            "/api/v1/domains/cloudflare/oauth/callback?code=oauth-code&state=bad-state"
        )

    assert response.status_code == 400
    assert "retry after checking the connector settings" in response.text


def test_cloudflare_oauth_callback_stores_token_and_redirects(
    authed_client: TestClient,
    db_session: Session,
):
    workspace = get_or_create_default_workspace(db_session)
    exchange_mock = AsyncMock(return_value={"access_token": "provider-token"})

    with (
        patch(
            "app.api.api_v1.endpoints.domains.decode_cloudflare_oauth_state",
            return_value={"workspace_id": workspace.id, "return_to": "/settings/cloudflare"},
        ) as decode_mock,
        patch(
            "app.api.api_v1.endpoints.domains.exchange_cloudflare_oauth_code",
            exchange_mock,
        ),
        patch("app.api.api_v1.endpoints.domains.persist_cloudflare_oauth_tokens") as persist_mock,
    ):
        response = authed_client.get(
            "/api/v1/domains/cloudflare/oauth/callback?code=oauth-code&state=state-token",
            headers={"x-forwarded-proto": "https", "host": "app.example.test"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/settings/cloudflare"
    decode_mock.assert_called_once_with("state-token")
    exchange_mock.assert_awaited_once_with(
        code="oauth-code",
        redirect_uri="https://app.example.test/api/v1/domains/cloudflare/oauth/callback",
    )
    persist_mock.assert_called_once_with(db_session, {"access_token": "provider-token"})


def test_cloudflare_oauth_status_endpoint_reports_connected_token(
    authed_client: TestClient,
    db_session: Session,
):
    db_session.add(
        Setting(
            key="cloudflare.api_token",
            value="encrypted-token",
            category="cloudflare",
            value_type="string",
        )
    )
    db_session.add(
        Setting(
            key="cloudflare.auth_mode",
            value="oauth",
            category="cloudflare",
            value_type="string",
        )
    )
    db_session.add(
        Setting(
            key="cloudflare.oauth_scopes",
            value="zone.read dns.read",
            category="cloudflare",
            value_type="string",
        )
    )
    db_session.commit()

    with patch("app.api.api_v1.endpoints.domains.cloudflare_oauth_configured", return_value=True):
        response = authed_client.get("/api/v1/domains/cloudflare/oauth/status")

    assert response.status_code == 200
    assert response.json() == {
        "oauth_configured": True,
        "connected": True,
        "auth_mode": "oauth",
        "scopes": "zone.read dns.read",
        "connected_at": None,
    }


@pytest.mark.asyncio
async def test_verify_cloudflare_domain_ownership_marks_domain_verified(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    workspace = get_or_create_default_workspace(db_session)
    domain = Domain(name=DOMAIN, workspace_id=workspace.id, verified=False, active=True)
    db_session.add(domain)
    db_session.commit()

    provider = FakeCloudflareProvider(
        zones=[
            {
                "id": "zone-1",
                "name": DOMAIN,
                "status": "active",
                "account": {"name": "Example Account"},
            }
        ]
    )
    monkeypatch.setattr(
        cloudflare_dns,
        "build_cloudflare_provider",
        _cloudflare_provider_factory(provider),
    )

    result = await cloudflare_dns.verify_cloudflare_domain_ownership(
        db_session,
        domain_name=DOMAIN,
        workspace_id=workspace.id,
    )

    db_session.refresh(domain)
    assert result["verified"] is True
    assert result["zone_id"] == "zone-1"
    assert result["account_name"] == "Example Account"
    assert domain.verified is True


@pytest.mark.asyncio
async def test_verify_cloudflare_domain_ownership_rejects_missing_zone(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    provider = FakeCloudflareProvider(zones=[])
    monkeypatch.setattr(
        cloudflare_dns,
        "build_cloudflare_provider",
        _cloudflare_provider_factory(provider),
    )

    with pytest.raises(LookupError, match="No Cloudflare zone visible"):
        await cloudflare_dns.verify_cloudflare_domain_ownership(
            db_session,
            domain_name=DOMAIN,
            workspace_id=1,
        )


@pytest.mark.asyncio
async def test_verify_cloudflare_domain_ownership_requires_monitored_domain(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    provider = FakeCloudflareProvider(zones=[{"id": "zone-1", "name": DOMAIN}])
    monkeypatch.setattr(
        cloudflare_dns,
        "build_cloudflare_provider",
        _cloudflare_provider_factory(provider),
    )

    with pytest.raises(LookupError, match="is not monitored"):
        await cloudflare_dns.verify_cloudflare_domain_ownership(
            db_session,
            domain_name=DOMAIN,
            workspace_id=1,
        )


@pytest.mark.asyncio
async def test_verify_cloudflare_domain_ownership_requires_domain_name(
    db_session: Session,
):
    with pytest.raises(LookupError, match="Domain name is required"):
        await cloudflare_dns.verify_cloudflare_domain_ownership(
            db_session,
            domain_name=" ",
            workspace_id=1,
        )


def test_cloudflare_ownership_endpoint_returns_provider_proof(
    authed_client: TestClient,
    db_session: Session,
):
    workspace = get_or_create_default_workspace(db_session)
    db_session.add(Domain(name=DOMAIN, workspace_id=workspace.id, verified=False, active=True))
    db_session.commit()
    ownership_result = {
        "domain": DOMAIN,
        "verified": True,
        "provider": "cloudflare",
        "zone_id": "zone-1",
        "zone_name": DOMAIN,
        "zone_status": "active",
        "account_name": "Example Account",
        "proof_reason": "DMARQ can see this domain as a Cloudflare zone.",
        "next_steps": ["Review the imported Cloudflare zones."],
    }

    verify_mock = AsyncMock(return_value=ownership_result)
    with patch.object(domains_endpoint, "verify_cloudflare_domain_ownership", verify_mock):
        response = authed_client.post(f"/api/v1/domains/{DOMAIN}/ownership/cloudflare")

    assert response.status_code == 200
    assert response.json() == ownership_result
    verify_mock.assert_awaited_once_with(
        db_session,
        domain_name=DOMAIN,
        workspace_id=workspace.id,
    )


def test_cloudflare_ownership_endpoint_returns_next_steps_on_provider_error(
    authed_client: TestClient,
):
    verify_mock = AsyncMock(side_effect=LookupError(f"No Cloudflare zone visible for {DOMAIN}"))
    with patch.object(domains_endpoint, "verify_cloudflare_domain_ownership", verify_mock):
        response = authed_client.post(f"/api/v1/domains/{DOMAIN}/ownership/cloudflare")

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["message"] == f"No Cloudflare zone visible for {DOMAIN}"
    assert "Connect Cloudflare from Settings" in detail["next_steps"][0]


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
    assert providers["akamai-edgedns"]["mode"] == "planned"
    assert providers["akamai-edgedns"]["name"] == "Akamai Edge DNS / FastDNS"
    assert providers["akamai-edgedns"]["record_write_status"] == "planned"
    assert "edgegrid" in providers["akamai-edgedns"]["auth_models"]


def test_dns_provider_connector_metadata_keeps_hyphenated_canonical_id():
    metadata = dns_provider_connectors.provider_connector_metadata("akamai_edgedns")

    assert metadata is not None
    assert metadata["id"] == "akamai-edgedns"
    assert dns_provider_connectors.provider_connector_metadata("fastdns")["id"] == (
        "akamai-edgedns"
    )


def test_dns_provider_capabilities_report_available_lexicon_runtime():
    with patch("app.services.dns_provider_writes.lexicon_runtime_available", return_value=True):
        providers = {
            provider["id"]: provider for provider in dns_provider_writes.provider_capabilities()
        }

    assert providers["cloudflare"]["status"] == "ready"
    assert providers["route53"]["status"] == "ready"
    assert providers["route53"]["mode"] == "lexicon"
    assert providers["route53"]["name"] == "Amazon Route 53"
    assert providers["digitalocean"]["name"] == "DigitalOcean DNS"


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


def test_dns_change_plan_apply_requires_verified_domain_for_live_write(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN, verified=False))
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
            "app.services.dns_provider_writes.build_cloudflare_provider",
            return_value=provider,
        ) as build_provider,
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

    assert response.status_code == 422
    assert "Verify domain ownership before applying live DNS changes" in response.json()["detail"]
    build_provider.assert_not_called()
    assert provider.updated == []
    assert db_session.query(WorkspaceAuditLog).count() == 0


def test_dns_change_plan_apply_requires_stored_domain_for_live_write(
    authed_client: TestClient,
):
    plan = _dns_plan(operation="update")

    with (
        patch("app.api.api_v1.endpoints.domains._domain_exists", return_value=True),
        patch(
            "app.api.api_v1.endpoints.domains._build_domain_dns_guidance",
            new=AsyncMock(return_value=_dns_guidance_with_plan(plan)),
        ),
        patch("app.services.dns_provider_writes.build_cloudflare_provider") as build_provider,
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

    assert response.status_code == 422
    assert "Add this domain to the workspace" in response.json()["detail"]
    build_provider.assert_not_called()


def test_dns_change_plan_apply_updates_cloudflare_and_audits(
    authed_client: TestClient,
    db_session,
):
    db_session.add(Domain(name=DOMAIN, verified=True))
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
    db_session.add(Domain(name=DOMAIN, verified=True))
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
        preview_response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={
                "plan_id": plan["plan_id"],
                "provider": "cloudflare",
                "dry_run": True,
                "confirm": False,
            },
        )
        response = authed_client.post(
            f"/api/v1/domains/{DOMAIN}/dns/change-plan/apply",
            json={
                "plan_id": plan["plan_id"],
                "provider": "cloudflare",
                "dry_run": False,
                "confirm": True,
            },
        )

    assert preview_response.status_code == 200
    preview_data = preview_response.json()
    assert preview_data["applied"] is False
    assert preview_data["dry_run"] is True
    assert preview_data["mutation"]["zone_id"] == "demo-zone"
    assert preview_data["mutation"]["current_values"] == ["v=DMARC1; p=none"]
    assert preview_data["verification"]["status"] == "not_run"
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
    db_session.add(Domain(name=DOMAIN, verified=True))
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
