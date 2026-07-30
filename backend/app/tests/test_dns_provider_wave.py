"""Focused coverage for OVH discovery, native writes, and local zone baselines."""

import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.models.workspace import Workspace
from app.services import dns_provider_writes, dns_zone_baselines, ovh_dns

ZONE = "example.test"
ZONE_TEXT = """
$TTL 3600
@ IN SOA ns1.example.test. hostmaster.example.test. 1 3600 600 86400 300
@ IN NS ns1.example.test.
@ IN MX 10 mail.example.test.
@ IN TXT "v=spf1 mx -all"
selector._domainkey IN CNAME selector.provider.example.
"""


def test_bind_zone_parser_normalizes_supported_records():
    records = dns_zone_baselines.parse_bind_zone(ZONE, ZONE_TEXT)

    assert {item["type"] for item in records} == {"SOA", "NS", "MX", "TXT", "CNAME"}
    assert any(item["value"] == "v=spf1 mx -all" for item in records)
    assert any(
        item["name"] == f"selector._domainkey.{ZONE}"
        and item["value"] == "selector.provider.example"
        for item in records
    )


def test_bind_zone_parser_rejects_malformed_input():
    with pytest.raises(ValueError, match="not valid BIND"):
        dns_zone_baselines.parse_bind_zone(ZONE, "this is not a zone record")


def test_zone_baseline_persists_expiring_non_scoring_evidence(db_session):
    workspace = Workspace(slug="baseline-test", name="Baseline test", active=True)
    db_session.add(workspace)
    db_session.commit()

    async def fake_compare(records):
        return [{"name": ZONE, "type": "TXT", "matches": False}]

    with patch.object(dns_zone_baselines, "compare_with_public_dns", new=fake_compare):
        item = asyncio.run(
            dns_zone_baselines.save_zone_baseline(
                db_session,
                workspace_id=workspace.id,
                domain=ZONE,
                zone_text=ZONE_TEXT,
                ttl_hours=12,
            )
        )

    payload = dns_zone_baselines.baseline_payload(item)
    assert payload["record_count"] == 5
    assert payload["affects_health_score"] is False
    assert payload["provenance"] == "imported_zone_baseline"
    assert item.expires_at > datetime.utcnow()


def test_ovh_client_signs_read_only_zone_requests(monkeypatch):
    requests = []

    class Response:
        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            return None

        def json(self):
            return self.data

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, headers):
            requests.append((url, headers))
            return Response([ZONE])

    monkeypatch.setattr(ovh_dns.httpx, "AsyncClient", lambda **_kwargs: Client())
    client = ovh_dns.OVHDNSClient(
        ovh_dns.OVHDNSCredentials(
            api_base="https://eu.api.ovh.com/v1",
            application_key="app",
            application_secret="secret",
            consumer_key="consumer",
        )
    )

    assert asyncio.run(client.list_zones()) == [ZONE]
    assert requests[0][0].endswith("/domain/zone")
    assert requests[0][1]["X-Ovh-Application"] == "app"
    assert requests[0][1]["X-Ovh-Signature"].startswith("$1$")


@pytest.mark.parametrize("provider_id", ["route53", "hetzner"])
def test_native_provider_previews_and_verifies_one_reviewed_update(db_session, provider_id):
    records = [
        {
            "id": "record-1",
            "name": f"_dmarc.{ZONE}",
            "type": "TXT",
            "content": "v=DMARC1; p=none",
            "ttl": 300,
        }
    ]

    class Client:
        async def zone_for_domain(self, _domain):
            return {"id": "zone-1", "name": ZONE}

        async def list_records(self, *_args, **_kwargs):
            return records

        async def upsert_record(self, *_args, **kwargs):
            records[0]["content"] = kwargs["content"]
            return {"status": "accepted"}

    provider = dns_provider_writes.NativeManagedDNSWriteProvider(provider_id)
    plan = {
        "operation": "update",
        "record_type": "TXT",
        "name": f"_dmarc.{ZONE}",
        "proposed_value": "v=DMARC1; p=reject",
        "current_values": ["v=DMARC1; p=none"],
    }
    builder = (
        "app.services.dns_provider_writes.build_route53_dns_client"
        if provider_id == "route53"
        else "app.services.dns_provider_writes.build_hetzner_dns_client"
    )
    with patch(builder, return_value=Client()):
        mutation = asyncio.run(
            provider.prepare_mutation(
                db_session, domain=ZONE, plan=plan, value_override=None, ttl=300
            )
        )
        result = asyncio.run(provider.apply_mutation(db_session, domain=ZONE, mutation=mutation))

    assert mutation.operation == "update"
    assert mutation.current_values == ["v=DMARC1; p=none"]
    assert result.applied is True
    assert result.verification.verified is True


def test_native_provider_blocks_multiple_matching_records(db_session):
    class Client:
        async def zone_for_domain(self, _domain):
            return {"id": "zone-1", "name": ZONE}

        async def list_records(self, *_args, **_kwargs):
            return [
                {"name": f"_dmarc.{ZONE}", "type": "TXT", "content": "one"},
                {"name": f"_dmarc.{ZONE}", "type": "TXT", "content": "two"},
            ]

    provider = dns_provider_writes.NativeManagedDNSWriteProvider("route53")
    plan = {
        "operation": "update",
        "record_type": "TXT",
        "name": f"_dmarc.{ZONE}",
        "proposed_value": "three",
    }
    with patch("app.services.dns_provider_writes.build_route53_dns_client", return_value=Client()):
        mutation = asyncio.run(
            provider.prepare_mutation(
                db_session, domain=ZONE, plan=plan, value_override=None, ttl=300
            )
        )

    assert mutation.applicable is False
    assert "Multiple provider records" in mutation.blocked_reason
