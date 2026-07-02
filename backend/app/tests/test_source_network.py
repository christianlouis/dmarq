import pytest

from app.services.source_network import (
    SourceNetworkIntelligence,
    lookup_source_network,
    lookup_source_network_cached,
    lookup_sources_network_cached,
    merge_network_into_geo,
)

pytestmark = pytest.mark.anyio


class FakeProvider:
    def __init__(self, records=None):
        self.records = records or []
        self.queries = []

    async def lookup_txt(self, name):
        self.queries.append(name)
        return self.records


async def test_lookup_source_network_parses_team_cymru_txt():
    provider = FakeProvider(
        [
            '"24940 | 193.138.192.0/19 | DE | ripencc | 2004-02-17 | HETZNER-AS, DE"',
        ]
    )

    result = await lookup_source_network(provider, "193.138.195.141")

    assert provider.queries == ["141.195.138.193.origin.asn.cymru.com"]
    assert result.asn == "AS24940"
    assert result.as_name == "HETZNER-AS, DE"
    assert result.bgp_prefix == "193.138.192.0/19"
    assert result.country_code == "DE"
    assert result.country == "Germany"
    assert result.region == "Europe"
    assert result.registry == "ripencc"
    assert result.allocated == "2004-02-17"
    assert result.source == "team-cymru"
    assert result.error is None


async def test_lookup_source_network_skips_non_global_ip():
    provider = FakeProvider()

    result = await lookup_source_network(provider, "192.0.2.10")

    assert provider.queries == []
    assert result.error == "Non-global IP address."
    assert result.source == "local"


async def test_lookup_source_network_cached_reuses_fresh_result(db_session):
    provider = FakeProvider(
        [
            '"64500 | 198.51.100.0/24 | US | arin | 2026-01-01 | EXAMPLE-AS, US"',
        ]
    )

    first, first_cached, first_checked = await lookup_source_network_cached(
        db_session,
        provider,
        "8.8.8.8",
    )
    provider.records = [
        '"64501 | 198.51.101.0/24 | US | arin | 2026-01-02 | OTHER-AS, US"',
    ]
    second, second_cached, second_checked = await lookup_source_network_cached(
        db_session,
        provider,
        "8.8.8.8",
    )

    assert first_cached is False
    assert second_cached is True
    assert first_checked == second_checked
    assert first.asn == "AS64500"
    assert second.asn == "AS64500"
    assert provider.queries == ["8.8.8.8.origin.asn.cymru.com"]


async def test_lookup_sources_network_cached_filters_invalid_and_non_global_ips(db_session):
    provider = FakeProvider(
        [
            '"15169 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE, US"',
        ]
    )

    results = await lookup_sources_network_cached(
        db_session,
        provider,
        ["unknown", "", None, "10.0.0.1", "192.0.2.10", "8.8.8.8", "8.8.8.8"],
    )

    assert list(results) == ["8.8.8.8"]
    assert results["8.8.8.8"].asn == "AS15169"
    assert provider.queries == ["8.8.8.8.origin.asn.cymru.com"]


def test_merge_network_into_geo_preserves_report_metadata_and_adds_prefix():
    network = SourceNetworkIntelligence(
        ip="193.138.195.141",
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
    merged = merge_network_into_geo(
        {"country": "France", "country_code": "FR", "source": "report"},
        network,
    )

    assert merged["country"] == "France"
    assert merged["country_code"] == "FR"
    assert merged["asn"] == "AS24940"
    assert merged["network"] == "Hetzner Online GmbH"
    assert merged["bgp_prefix"] == "193.138.192.0/19"
    assert merged["registry"] == "ripencc"
    assert merged["network_source"] == "team-cymru"
