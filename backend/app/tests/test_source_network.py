from types import SimpleNamespace

import pytest

from app.services.source_network import (
    _ASN_NAME_CACHE,
    SourceNetworkIntelligence,
    lookup_source_network,
    lookup_source_network_cached,
    lookup_sources_network_cached,
    merge_network_into_geo,
)

pytestmark = pytest.mark.anyio


class FakeProvider:
    def __init__(self, records=None):
        self.records = [] if records is None else records
        self.queries = []

    async def lookup_txt(self, name):
        self.queries.append(name)
        if isinstance(self.records, dict):
            response = self.records.get(name, [])
            if isinstance(response, Exception):
                raise response
            return response
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


async def test_lookup_source_network_accepts_team_cymru_dns_without_as_name():
    provider = FakeProvider(
        {
            "203.205.31.50.origin.asn.cymru.com": [
                '"23352 | 50.31.205.0/24 | US | arin | 2011-02-03"',
            ],
            "AS23352.asn.cymru.com": [
                '"23352 | US | arin | 2002-03-05 | SERVERCENTRAL - DEFT.COM, US"',
            ],
        }
    )

    result = await lookup_source_network(provider, "50.31.205.203")

    assert provider.queries == [
        "203.205.31.50.origin.asn.cymru.com",
        "AS23352.asn.cymru.com",
    ]
    assert result.asn == "AS23352"
    assert result.as_name == "SERVERCENTRAL - DEFT.COM, US"
    assert result.bgp_prefix == "50.31.205.0/24"
    assert result.country == "United States"
    assert result.region == "North America"
    assert result.error is None


async def test_lookup_source_network_uses_origin6_for_ipv6_sources():
    provider = FakeProvider(
        {
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
                "b.1.1.3.7.1.c.0.8.f.4.0.1.0.a.2.origin6.asn.cymru.com"
            ): ['"24940 | 2a01:4f8::/32 | DE | ripencc | 2007-10-10"'],
            "AS24940.asn.cymru.com": [
                '"24940 | DE | ripencc | 2002-06-03 | HETZNER-AS - Hetzner Online GmbH, DE"',
            ],
        }
    )

    result = await lookup_source_network(provider, "2a01:4f8:c17:311b::1")

    assert provider.queries == [
        (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
            "b.1.1.3.7.1.c.0.8.f.4.0.1.0.a.2.origin6.asn.cymru.com"
        ),
        "AS24940.asn.cymru.com",
    ]
    assert result.asn == "AS24940"
    assert result.as_name == "HETZNER-AS - Hetzner Online GmbH, DE"
    assert result.bgp_prefix == "2a01:4f8::/32"
    assert result.country == "Germany"
    assert result.region == "Europe"
    assert result.error is None


async def test_lookup_source_network_tolerates_asn_name_lookup_failure():
    provider = FakeProvider(
        {
            "203.205.31.50.origin.asn.cymru.com": [
                '"64501 | 50.31.205.0/24 | US | arin | 2011-02-03"',
            ],
            "AS64501.asn.cymru.com": RuntimeError("temporary DNS failure"),
        }
    )

    result = await lookup_source_network(provider, "50.31.205.203")

    assert provider.queries == [
        "203.205.31.50.origin.asn.cymru.com",
        "AS64501.asn.cymru.com",
    ]
    assert result.asn == "AS64501"
    assert result.as_name is None
    assert result.bgp_prefix == "50.31.205.0/24"
    assert result.error is None


async def test_lookup_source_network_reuses_asn_name_lookup_cache():
    _ASN_NAME_CACHE.pop("AS64502", None)
    provider = FakeProvider(
        {
            "8.8.8.8.origin.asn.cymru.com": [
                '"64502 | 8.8.8.0/24 | US | arin | 2011-02-03"',
            ],
            "4.4.8.8.origin.asn.cymru.com": [
                '"64502 | 8.8.4.0/24 | US | arin | 2011-02-03"',
            ],
            "AS64502.asn.cymru.com": [
                '"64502 | US | arin | 2002-03-05 | EXAMPLE-AS, US"',
            ],
        }
    )

    first = await lookup_source_network(provider, "8.8.8.8")
    second = await lookup_source_network(provider, "8.8.4.4")

    assert provider.queries == [
        "8.8.8.8.origin.asn.cymru.com",
        "AS64502.asn.cymru.com",
        "4.4.8.8.origin.asn.cymru.com",
    ]
    assert first.as_name == "EXAMPLE-AS, US"
    assert second.as_name == "EXAMPLE-AS, US"


async def test_lookup_source_network_prefers_ipinfo_lite(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        @staticmethod
        def read():
            return (
                b'{"ip":"104.245.209.200","network":"104.245.208.0/21",'
                b'"asn":"AS23352","as_name":"SERVERCENTRAL - DEFT.COM",'
                b'"as_domain":"deft.com","country_code":"US",'
                b'"country":"United States","continent":"North America"}'
            )

    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.headers.get("Authorization")
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.source_network.get_settings",
        lambda: SimpleNamespace(IPINFO_TOKEN="secret-token", IPINFO_TIMEOUT_SECONDS=1.5),
    )
    monkeypatch.setattr("app.services.source_network.urlopen", fake_urlopen)
    provider = FakeProvider()

    result = await lookup_source_network(provider, "104.245.209.200")

    assert provider.queries == []
    assert captured["url"] == "https://api.ipinfo.io/lite/104.245.209.200"
    assert captured["authorization"] == "Bearer secret-token"
    assert captured["timeout"] == 1.5
    assert result.source == "ipinfo-lite"
    assert result.asn == "AS23352"
    assert result.as_name == "SERVERCENTRAL - DEFT.COM"
    assert result.bgp_prefix == "104.245.208.0/21"
    assert result.country == "United States"
    assert result.region == "North America"
    assert result.error is None


async def test_lookup_source_network_uses_ipgeolocation_when_configured(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        @staticmethod
        def read():
            return (
                b'{"ip":"104.245.209.200","location":{"continent_name":"North America",'
                b'"country_code2":"US","country_name":"United States","city":"Chicago",'
                b'"latitude":"41.87810","longitude":"-87.62980"},'
                b'"asn":{"as_number":"AS23352","organization":"SERVERCENTRAL - DEFT.COM",'
                b'"country":"US","route":"104.245.208.0/21"}}'
            )

    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.source_network.get_settings",
        lambda: SimpleNamespace(
            IPINFO_TOKEN=None,
            IPGEOLOCATION_API_KEY="geo-key",
            IPGEOLOCATION_TIMEOUT_SECONDS=1.25,
            CLOUDFLARE_RADAR_API_TOKEN=None,
            CLOUDFLARE_API_TOKEN=None,
        ),
    )
    monkeypatch.setattr("app.services.source_network.urlopen", fake_urlopen)
    provider = FakeProvider()

    result = await lookup_source_network(provider, "104.245.209.200")

    assert provider.queries == []
    assert captured["url"].startswith("https://api.ipgeolocation.io/v3/ipgeo?")
    assert "apiKey=geo-key" in captured["url"]
    assert "ip=104.245.209.200" in captured["url"]
    assert captured["timeout"] == 1.25
    assert result.source == "ipgeolocation"
    assert result.asn == "AS23352"
    assert result.as_name == "SERVERCENTRAL - DEFT.COM"
    assert result.bgp_prefix == "104.245.208.0/21"
    assert result.country == "United States"
    assert result.region == "North America"
    assert result.city == "Chicago"
    assert result.radar_url == "https://radar.cloudflare.com/ip/104.245.209.200"
    assert result.error is None


async def test_lookup_source_network_uses_cloudflare_radar_when_configured(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        @staticmethod
        def read():
            return (
                b'{"success":true,"result":{"ip":{"asn":"23352","asnLocation":"US",'
                b'"asnName":"SERVERCENTRAL","asnOrgName":"Deft.com",'
                b'"ip":"104.245.209.200","ipVersion":"IPv4",'
                b'"location":"US","locationName":"United States"}}}'
            )

    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.headers.get("Authorization")
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.source_network.get_settings",
        lambda: SimpleNamespace(
            IPINFO_TOKEN=None,
            IPGEOLOCATION_API_KEY=None,
            CLOUDFLARE_RADAR_API_TOKEN="radar-token",
            CLOUDFLARE_RADAR_TIMEOUT_SECONDS=1.75,
        ),
    )
    monkeypatch.setattr("app.services.source_network.urlopen", fake_urlopen)
    provider = FakeProvider()

    result = await lookup_source_network(provider, "104.245.209.200")

    assert provider.queries == []
    assert captured["url"].startswith("https://api.cloudflare.com/client/v4/radar/entities/ip?")
    assert "ip=104.245.209.200" in captured["url"]
    assert captured["authorization"] == "Bearer radar-token"
    assert captured["timeout"] == 1.75
    assert result.source == "cloudflare-radar"
    assert result.asn == "AS23352"
    assert result.as_name == "Deft.com"
    assert result.country == "United States"
    assert result.cloudflare_asn_name == "SERVERCENTRAL"
    assert result.cloudflare_asn_org_name == "Deft.com"
    assert result.radar_url == "https://radar.cloudflare.com/ip/104.245.209.200"
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
        city="Falkenstein",
        registry="ripencc",
        allocated="2004-02-17",
        organization="Hetzner Online GmbH",
        domain="hetzner.com",
        radar_url="https://radar.cloudflare.com/ip/193.138.195.141",
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
    assert merged["city"] == "Falkenstein"
    assert merged["registry"] == "ripencc"
    assert merged["organization"] == "Hetzner Online GmbH"
    assert merged["domain"] == "hetzner.com"
    assert merged["radar_url"] == "https://radar.cloudflare.com/ip/193.138.195.141"
    assert merged["network_source"] == "team-cymru"
