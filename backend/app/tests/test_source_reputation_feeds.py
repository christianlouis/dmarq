from types import SimpleNamespace

import dns.resolver
import httpx
import pytest

from app.services.dns_resolver import PUBLIC_RECURSIVE_NAMESERVERS
from app.services.source_reputation_feeds import (
    AbuseIPDBFeedProvider,
    DNSBLFeedProvider,
    FeedProviderConfig,
    StaticFeedProvider,
    feed_registry,
    lookup_ip_reputation_cached,
    lookup_sources_reputation_cached,
    provider_configs_from_settings,
)


def _settings(**overrides):
    values = {
        "SOURCE_REPUTATION_FEEDS_ENABLED": False,
        "SOURCE_REPUTATION_FEEDS": None,
        "SOURCE_REPUTATION_SPAMHAUS_DQS_ZONE": None,
        "SOURCE_REPUTATION_ABUSIX_ZONE": "combined.mail.abusix.zone",
        "SOURCE_REPUTATION_ABUSEIPDB_API_KEY": None,
        "SOURCE_REPUTATION_ABUSEIPDB_MAX_AGE_DAYS": 90,
        "SOURCE_REPUTATION_ABUSEIPDB_LISTED_THRESHOLD": 75,
        "SOURCE_REPUTATION_FEED_TIMEOUT_SECONDS": 2.0,
        "SOURCE_REPUTATION_FEED_CACHE_SECONDS": 86_400,
        "SOURCE_REPUTATION_FEED_MAX_IPS": 100,
        "DEMO_MODE": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_provider_configs_are_disabled_by_default():
    configs = provider_configs_from_settings(_settings())

    assert {item.provider_id for item in configs} == {
        "spamhaus_dqs",
        "abusix_mail",
        "spamcop_scbl",
        "barracuda_brbl",
        "abuseipdb",
    }
    assert all(item.enabled is False for item in configs)
    assert all(item.requires_terms is True for item in configs)


def test_spamhaus_dqs_requires_configured_query_zone():
    without_zone = provider_configs_from_settings(
        _settings(SOURCE_REPUTATION_FEEDS_ENABLED=True, SOURCE_REPUTATION_FEEDS="spamhaus_dqs")
    )
    with_zone = provider_configs_from_settings(
        _settings(
            SOURCE_REPUTATION_FEEDS_ENABLED=True,
            SOURCE_REPUTATION_FEEDS="spamhaus_dqs",
            SOURCE_REPUTATION_SPAMHAUS_DQS_ZONE="example.dq.spamhaus.net",
        )
    )

    assert without_zone[0].enabled is False
    assert with_zone[0].enabled is True
    assert with_zone[0].query_zone == "example.dq.spamhaus.net"


def test_abusix_uses_default_mail_intelligence_zone():
    configs = provider_configs_from_settings(
        _settings(SOURCE_REPUTATION_FEEDS_ENABLED=True, SOURCE_REPUTATION_FEEDS="abusix_mail")
    )
    abusix = next(item for item in configs if item.provider_id == "abusix_mail")

    assert abusix.enabled is True
    assert abusix.query_zone == "combined.mail.abusix.zone"


def test_abuseipdb_requires_api_key():
    without_key = provider_configs_from_settings(
        _settings(SOURCE_REPUTATION_FEEDS_ENABLED=True, SOURCE_REPUTATION_FEEDS="abuseipdb")
    )
    with_key = provider_configs_from_settings(
        _settings(
            SOURCE_REPUTATION_FEEDS_ENABLED=True,
            SOURCE_REPUTATION_FEEDS="abuseipdb",
            SOURCE_REPUTATION_ABUSEIPDB_API_KEY="secret",
        )
    )
    without_config = next(item for item in without_key if item.provider_id == "abuseipdb")
    with_config = next(item for item in with_key if item.provider_id == "abuseipdb")

    assert without_config.enabled is False
    assert with_config.enabled is True
    assert with_config.kind == "api"
    assert with_config.api_key == "secret"


def test_feed_registry_exposes_safe_metadata_only():
    registry = feed_registry(
        _settings(
            SOURCE_REPUTATION_FEEDS_ENABLED=True,
            SOURCE_REPUTATION_FEEDS="spamcop_scbl,barracuda_brbl,abuseipdb",
            SOURCE_REPUTATION_ABUSEIPDB_API_KEY="secret",
        )
    )

    assert registry["spamcop_scbl"]["enabled"] is True
    assert registry["barracuda_brbl"]["enabled"] is True
    assert registry["spamhaus_dqs"]["enabled"] is False
    assert registry["spamcop_scbl"]["configured"] is True
    assert registry["spamhaus_dqs"]["configured"] is False
    assert registry["abuseipdb"]["enabled"] is True
    assert registry["abuseipdb"]["configured"] is True
    assert registry["abuseipdb"]["kind"] == "api"
    assert "query_zone" not in registry["spamcop_scbl"]
    assert "secret" not in registry["spamcop_scbl"]
    assert "secret" not in registry["abuseipdb"]


def test_dnsbl_default_resolver_uses_public_recursive_nameservers():
    provider = DNSBLFeedProvider(
        FeedProviderConfig(
            provider_id="demo_feed",
            display_name="Demo Reputation Feed",
            enabled=True,
            query_zone="example.test",
        )
    )

    assert provider._resolver.nameservers == list(PUBLIC_RECURSIVE_NAMESERVERS)


class NoNameserversResolver:
    lifetime = 0.0
    timeout = 0.0

    def resolve(self, *_args, **_kwargs):
        raise dns.resolver.NoNameservers()


@pytest.mark.asyncio
async def test_dnsbl_no_nameservers_reports_provider_error():
    provider = DNSBLFeedProvider(
        FeedProviderConfig(
            provider_id="demo_feed",
            display_name="Demo Reputation Feed",
            enabled=True,
            query_zone="example.test",
        ),
        resolver=NoNameserversResolver(),
    )

    evidence = await provider.lookup_ip("8.8.8.8")

    assert evidence.status == "error"
    assert "nameserver" in evidence.detail.lower()


@pytest.mark.asyncio
async def test_dnsbl_ipv6_sources_are_skipped_without_exception():
    provider = DNSBLFeedProvider(
        FeedProviderConfig(
            provider_id="demo_feed",
            display_name="Demo Reputation Feed",
            enabled=True,
            query_zone="example.test",
        ),
        resolver=NoNameserversResolver(),
    )

    evidence = await provider.lookup_ip("2a01:4f8:c17:311b::1")

    assert evidence.status == "skipped"
    assert "IPv4 sources only" in (evidence.detail or "")


@pytest.mark.asyncio
async def test_abuseipdb_high_score_returns_listing():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["ipAddress"] == "8.8.8.8"
        assert request.headers["Key"] == "secret"
        return httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 92,
                    "totalReports": 12,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                    "domain": "example.net",
                    "countryCode": "US",
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = AbuseIPDBFeedProvider(
            FeedProviderConfig(
                provider_id="abuseipdb",
                display_name="AbuseIPDB",
                kind="api",
                enabled=True,
                api_key="secret",
                listed_threshold=75,
            ),
            client=client,
        )

        evidence = await provider.lookup_ip("8.8.8.8")

    assert evidence.status == "listed"
    assert evidence.listing == "AbuseIPDB score 92"
    assert "totalReports=12" in evidence.detail
    assert "isp=Example ISP" in evidence.detail


@pytest.mark.asyncio
async def test_abuseipdb_low_nonzero_score_returns_suspicious_context():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"abuseConfidenceScore": 14, "totalReports": 1}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = AbuseIPDBFeedProvider(
            FeedProviderConfig(
                provider_id="abuseipdb",
                display_name="AbuseIPDB",
                kind="api",
                enabled=True,
                api_key="secret",
            ),
            client=client,
        )

        evidence = await provider.lookup_ip("8.8.8.8")

    assert evidence.status == "suspicious"
    assert evidence.listing is None
    assert "abuseConfidenceScore=14" in evidence.detail


@pytest.mark.asyncio
async def test_lookup_ip_reputation_cached_reuses_provider_result(db_session):
    provider = StaticFeedProvider(
        FeedProviderConfig(
            provider_id="demo_feed",
            display_name="Demo Reputation Feed",
            enabled=True,
            listing_name="Demo RBL",
        ),
        {"8.8.8.8": "Demo RBL"},
    )

    first, first_cached, _ = await lookup_ip_reputation_cached(
        db_session,
        "8.8.8.8",
        [provider],
    )
    second, second_cached, _ = await lookup_ip_reputation_cached(
        db_session,
        "8.8.8.8",
        [provider],
    )

    assert first.listed is True
    assert first.evidence[0].status == "listed"
    assert first.evidence[0].listing == "Demo RBL"
    assert first_cached is False
    assert second_cached is True
    assert second.listed is True


@pytest.mark.asyncio
async def test_lookup_sources_reputation_filters_ineligible_ips_before_max_limit(db_session):
    provider = StaticFeedProvider(
        FeedProviderConfig(
            provider_id="demo_feed",
            display_name="Demo Reputation Feed",
            enabled=True,
            listing_name="Demo RBL",
        ),
        {"8.8.8.8": "Demo RBL"},
    )

    results = await lookup_sources_reputation_cached(
        db_session,
        ["10.0.0.1", "not-an-ip", "8.8.8.8"],
        [provider],
        max_ips=1,
    )

    assert list(results) == ["8.8.8.8"]
    assert results["8.8.8.8"].listed is True

from unittest.mock import patch

def test_provider_configs_from_settings_all_enabled():
    settings = _settings(
        SOURCE_REPUTATION_FEEDS_ENABLED=True,
        SOURCE_REPUTATION_FEEDS="spamhaus_dqs,abusix_mail,spamcop_scbl,barracuda_brbl,abuseipdb",
        SOURCE_REPUTATION_SPAMHAUS_DQS_ZONE="example.dq.spamhaus.net",
        SOURCE_REPUTATION_ABUSIX_ZONE="combined.mail.abusix.zone",
        SOURCE_REPUTATION_ABUSEIPDB_API_KEY="secret-key",
        SOURCE_REPUTATION_ABUSEIPDB_MAX_AGE_DAYS=90,
        SOURCE_REPUTATION_ABUSEIPDB_LISTED_THRESHOLD=75,
    )

    configs = provider_configs_from_settings(settings)

    assert len(configs) == 5

    spamhaus = next(c for c in configs if c.provider_id == "spamhaus_dqs")
    assert spamhaus.enabled is True
    assert spamhaus.query_zone == "example.dq.spamhaus.net"

    abusix = next(c for c in configs if c.provider_id == "abusix_mail")
    assert abusix.enabled is True
    assert abusix.query_zone == "combined.mail.abusix.zone"

    spamcop = next(c for c in configs if c.provider_id == "spamcop_scbl")
    assert spamcop.enabled is True
    assert spamcop.query_zone == "bl.spamcop.net"

    barracuda = next(c for c in configs if c.provider_id == "barracuda_brbl")
    assert barracuda.enabled is True
    assert barracuda.query_zone == "b.barracudacentral.org"

    abuseipdb = next(c for c in configs if c.provider_id == "abuseipdb")
    assert abuseipdb.enabled is True
    assert abuseipdb.kind == "api"
    assert abuseipdb.api_key == "secret-key"
    assert abuseipdb.max_age_days == 90
    assert abuseipdb.listed_threshold == 75


@patch("app.services.source_reputation_feeds.get_settings")
def test_provider_configs_from_settings_uses_get_settings_when_none(mock_get_settings):
    settings = _settings()
    mock_get_settings.return_value = settings

    configs = provider_configs_from_settings(None)

    mock_get_settings.assert_called_once()
    assert len(configs) == 5
    assert all(c.enabled is False for c in configs)
