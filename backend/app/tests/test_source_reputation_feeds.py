from types import SimpleNamespace

import pytest

from app.services.source_reputation_feeds import (
    FeedProviderConfig,
    StaticFeedProvider,
    feed_registry,
    lookup_ip_reputation_cached,
    provider_configs_from_settings,
)


def _settings(**overrides):
    values = {
        "SOURCE_REPUTATION_FEEDS_ENABLED": False,
        "SOURCE_REPUTATION_FEEDS": None,
        "SOURCE_REPUTATION_SPAMHAUS_DQS_ZONE": None,
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
        "spamcop_scbl",
        "barracuda_brbl",
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


def test_feed_registry_exposes_safe_metadata_only():
    registry = feed_registry(
        _settings(
            SOURCE_REPUTATION_FEEDS_ENABLED=True,
            SOURCE_REPUTATION_FEEDS="spamcop_scbl,barracuda_brbl",
        )
    )

    assert registry["spamcop_scbl"]["enabled"] is True
    assert registry["barracuda_brbl"]["enabled"] is True
    assert registry["spamhaus_dqs"]["enabled"] is False
    assert "secret" not in registry["spamcop_scbl"]


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
