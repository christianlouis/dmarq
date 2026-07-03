from types import SimpleNamespace

import pytest

from app.services.source_reputation import (
    build_source_reputation,
    build_source_reputation_cached,
    reputation_presentation,
    source_reputation_by_ip,
)
from app.services.source_reputation_feeds import FeedLookupEvidence, IPFeedReputation


def _report(records):
    return {
        "domain": "example.com",
        "begin_date": 1_700_000_000,
        "end_date": 1_700_086_400,
        "records": records,
    }


def test_build_source_reputation_flags_listed_metadata():
    sources = [
        {
            "source_ip": "198.51.100.199",
            "count": 20,
            "dmarc_fail_count": 20,
            "extensions": {
                "demo:reputation": "listed",
                "demo:blacklists": "Demo RBL, Legacy Sender Watch",
                "demo:source": "unknown-forwarder",
            },
        }
    ]

    result = build_source_reputation(
        "example.com",
        [_report([{"source_ip": "198.51.100.199"}])],
        sources,
    )

    assert result.status == "listed"
    assert result.summary["listed"] == 1
    source = result.sources[0]
    assert source.status == "listed"
    assert source.listings == ["Demo RBL", "Legacy Sender Watch"]
    assert source.risk_score >= 70
    assert source.first_seen == 1_700_000_000
    assert source.last_seen == 1_700_086_400


def test_build_source_reputation_flags_reported_listed_without_listing_names():
    sources = [
        {
            "source_ip": "203.0.113.66",
            "count": 10,
            "dmarc_fail_count": 0,
            "extensions": {
                "demo:reputation": "listed",
                "demo:source": "unknown-forwarder",
            },
        }
    ]

    result = build_source_reputation("example.com", [], sources)

    source = result.sources[0]
    assert result.status == "listed"
    assert result.summary["highest_risk_score"] >= 45
    assert source.status == "listed"
    assert source.risk_score >= 45
    assert any(
        item.label == "Reputation status" and item.value == "listed" for item in source.evidence
    )


def test_build_source_reputation_reports_suspicious_sender_context():
    sources = [
        {
            "source_ip": "203.0.113.77",
            "count": 12,
            "dmarc_fail_count": 0,
            "extensions": {"demo:source": "unknown-forwarder"},
        }
    ]

    result = build_source_reputation(
        "example.com",
        [],
        sources,
        senders_by_ip={
            "203.0.113.77": {
                "status": "suspicious",
                "reason": "unexpected source owner",
            }
        },
    )

    source = result.sources[0]
    assert source.status == "unknown"
    assert source.risk_score == 25
    assert any(item.label == "Sender identity" for item in source.evidence)
    assert source.recommendations == []


def test_build_source_reputation_reports_warning_anomalies():
    sources = [
        {
            "source_ip": "203.0.113.88",
            "count": 12,
            "dmarc_fail_count": 0,
            "extensions": {"demo:source": "workspace-mail"},
        }
    ]

    result = build_source_reputation(
        "example.com",
        [],
        sources,
        anomalies_by_ip={"203.0.113.88": [{"severity": "warning"}]},
    )

    source = result.sources[0]
    assert source.status == "clean"
    assert source.risk_score == 10
    assert any(item.label == "Source anomalies" and item.value == "1" for item in source.evidence)


def test_build_source_reputation_flags_non_global_source_ip():
    sources = [
        {
            "source_ip": "10.0.0.25",
            "count": 8,
            "dmarc_fail_count": 0,
            "extensions": {},
        }
    ]

    result = build_source_reputation("example.com", [], sources)

    source = source_reputation_by_ip(result)["10.0.0.25"]
    assert source.status == "unknown"
    assert source.risk_score == 18
    assert any(item.label == "Network scope" for item in source.evidence)


def test_build_source_reputation_marks_clean_known_source():
    sources = [
        {
            "source_ip": "203.0.113.10",
            "count": 100,
            "dmarc_fail_count": 0,
            "extensions": {
                "demo:reputation": "clean",
                "demo:source": "workspace-mail",
            },
        }
    ]

    result = build_source_reputation("example.com", [], sources)

    assert result.status == "clean"
    assert result.summary["clean"] == 1
    assert result.sources[0].status == "clean"
    assert result.sources[0].risk_score <= 10


def test_build_source_reputation_merges_external_feed_listing():
    sources = [
        {
            "source_ip": "8.8.8.8",
            "count": 100,
            "dmarc_fail_count": 0,
        }
    ]

    result = build_source_reputation(
        "example.com",
        [],
        sources,
        feed_results_by_ip={
            "8.8.8.8": IPFeedReputation(
                ip="8.8.8.8",
                listed=True,
                evidence=[
                    FeedLookupEvidence(
                        provider_id="demo_feed",
                        provider_name="Demo Reputation Feed",
                        status="listed",
                        listing="Demo RBL",
                    )
                ],
            )
        },
    )

    source = result.sources[0]
    assert result.status == "listed"
    assert source.status == "listed"
    assert "Demo RBL" in source.listings
    assert source.risk_score >= 45
    assert any(item.label == "External reputation feeds" for item in source.evidence)
    assert any("delisting" in item for item in source.recommendations)


def test_reputation_presentation_distinguishes_local_only_from_checked_feeds():
    local_result = build_source_reputation(
        "example.com",
        [],
        [{"source_ip": "8.8.8.8", "count": 100, "dmarc_fail_count": 0}],
    )

    local_view = reputation_presentation(local_result.sources[0])

    assert local_view.status_label == "Clean"
    assert local_view.feed_status == "local_only"
    assert "local DMARC evidence" in local_view.feed_summary

    checked_result = build_source_reputation(
        "example.com",
        [],
        [{"source_ip": "8.8.4.4", "count": 100, "dmarc_fail_count": 0}],
        feed_results_by_ip={
            "8.8.4.4": IPFeedReputation(
                ip="8.8.4.4",
                evidence=[
                    FeedLookupEvidence(
                        provider_id="demo_feed",
                        provider_name="Demo Reputation Feed",
                        status="clean",
                        detail="clean",
                    )
                ],
            )
        },
    )

    checked_source = checked_result.sources[0]
    checked_view = reputation_presentation(checked_source)

    assert checked_view.status_label == "Clean"
    assert checked_view.feed_status == "checked"
    assert "checked without listings" in checked_view.feed_summary
    assert any(item.source == "external" and item.value == "clean" for item in checked_source.evidence)


@pytest.mark.asyncio
async def test_build_source_reputation_cached_reuses_fresh_result(db_session):
    sources = [
        {
            "source_ip": "203.0.113.10",
            "count": 100,
            "dmarc_fail_count": 0,
            "extensions": {"demo:reputation": "clean", "demo:source": "workspace-mail"},
        }
    ]

    first, first_cached, first_checked = await build_source_reputation_cached(
        db_session,
        "example.com",
        [],
        sources,
    )
    second, second_cached, second_checked = await build_source_reputation_cached(
        db_session,
        "example.com",
        [],
        sources,
    )

    assert first.status == "clean"
    assert first_cached is False
    assert second.status == "clean"
    assert second_cached is True
    assert second_checked == first_checked
    assert source_reputation_by_ip(second)["203.0.113.10"].status == "clean"


@pytest.mark.asyncio
async def test_build_source_reputation_cached_includes_reports_in_cache_key(db_session):
    sources = [
        {
            "source_ip": "203.0.113.10",
            "count": 100,
            "dmarc_fail_count": 0,
            "extensions": {"demo:reputation": "clean", "demo:source": "workspace-mail"},
        }
    ]

    first, first_cached, _ = await build_source_reputation_cached(
        db_session,
        "example.com",
        [_report([{"source_ip": "203.0.113.10"}])],
        sources,
    )
    second, second_cached, _ = await build_source_reputation_cached(
        db_session,
        "example.com",
        [
            {
                "domain": "example.com",
                "begin_date": 1_800_000_000,
                "end_date": 1_800_086_400,
                "records": [{"source_ip": "203.0.113.10"}],
            }
        ],
        sources,
    )

    assert first_cached is False
    assert second_cached is False
    assert source_reputation_by_ip(first)["203.0.113.10"].first_seen == 1_700_000_000
    assert source_reputation_by_ip(second)["203.0.113.10"].first_seen == 1_800_000_000


@pytest.mark.asyncio
async def test_build_source_reputation_cached_skips_feed_lookup_on_fresh_domain_cache(
    db_session,
    monkeypatch,
):
    calls = 0
    provider = SimpleNamespace(
        config=SimpleNamespace(
            provider_id="demo_feed",
            enabled=True,
            kind="dnsbl",
            query_zone="example.test",
            listing_name="Demo RBL",
        )
    )

    async def fake_lookup_sources(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {}

    monkeypatch.setattr(
        "app.services.source_reputation.providers_from_settings",
        lambda _settings: [provider],
    )
    monkeypatch.setattr(
        "app.services.source_reputation.lookup_sources_reputation_cached",
        fake_lookup_sources,
    )
    sources = [
        {
            "source_ip": "8.8.8.8",
            "count": 100,
            "dmarc_fail_count": 0,
            "extensions": {"demo:reputation": "clean", "demo:source": "workspace-mail"},
        }
    ]

    first, first_cached, _ = await build_source_reputation_cached(
        db_session,
        "example.com",
        [],
        sources,
    )
    second, second_cached, _ = await build_source_reputation_cached(
        db_session,
        "example.com",
        [],
        sources,
    )

    assert first.status == "clean"
    assert second.status == "clean"
    assert first_cached is False
    assert second_cached is True
    assert calls == 1
