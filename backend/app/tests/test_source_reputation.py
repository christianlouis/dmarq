import pytest

from app.services.source_reputation import (
    build_source_reputation,
    build_source_reputation_cached,
    source_reputation_by_ip,
)


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
    assert any(item.label == "Reputation status" and item.value == "listed" for item in source.evidence)


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
