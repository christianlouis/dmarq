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
