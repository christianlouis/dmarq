from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.dns_cache import DNSCache
from app.services.bimi import (
    check_bimi,
    check_bimi_cached,
    check_bimi_with_fallback,
    parse_bimi_record,
)


def test_parse_bimi_record_requires_single_bimi_record():
    result, warnings, errors = parse_bimi_record(
        ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"]
    )

    assert result is not None
    assert result.status == "pass"
    assert result.logo_url == "https://example.com/logo.svg"
    assert result.certificate_url == "https://example.com/vmc.pem"
    assert warnings == []
    assert errors == []


def test_parse_bimi_record_reports_missing_and_malformed_records():
    missing, missing_warnings, missing_errors = parse_bimi_record([])
    malformed, _, malformed_errors = parse_bimi_record(["v=BIMI1; l=http://example.com/logo.png"])

    assert missing is None
    assert missing_warnings == []
    assert missing_errors == ["No BIMI TXT record was found at the selector."]
    assert malformed is not None
    assert malformed.status == "fail"
    assert "HTTPS" in malformed_errors[0]


def test_parse_bimi_record_warns_without_certificate():
    result, warnings, errors = parse_bimi_record(["v=BIMI1; l=https://example.com/logo.svg"])

    assert result is not None
    assert result.status == "pass"
    assert errors == []
    assert warnings == ["No BIMI certificate URL is published; some mailbox providers require one."]


@pytest.mark.asyncio
async def test_check_bimi_looks_up_default_selector():
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(
        return_value=["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"]
    )

    result = await check_bimi("example.com", provider)

    assert result.status == "pass"
    assert result.query_name == "default._bimi.example.com"
    provider.lookup_txt.assert_awaited_once_with("default._bimi.example.com")


@pytest.mark.asyncio
async def test_check_bimi_falls_back_after_dns_lookup_failure(monkeypatch):
    primary = AsyncMock()
    primary.lookup_txt = AsyncMock(side_effect=LookupError("local resolver timed out"))
    fallback = AsyncMock()
    fallback.lookup_txt = AsyncMock(return_value=["v=BIMI1; l=https://example.com/logo.svg"])

    monkeypatch.setattr(
        "app.services.bimi.dns_fallback_candidates",
        lambda _provider: [primary, fallback],
    )

    result = await check_bimi_with_fallback("example.com", primary)

    assert result.status == "pass"
    assert result.logo_url == "https://example.com/logo.svg"
    primary.lookup_txt.assert_awaited_once()
    fallback.lookup_txt.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_bimi_cached_reuses_fresh_result(db_session):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=BIMI1; l=https://example.com/logo.svg"])

    first, first_cached, first_checked = await check_bimi_cached(
        db_session, provider, "example.com"
    )
    second, second_cached, second_checked = await check_bimi_cached(
        db_session, provider, "example.com"
    )

    assert first.status == "pass"
    assert first_cached is False
    assert second_cached is True
    assert second.logo_url == "https://example.com/logo.svg"
    assert second_checked == first_checked
    assert provider.lookup_txt.await_count == 1


@pytest.mark.asyncio
async def test_check_bimi_cached_recovers_from_concurrent_insert(db_session, monkeypatch):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=BIMI1; l=https://example.com/logo.svg"])
    original_commit = db_session.commit
    original_rollback = db_session.rollback
    commit_calls = 0

    def fake_commit():
        nonlocal commit_calls
        commit_calls += 1
        if commit_calls == 1:
            raise IntegrityError("insert", {}, Exception("duplicate"))
        original_commit()

    def fake_rollback():
        original_rollback()
        db_session.add(
            DNSCache(
                domain="example.com",
                provider=f"{provider.__class__.__name__}:bimi",
                selectors_key="bimi-v1:default",
                result_json=(
                    '{"certificate_url":null,"dns_record":null,"errors":["missing"],'
                    '"evidence_url":null,"logo_url":null,"query_name":"default._bimi.example.com",'
                    '"selector":"default","status":"fail","warnings":[]}'
                ),
                checked_at=datetime(2026, 5, 23, 12, 0, 0),
            )
        )
        original_commit()

    monkeypatch.setattr(db_session, "commit", fake_commit)
    monkeypatch.setattr(db_session, "rollback", fake_rollback)

    result, cached, _checked = await check_bimi_cached(db_session, provider, "example.com")

    assert result.status == "pass"
    assert cached is False
    assert db_session.query(DNSCache).count() == 1
