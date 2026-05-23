from datetime import datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from app.models.dns_cache import DNSCache
from app.services.mta_sts import (
    _CACHE_KEY,
    MTAStsResult,
    check_mta_sts,
    check_mta_sts_cached,
    parse_mta_sts_policy,
    parse_mta_sts_record,
)


def test_parse_mta_sts_record_requires_single_record_with_id():
    record, warnings, errors = parse_mta_sts_record(["v=STSv1; id=20260523"])

    assert record == "v=STSv1; id=20260523"
    assert warnings == []
    assert errors == []


def test_parse_mta_sts_record_reports_missing_id_and_multiple_records():
    record, warnings, errors = parse_mta_sts_record(["v=STSv1", "v=STSv1; id=two"])

    assert record == "v=STSv1"
    assert warnings == ["Multiple _mta-sts TXT records were found; publish exactly one."]
    assert "id tag" in errors[0]


def test_parse_mta_sts_record_reports_missing_and_malformed_versions():
    missing_record, missing_warnings, missing_errors = parse_mta_sts_record([])
    malformed_record, malformed_warnings, malformed_errors = parse_mta_sts_record(
        ["v=STSv1x; id=bad"]
    )

    assert missing_record is None
    assert missing_warnings == []
    assert missing_errors == ["No _mta-sts TXT record was found."]
    assert malformed_record == "v=STSv1x; id=bad"
    assert malformed_warnings == []
    assert malformed_errors == ["The _mta-sts TXT record must start with v=STSv1."]


def test_parse_mta_sts_policy_validates_required_fields():
    policy, warnings, errors = parse_mta_sts_policy(
        "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400\n"
    )

    assert policy["mode"] == "testing"
    assert policy["mx"] == ["mail.example.com"]
    assert policy["max_age"] == 86400
    assert warnings == ["MTA-STS policy is valid but not enforcing mail delivery (testing)."]
    assert errors == []


def test_parse_mta_sts_policy_reports_invalid_fields():
    policy, warnings, errors = parse_mta_sts_policy(
        "# comment\nignored line\nmode: invalid\nmax_age: 0\n"
    )
    bad_age_policy, bad_age_warnings, bad_age_errors = parse_mta_sts_policy(
        "version: STSv1\nmode: enforce\nmax_age: nope\n"
    )

    assert policy["max_age"] == 0
    assert warnings == []
    assert "version: STSv1" in errors[0]
    assert "mode: enforce, testing, or none" in errors[1]
    assert "greater than zero" in errors[2]
    assert "at least one mx" in errors[3]
    assert bad_age_policy["mode"] == "enforce"
    assert bad_age_warnings == []
    assert "integer max_age" in bad_age_errors[0]
    assert "at least one mx" in bad_age_errors[1]


class _FakeAsyncClient:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def get(self, _url):
        return self.response


@pytest.mark.asyncio
async def test_check_mta_sts_validates_dns_and_policy(monkeypatch):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=STSv1; id=20260523"])
    request = httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt")
    response = httpx.Response(
        200,
        text="version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n",
        request=request,
    )
    monkeypatch.setattr(
        "app.services.mta_sts.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(response),
    )

    result = await check_mta_sts("example.com", provider)

    assert result.status == "pass"
    assert result.dns_record == "v=STSv1; id=20260523"
    assert result.mode == "enforce"
    assert result.mx == ["*.example.com"]
    assert result.errors == []


@pytest.mark.asyncio
async def test_check_mta_sts_cached_reuses_fresh_result(db_session, monkeypatch):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=STSv1; id=20260523"])
    request = httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt")
    response = httpx.Response(
        200,
        text="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
        request=request,
    )
    monkeypatch.setattr(
        "app.services.mta_sts.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(response),
    )

    first, first_cached, first_checked = await check_mta_sts_cached(
        db_session, provider, "example.com"
    )
    second, second_cached, second_checked = await check_mta_sts_cached(
        db_session, provider, "example.com"
    )

    assert isinstance(first, MTAStsResult)
    assert first.status == "pass"
    assert first_cached is False
    assert second.status == "pass"
    assert second_cached is True
    assert isinstance(first_checked, datetime)
    assert second_checked == first_checked
    provider.lookup_txt.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_mta_sts_returns_missing_record_without_policy_fetch(monkeypatch):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=[])
    fetch_attempted = False

    class _UnexpectedAsyncClient:
        async def __aenter__(self):
            nonlocal fetch_attempted
            fetch_attempted = True
            return self

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(
        "app.services.mta_sts.httpx.AsyncClient",
        lambda **_: _UnexpectedAsyncClient(),
    )

    result = await check_mta_sts("example.com", provider)

    assert result.status == "fail"
    assert result.errors == ["No _mta-sts TXT record was found."]
    assert fetch_attempted is False


@pytest.mark.asyncio
async def test_check_mta_sts_reports_policy_fetch_error(monkeypatch):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=STSv1; id=20260523"])
    request = httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt")
    response = httpx.Response(404, text="missing", request=request)
    monkeypatch.setattr(
        "app.services.mta_sts.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(response),
    )

    result = await check_mta_sts("example.com", provider)

    assert result.status == "fail"
    assert result.policy_text is None
    assert result.errors[0].startswith("MTA-STS policy fetch failed:")


@pytest.mark.asyncio
async def test_check_mta_sts_cached_refresh_updates_existing_row(db_session, monkeypatch):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=STSv1; id=20260523"])
    request = httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt")
    responses = [
        httpx.Response(
            200,
            text="version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400\n",
            request=request,
        ),
        httpx.Response(
            200,
            text="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
            request=request,
        ),
    ]
    monkeypatch.setattr(
        "app.services.mta_sts.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(responses.pop(0)),
    )

    first, first_cached, _first_checked = await check_mta_sts_cached(
        db_session, provider, "example.com"
    )
    second, second_cached, _second_checked = await check_mta_sts_cached(
        db_session, provider, "example.com", refresh=True
    )

    assert first.mode == "testing"
    assert first_cached is False
    assert second.mode == "enforce"
    assert second_cached is False
    assert db_session.query(DNSCache).count() == 1


@pytest.mark.asyncio
async def test_check_mta_sts_cached_recovers_from_concurrent_insert(db_session, monkeypatch):
    """Concurrent page widgets should not fail on a duplicate cache insert."""
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=STSv1; id=20260523"])
    request = httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt")
    response = httpx.Response(
        200,
        text="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
        request=request,
    )
    monkeypatch.setattr(
        "app.services.mta_sts.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(response),
    )

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
                provider=f"{provider.__class__.__name__}:mta-sts",
                selectors_key=_CACHE_KEY,
                result_json='{"status":"fail","errors":["stale"],"warnings":[],"mx":[]}',
                checked_at=datetime(2026, 5, 23, 12, 0, 0),
            )
        )
        original_commit()

    monkeypatch.setattr(db_session, "commit", fake_commit)
    monkeypatch.setattr(db_session, "rollback", fake_rollback)

    result, cached, _checked = await check_mta_sts_cached(db_session, provider, "example.com")

    assert result.status == "pass"
    assert cached is False
    assert db_session.query(DNSCache).count() == 1


@pytest.mark.asyncio
async def test_check_mta_sts_cached_reraises_when_conflict_row_missing(db_session, monkeypatch):
    provider = AsyncMock()
    provider.lookup_txt = AsyncMock(return_value=["v=STSv1; id=20260523"])
    request = httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt")
    response = httpx.Response(
        200,
        text="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
        request=request,
    )
    monkeypatch.setattr(
        "app.services.mta_sts.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(response),
    )

    def fake_commit():
        raise IntegrityError("insert", {}, Exception("duplicate"))

    monkeypatch.setattr(db_session, "commit", fake_commit)

    with pytest.raises(IntegrityError):
        await check_mta_sts_cached(db_session, provider, "example.com")
