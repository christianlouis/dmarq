from unittest.mock import AsyncMock

import pytest

from app.services.dane import (
    TLSASuggestion,
    _derive_tlsa_suggestions,
    check_dane,
    check_dane_cached,
    parse_tlsa_record,
)
from app.services.dns_resolver import BaseDNSProvider


class FakeDANEDNSProvider(BaseDNSProvider):
    def __init__(self, mx_hosts=None, tlsa_records=None):
        self.mx_hosts = mx_hosts or []
        self.tlsa_records = tlsa_records or {}
        self.lookup_mx = AsyncMock(return_value=self.mx_hosts)
        self.lookup_tlsa = AsyncMock(side_effect=self._lookup_tlsa)

    async def lookup_txt(self, name: str):  # pragma: no cover - unused protocol method
        raise LookupError(name)

    async def _lookup_tlsa(self, name: str):
        return list(self.tlsa_records.get(name, []))


def test_parse_tlsa_record_accepts_valid_dane_ee_spki_hash():
    record = parse_tlsa_record(
        "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        query_name="_25._tcp.mx.example.com",
        mx_host="mx.example.com",
    )

    assert record.valid is True
    assert record.certificate_usage == 3
    assert record.selector == 1
    assert record.matching_type == 1
    assert record.errors == []


def test_parse_tlsa_record_accepts_grouped_association_data():
    record = parse_tlsa_record(
        "3 1 1 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef",
        query_name="_25._tcp.mx.example.com",
        mx_host="mx.example.com",
    )

    assert record.valid is True
    assert (
        record.association_data
        == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )
    assert record.errors == []


def test_parse_tlsa_record_rejects_bad_fields():
    record = parse_tlsa_record(
        "9 4 8 not-hex",
        query_name="_25._tcp.mx.example.com",
        mx_host="mx.example.com",
    )

    assert record.valid is False
    assert "TLSA certificate usage must be 0, 1, 2, or 3." in record.errors
    assert "TLSA selector must be 0 for full certificate or 1 for SPKI." in record.errors
    assert "TLSA matching type must be 0, 1, or 2." in record.errors
    assert "TLSA association data must be hexadecimal." in record.errors


@pytest.mark.asyncio
async def test_check_dane_requires_mx_hosts():
    provider = FakeDANEDNSProvider(mx_hosts=[])

    result = await check_dane("example.com", provider)

    assert result.status == "fail"
    assert result.records == []
    assert result.errors == ["No MX hosts were found for DANE/TLSA evaluation."]


@pytest.mark.asyncio
async def test_check_dane_reports_fail_when_all_records_are_invalid_or_missing():
    provider = FakeDANEDNSProvider(
        mx_hosts=["mx1.example.com", "mx2.example.com"],
        tlsa_records={
            "_25._tcp.mx1.example.com": ["3 1 1 not-hex"],
        },
    )

    result = await check_dane("example.com", provider)

    assert result.status == "fail"
    assert result.mx_hosts == ["mx1.example.com", "mx2.example.com"]
    assert result.records[0].valid is False
    assert "No TLSA records were found for MX host(s): mx2.example.com" in result.errors
    assert "TLSA records need syntax review for MX host(s): mx1.example.com" in result.errors


@pytest.mark.asyncio
async def test_check_dane_reports_partial_mx_coverage_with_one_valid_host():
    provider = FakeDANEDNSProvider(
        mx_hosts=["mx1.example.com", "mx2.example.com"],
        tlsa_records={
            "_25._tcp.mx1.example.com": [
                "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ],
        },
    )

    result = await check_dane("example.com", provider)

    assert result.status == "partial"
    assert result.mx_hosts == ["mx1.example.com", "mx2.example.com"]
    assert result.records[0].valid is True
    assert "No TLSA records were found for MX host(s): mx2.example.com" in result.errors


@pytest.mark.asyncio
async def test_check_dane_derives_live_tlsa_suggestion(monkeypatch):
    provider = FakeDANEDNSProvider(mx_hosts=["mx1.example.com"])

    async def fake_suggestions(mx_hosts, *, port, timeout=5.0):
        assert mx_hosts == ["mx1.example.com"]
        assert port == 25
        return [
            TLSASuggestion(
                query_name="_25._tcp.mx1.example.com",
                mx_host="mx1.example.com",
                record=(
                    "3 1 1 " "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                association_data="a" * 64,
                status="ready",
            )
        ]

    monkeypatch.setattr("app.services.dane._derive_tlsa_suggestions", fake_suggestions)

    result = await check_dane("example.com", provider, derive_suggestions=True)

    assert result.status == "fail"
    assert result.suggested_records[0].record == "3 1 1 " + "a" * 64
    assert "No TLSA records were found for MX host(s): mx1.example.com" in result.errors


@pytest.mark.asyncio
async def test_check_dane_flags_live_tlsa_mismatch(monkeypatch):
    provider = FakeDANEDNSProvider(
        mx_hosts=["mx1.example.com"],
        tlsa_records={
            "_25._tcp.mx1.example.com": [
                "3 1 1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ],
        },
    )

    async def fake_suggestions(mx_hosts, *, port, timeout=5.0):
        return [
            TLSASuggestion(
                query_name="_25._tcp.mx1.example.com",
                mx_host="mx1.example.com",
                record=(
                    "3 1 1 " "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                association_data="a" * 64,
                status="ready",
            )
        ]

    monkeypatch.setattr("app.services.dane._derive_tlsa_suggestions", fake_suggestions)

    result = await check_dane("example.com", provider, derive_suggestions=True)

    assert result.status == "fail"
    assert any(
        "do not match the live SMTP STARTTLS certificate" in error for error in result.errors
    )
    assert any("does not match the live SMTP" in warning for warning in result.records[0].warnings)


@pytest.mark.asyncio
async def test_check_dane_accepts_matching_live_tlsa_suggestion(monkeypatch):
    provider = FakeDANEDNSProvider(
        mx_hosts=["mx1.example.com"],
        tlsa_records={
            "_25._tcp.mx1.example.com": [
                "3 1 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
        },
    )

    async def fake_suggestions(mx_hosts, *, port, timeout=5.0):
        return [
            TLSASuggestion(
                query_name="_25._tcp.mx1.example.com",
                mx_host="mx1.example.com",
                record=(
                    "3 1 1 " "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                association_data="a" * 64,
                status="ready",
            )
        ]

    monkeypatch.setattr("app.services.dane._derive_tlsa_suggestions", fake_suggestions)

    result = await check_dane("example.com", provider, derive_suggestions=True)

    assert result.status == "pass"
    assert not any(
        "do not match the live SMTP STARTTLS certificate" in error for error in result.errors
    )
    assert not any(
        "does not match the live SMTP" in warning for warning in result.records[0].warnings
    )


@pytest.mark.asyncio
async def test_derive_tlsa_suggestions_keeps_host_failures_as_data(monkeypatch):
    def fake_suggestion(mx_host, port, timeout):
        if mx_host == "mx1.example.com":
            raise RuntimeError("transient STARTTLS failure")
        return TLSASuggestion(
            query_name="_25._tcp.mx2.example.com",
            mx_host="mx2.example.com",
            record="3 1 1 " + "a" * 64,
            association_data="a" * 64,
            status="ready",
        )

    monkeypatch.setattr("app.services.dane._derive_tlsa_suggestion_sync", fake_suggestion)

    suggestions = await _derive_tlsa_suggestions(
        ["mx1.example.com", "mx2.example.com"],
        port=25,
    )

    assert suggestions[0].mx_host == "mx1.example.com"
    assert suggestions[0].status == "unavailable"
    assert "transient STARTTLS failure" in str(suggestions[0].error)
    assert suggestions[1].status == "ready"


@pytest.mark.asyncio
async def test_check_dane_filters_null_mx_marker():
    provider = FakeDANEDNSProvider(mx_hosts=["."])

    result = await check_dane("example.com", provider)

    assert result.status == "fail"
    assert result.mx_hosts == []
    assert result.errors == ["No MX hosts were found for DANE/TLSA evaluation."]
    provider.lookup_tlsa.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_dane_cached_reuses_fresh_result(db_session):
    provider = FakeDANEDNSProvider(
        mx_hosts=["mx.example.com"],
        tlsa_records={
            "_25._tcp.mx.example.com": [
                "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ],
        },
    )

    first, first_cached, first_checked = await check_dane_cached(
        db_session,
        provider,
        "example.com",
    )
    second, second_cached, second_checked = await check_dane_cached(
        db_session,
        provider,
        "example.com",
    )

    assert first.status == "pass"
    assert first_cached is False
    assert second.status == "pass"
    assert second_cached is True
    assert second_checked == first_checked
    provider.lookup_mx.assert_awaited_once()
    provider.lookup_tlsa.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_dane_cached_keeps_live_suggestions_in_separate_cache(
    db_session,
    monkeypatch,
):
    provider = FakeDANEDNSProvider(mx_hosts=["mx.example.com"])

    async def fake_suggestions(mx_hosts, *, port, timeout=5.0):
        return [
            TLSASuggestion(
                query_name="_25._tcp.mx.example.com",
                mx_host="mx.example.com",
                record=(
                    "3 1 1 " "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                association_data="a" * 64,
                status="ready",
            )
        ]

    monkeypatch.setattr("app.services.dane._derive_tlsa_suggestions", fake_suggestions)

    plain, plain_cached, _ = await check_dane_cached(db_session, provider, "example.com")
    live, live_cached, _ = await check_dane_cached(
        db_session,
        provider,
        "example.com",
        derive_suggestions=True,
    )

    assert plain_cached is False
    assert live_cached is False
    assert plain.suggested_records == []
    assert live.suggested_records[0].association_data == "a" * 64


def test_parse_tlsa_record_missing_parts():
    record = parse_tlsa_record(
        "3 1 1",
        query_name="_25._tcp.mx.example.com",
        mx_host="mx.example.com",
    )

    assert record.valid is False
    assert (
        "TLSA records must contain certificate usage, selector, matching type, and data."
        in record.errors
    )


def test_parse_tlsa_record_incomplete_bytes():
    record = parse_tlsa_record(
        "3 1 1 123",
        query_name="_25._tcp.mx.example.com",
        mx_host="mx.example.com",
    )

    assert record.valid is False
    assert "TLSA association data must contain complete bytes." in record.errors


def test_parse_tlsa_record_warnings():
    record = parse_tlsa_record(
        "0 1 0 0123456789abcdef",
        query_name="_25._tcp.mx.example.com",
        mx_host="mx.example.com",
    )

    assert record.valid is True
    assert (
        "PKIX TLSA usages still depend on public CA validation; usage 3 is common for DANE-EE."
        in record.warnings
    )
    assert (
        "Full-certificate TLSA values are bulky and rotate whenever the certificate changes."
        in record.warnings
    )


def test_parse_tlsa_record_empty_association_data():
    record = parse_tlsa_record(
        "3 1 1  ",
        query_name="_25._tcp.mx.example.com",
        mx_host="mx.example.com",
    )

    assert record.valid is False
    assert (
        "TLSA records must contain certificate usage, selector, matching type, and data."
        in record.errors
    )
