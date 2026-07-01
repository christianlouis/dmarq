from unittest.mock import AsyncMock

import pytest

from app.services.dane import check_dane, check_dane_cached, parse_tlsa_record
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
async def test_check_dane_reports_partial_mx_coverage_and_invalid_records():
    provider = FakeDANEDNSProvider(
        mx_hosts=["mx1.example.com", "mx2.example.com"],
        tlsa_records={
            "_25._tcp.mx1.example.com": ["3 1 1 not-hex"],
        },
    )

    result = await check_dane("example.com", provider)

    assert result.status == "partial"
    assert result.mx_hosts == ["mx1.example.com", "mx2.example.com"]
    assert result.records[0].valid is False
    assert "No TLSA records were found for MX host(s): mx2.example.com" in result.errors
    assert "TLSA records need syntax review for MX host(s): mx1.example.com" in result.errors


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
