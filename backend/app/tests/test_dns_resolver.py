"""
Unit tests for app.services.dns_resolver.

DNS network I/O is mocked at the ``lookup_txt`` level so no real DNS queries
are made during testing.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.dns_resolver import (
    BaseDNSProvider,
    CloudflareDNSProvider,
    DomainDNSResult,
    SystemDNSProvider,
    extract_dmarc_policy,
    get_default_provider,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeDNSProvider(BaseDNSProvider):
    """Concrete provider backed by a simple dict for deterministic tests."""

    def __init__(self, records: dict):
        self._records = records

    async def lookup_txt(self, name: str):
        if name in self._records:
            return self._records[name]
        raise LookupError(f"NXDOMAIN: {name}")


# ---------------------------------------------------------------------------
# extract_dmarc_policy
# ---------------------------------------------------------------------------


def test_extract_dmarc_policy_none():
    record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
    assert extract_dmarc_policy(record) == "none"


def test_extract_dmarc_policy_quarantine():
    record = "v=DMARC1; p=quarantine; pct=100"
    assert extract_dmarc_policy(record) == "quarantine"


def test_extract_dmarc_policy_reject():
    assert extract_dmarc_policy("v=DMARC1; p=reject") == "reject"


def test_extract_dmarc_policy_missing_tag():
    assert extract_dmarc_policy("v=DMARC1; rua=mailto:dmarc@example.com") is None


def test_extract_dmarc_policy_none_input():
    assert extract_dmarc_policy(None) is None


# ---------------------------------------------------------------------------
# BaseDNSProvider helpers via FakeDNSProvider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_dmarc_found():
    provider = FakeDNSProvider(
        {"_dmarc.example.com": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]}
    )
    found, record = await provider.check_dmarc("example.com")
    assert found is True
    assert record is not None
    assert "p=quarantine" in record


@pytest.mark.asyncio
async def test_check_dmarc_not_found():
    provider = FakeDNSProvider({})
    found, record = await provider.check_dmarc("example.com")
    assert found is False
    assert record is None


@pytest.mark.asyncio
async def test_check_spf_found():
    provider = FakeDNSProvider(
        {"example.com": ["v=spf1 include:_spf.google.com ~all", "some-other-record"]}
    )
    found, record = await provider.check_spf("example.com")
    assert found is True
    assert record is not None
    assert record.startswith("v=spf1")


@pytest.mark.asyncio
async def test_check_spf_not_found():
    provider = FakeDNSProvider({"example.com": ["some-other-record"]})
    found, record = await provider.check_spf("example.com")
    assert found is False
    assert record is None


@pytest.mark.asyncio
async def test_check_dkim_found_first_selector():
    provider = FakeDNSProvider(
        {"google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3"]}
    )
    found, selector, record = await provider.check_dkim("example.com", ["google", "mail"])
    assert found is True
    assert selector == "google"
    assert record is not None


@pytest.mark.asyncio
async def test_check_dkim_found_second_selector():
    provider = FakeDNSProvider(
        {"mail._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3"]}
    )
    found, selector, record = await provider.check_dkim("example.com", ["google", "mail"])
    assert found is True
    assert selector == "mail"


@pytest.mark.asyncio
async def test_check_dkim_not_found():
    provider = FakeDNSProvider({})
    found, selector, record = await provider.check_dkim("example.com", ["google", "mail"])
    assert found is False
    assert selector is None
    assert record is None


@pytest.mark.asyncio
async def test_check_domain_all_present():
    provider = FakeDNSProvider(
        {
            "_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
            "example.com": ["v=spf1 include:_spf.google.com ~all"],
            "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3"],
        }
    )
    result = await provider.check_domain("example.com", selectors=["google"])
    assert isinstance(result, DomainDNSResult)
    assert result.dmarc is True
    assert result.spf is True
    assert result.dkim is True
    assert result.dkim_selector == "google"


@pytest.mark.asyncio
async def test_check_domain_none_present():
    provider = FakeDNSProvider({})
    result = await provider.check_domain("missing.example.com")
    assert result.dmarc is False
    assert result.spf is False
    assert result.dkim is False


@pytest.mark.asyncio
async def test_check_domain_uses_common_selectors_as_fallback():
    """When no selectors are passed, common selectors should be tried."""
    # Use 'default' which is in COMMON_DKIM_SELECTORS
    provider = FakeDNSProvider({"default._domainkey.example.com": ["v=DKIM1; k=rsa; p=ABC"]})
    result = await provider.check_domain("example.com", selectors=[])
    assert result.dkim is True
    assert result.dkim_selector == "default"


@pytest.mark.asyncio
async def test_check_domain_manual_selectors_take_priority():
    """Manually supplied selectors must be checked before common ones."""
    # Only the manual selector 'custom' has a record
    provider = FakeDNSProvider({"custom._domainkey.example.com": ["v=DKIM1; k=rsa; p=XYZ"]})
    result = await provider.check_domain("example.com", selectors=["custom"])
    assert result.dkim is True
    assert result.dkim_selector == "custom"


# ---------------------------------------------------------------------------
# SystemDNSProvider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_system_provider_returns_txt_records():
    """SystemDNSProvider.lookup_txt should decode dnspython rdata correctly."""
    mock_string = b"v=DMARC1; p=none"

    class FakeRdata:
        strings = [mock_string]

    class FakeAnswers:
        def __iter__(self):
            return iter([FakeRdata()])

    with patch("dns.asyncresolver.resolve", new=AsyncMock(return_value=FakeAnswers())):
        provider = SystemDNSProvider()
        records = await provider.lookup_txt("_dmarc.example.com")

    assert records == ["v=DMARC1; p=none"]


@pytest.mark.asyncio
async def test_system_provider_raises_lookup_error_on_dns_exception():
    import dns.exception  # type: ignore[import]

    with patch(
        "dns.asyncresolver.resolve",
        new=AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN")),
    ):
        provider = SystemDNSProvider()
        with pytest.raises(LookupError):
            await provider.lookup_txt("nonexistent.example.com")


# ---------------------------------------------------------------------------
# CloudflareDNSProvider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cloudflare_provider_parses_doh_response():
    """CloudflareDNSProvider should parse the Cloudflare DoH JSON response."""
    from unittest.mock import MagicMock

    fake_response_data = {
        "Answer": [
            {"type": 16, "data": '"v=DMARC1; p=reject"'},
            {"type": 1, "data": "93.184.216.34"},  # A record — should be ignored
        ]
    }

    mock_response = AsyncMock()
    mock_response.raise_for_status = MagicMock()  # raise_for_status is synchronous in httpx
    mock_response.json = lambda: fake_response_data

    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
        provider = CloudflareDNSProvider()
        records = await provider.lookup_txt("_dmarc.example.com")

    assert records == ["v=DMARC1; p=reject"]


@pytest.mark.asyncio
async def test_cloudflare_provider_raises_on_http_error():
    import httpx

    with patch(
        "httpx.AsyncClient.get",
        new=AsyncMock(side_effect=httpx.RequestError("connection refused")),
    ):
        provider = CloudflareDNSProvider()
        with pytest.raises(LookupError):
            await provider.lookup_txt("_dmarc.example.com")


# ---------------------------------------------------------------------------
# get_default_provider
# ---------------------------------------------------------------------------


def test_get_default_provider_returns_system():
    provider = get_default_provider()
    assert isinstance(provider, SystemDNSProvider)
