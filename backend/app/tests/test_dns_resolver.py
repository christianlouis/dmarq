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
    found, selectors, record = await provider.check_dkim("example.com", ["google", "mail"])
    assert found is True
    assert selectors == ["google"]
    assert record is not None


@pytest.mark.asyncio
async def test_check_dkim_found_second_selector():
    provider = FakeDNSProvider(
        {"mail._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3"]}
    )
    found, selectors, record = await provider.check_dkim("example.com", ["google", "mail"])
    assert found is True
    assert selectors == ["mail"]


@pytest.mark.asyncio
async def test_check_dkim_found_multiple_selectors():
    """When multiple selectors resolve, all are returned."""
    provider = FakeDNSProvider(
        {
            "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3"],
            "mail._domainkey.example.com": ["v=DKIM1; k=rsa; p=XYZ"],
        }
    )
    found, selectors, record = await provider.check_dkim("example.com", ["google", "mail"])
    assert found is True
    assert "google" in selectors
    assert "mail" in selectors
    assert len(selectors) == 2
    assert record is not None  # record of the first match


@pytest.mark.asyncio
async def test_check_dkim_not_found():
    provider = FakeDNSProvider({})
    found, selectors, record = await provider.check_dkim("example.com", ["google", "mail"])
    assert found is False
    assert selectors == []
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
    assert result.dkim_selectors == ["google"]


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
    assert result.dkim_selectors == ["default"]


@pytest.mark.asyncio
async def test_check_domain_manual_selectors_take_priority():
    """Manually supplied selectors must be checked before common ones."""
    # Only the manual selector 'custom' has a record
    provider = FakeDNSProvider({"custom._domainkey.example.com": ["v=DKIM1; k=rsa; p=XYZ"]})
    result = await provider.check_domain("example.com", selectors=["custom"])
    assert result.dkim is True
    assert result.dkim_selectors == ["custom"]


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


# ---------------------------------------------------------------------------
# _ip_to_arpa_name helper
# ---------------------------------------------------------------------------


def test_ip_to_arpa_name_ipv4():
    from app.services.dns_resolver import _ip_to_arpa_name

    assert _ip_to_arpa_name("1.2.3.4") == "4.3.2.1.in-addr.arpa"


def test_ip_to_arpa_name_ipv4_leading_zero_safe():
    from app.services.dns_resolver import _ip_to_arpa_name

    assert _ip_to_arpa_name("192.168.1.100") == "100.1.168.192.in-addr.arpa"


def test_ip_to_arpa_name_ipv6():
    from app.services.dns_resolver import _ip_to_arpa_name

    # 2001:db8::1 expanded → 20010db8000000000000000000000001
    name = _ip_to_arpa_name("2001:db8::1")
    assert name.endswith(".ip6.arpa")


def test_ip_to_arpa_name_invalid_raises():
    from app.services.dns_resolver import _ip_to_arpa_name

    with pytest.raises(ValueError):
        _ip_to_arpa_name("not-an-ip")


# ---------------------------------------------------------------------------
# BaseDNSProvider.lookup_ptr (default returns None)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_base_provider_lookup_ptr_returns_none():
    """FakeDNSProvider only implements lookup_txt; lookup_ptr must return None."""
    provider = FakeDNSProvider({})
    result = await provider.lookup_ptr("1.2.3.4")
    assert result is None


# ---------------------------------------------------------------------------
# SystemDNSProvider.lookup_ptr
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_system_provider_lookup_ptr_returns_hostname():
    """SystemDNSProvider.lookup_ptr should decode the first PTR rdata."""

    class FakePTRRdata:
        def __str__(self):
            return "mail.example.com."

    class FakePTRAnswers:
        def __iter__(self):
            return iter([FakePTRRdata()])

    with patch("dns.asyncresolver.resolve", new=AsyncMock(return_value=FakePTRAnswers())):
        provider = SystemDNSProvider()
        hostname = await provider.lookup_ptr("1.2.3.4")

    # Trailing dot should be stripped
    assert hostname == "mail.example.com"


@pytest.mark.asyncio
async def test_system_provider_lookup_ptr_returns_none_on_nxdomain():
    import dns.exception  # type: ignore[import]

    with patch(
        "dns.asyncresolver.resolve",
        new=AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN")),
    ):
        provider = SystemDNSProvider()
        hostname = await provider.lookup_ptr("1.2.3.4")

    assert hostname is None


@pytest.mark.asyncio
async def test_system_provider_lookup_ptr_returns_none_for_invalid_ip():
    provider = SystemDNSProvider()
    result = await provider.lookup_ptr("not-an-ip")
    assert result is None


# ---------------------------------------------------------------------------
# CloudflareDNSProvider.lookup_ptr
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cloudflare_provider_lookup_ptr_returns_hostname():
    """CloudflareDNSProvider.lookup_ptr should extract the PTR name from DoH JSON."""
    from unittest.mock import MagicMock

    fake_response_data = {
        "Answer": [
            {"type": 12, "data": "mail.example.com."},
            {"type": 1, "data": "93.184.216.34"},  # A record — should be ignored
        ]
    }

    mock_response = AsyncMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = lambda: fake_response_data

    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
        provider = CloudflareDNSProvider()
        hostname = await provider.lookup_ptr("1.2.3.4")

    assert hostname == "mail.example.com"


@pytest.mark.asyncio
async def test_cloudflare_provider_lookup_ptr_returns_none_when_no_ptr():
    """CloudflareDNSProvider.lookup_ptr returns None when no PTR answer exists."""
    from unittest.mock import MagicMock

    fake_response_data = {"Answer": []}

    mock_response = AsyncMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = lambda: fake_response_data

    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
        provider = CloudflareDNSProvider()
        hostname = await provider.lookup_ptr("1.2.3.4")

    assert hostname is None


@pytest.mark.asyncio
async def test_cloudflare_provider_lookup_ptr_returns_none_for_invalid_ip():
    provider = CloudflareDNSProvider()
    result = await provider.lookup_ptr("not-an-ip")
    assert result is None
