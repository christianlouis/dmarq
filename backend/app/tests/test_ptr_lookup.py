"""Regression coverage for typed PTR lookup failure modes and caching."""

import asyncio

import dns.exception
import dns.resolver
import pytest

from app.services import ptr_lookup
from app.services.dns_resolver import BaseDNSProvider
from app.services.ptr_lookup import (
    PtrLookupResult,
    clear_ptr_lookup_cache,
    lookup_ptr_with_fallbacks,
    ptr_label,
)

# Use a globally routable documentation-safe public IP for enrichment tests.
_GLOBAL_IP = "8.8.8.8"


class _PrimaryTimeoutProvider(BaseDNSProvider):
    async def lookup_txt(self, _name):
        return []

    async def lookup_ptr(self, _ip):
        raise AssertionError("classified path should not call generic lookup_ptr")


@pytest.fixture(autouse=True)
def _reset_ptr_cache():
    clear_ptr_lookup_cache()
    yield
    clear_ptr_lookup_cache()


@pytest.mark.asyncio
async def test_lookup_ptr_distinguishes_nxdomain_timeout_and_refused(monkeypatch):
    calls = {"count": 0}

    async def fake_provider_ptr(provider, ip):  # pylint: disable=unused-argument
        calls["count"] += 1
        if calls["count"] == 1:
            return PtrLookupResult(status="timeout", detail="DNS query timed out", provider="P1")
        if calls["count"] == 2:
            return PtrLookupResult(status="refused", detail="resolver refused", provider="P2")
        return PtrLookupResult(
            status="nxdomain",
            detail="authoritative NXDOMAIN",
            provider="P3",
            authoritative_negative=True,
        )

    monkeypatch.setattr(ptr_lookup, "_provider_ptr", fake_provider_ptr)
    monkeypatch.setattr(
        ptr_lookup,
        "dns_fallback_candidates",
        lambda provider: [provider, object(), object()],
    )

    result = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), _GLOBAL_IP)

    assert result.status == "nxdomain"
    assert result.authoritative_negative is True
    assert result.hostname is None
    assert "NXDOMAIN" in ptr_label(result)


@pytest.mark.asyncio
async def test_transient_ptr_failures_are_not_cached_as_permanent(monkeypatch):
    calls = {"count": 0}

    async def fake_provider_ptr(provider, ip):  # pylint: disable=unused-argument
        calls["count"] += 1
        if calls["count"] == 1:
            return PtrLookupResult(
                status="timeout",
                detail="DNS query timed out",
                provider="Primary",
            )
        return PtrLookupResult(
            hostname="mail.example.net",
            status="ok",
            detail="PTR record found",
            provider="Fallback",
        )

    monkeypatch.setattr(ptr_lookup, "_provider_ptr", fake_provider_ptr)
    monkeypatch.setattr(
        ptr_lookup,
        "dns_fallback_candidates",
        lambda provider: [provider, object()],
    )

    first = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), _GLOBAL_IP)
    assert first.status == "ok"
    assert first.hostname == "mail.example.net"

    # Cache should store the successful answer, not the earlier timeout.
    second = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), _GLOBAL_IP)
    assert second.hostname == "mail.example.net"
    assert calls["count"] == 2  # second call served from cache (no extra provider hits)


@pytest.mark.asyncio
async def test_nxdomain_is_cached_but_timeout_alone_is_not(monkeypatch):
    calls = {"count": 0}

    async def timeout_then_nxdomain(provider, ip):  # pylint: disable=unused-argument
        calls["count"] += 1
        if calls["count"] == 1:
            return PtrLookupResult(status="timeout", detail="timed out", provider="Primary")
        return PtrLookupResult(
            status="nxdomain",
            detail="authoritative NXDOMAIN",
            provider="Fallback",
            authoritative_negative=True,
        )

    monkeypatch.setattr(ptr_lookup, "_provider_ptr", timeout_then_nxdomain)
    monkeypatch.setattr(
        ptr_lookup,
        "dns_fallback_candidates",
        lambda provider: [provider, object()],
    )

    first = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), _GLOBAL_IP)
    assert first.status == "nxdomain"
    assert first.cacheable is True

    second = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), _GLOBAL_IP)
    assert second.status == "nxdomain"
    assert calls["count"] == 2  # cached after authoritative negative


@pytest.mark.asyncio
async def test_authoritative_negative_wins_over_later_transient_failure(monkeypatch):
    calls = {"count": 0}

    async def nxdomain_then_timeout(provider, ip):  # pylint: disable=unused-argument
        calls["count"] += 1
        if calls["count"] == 1:
            return PtrLookupResult(
                status="nxdomain",
                detail="authoritative NXDOMAIN",
                provider="Primary",
                authoritative_negative=True,
            )
        return PtrLookupResult(status="timeout", detail="timed out", provider="Fallback")

    monkeypatch.setattr(ptr_lookup, "_provider_ptr", nxdomain_then_timeout)
    monkeypatch.setattr(
        ptr_lookup,
        "dns_fallback_candidates",
        lambda provider: [provider, object()],
    )

    result = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), _GLOBAL_IP)

    assert result.status == "nxdomain"
    assert result.authoritative_negative is True


def test_classify_dnspython_exc_maps_known_failure_modes():
    nx = ptr_lookup._classify_dnspython_exc(
        dns.resolver.NXDOMAIN()
    )  # pylint: disable=protected-access
    assert nx.status == "nxdomain"
    assert nx.authoritative_negative is True

    timeout = ptr_lookup._classify_dnspython_exc(
        dns.exception.Timeout()
    )  # pylint: disable=protected-access
    assert timeout.status == "timeout"

    refused = ptr_lookup._classify_dnspython_exc(  # pylint: disable=protected-access
        RuntimeError("REFUSED by upstream resolver")
    )
    assert refused.status == "refused"


@pytest.mark.asyncio
async def test_lookup_ptr_skips_non_global_and_invalid_ips():
    invalid = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), "not-an-ip")
    assert invalid.status == "invalid"
    assert invalid.hostname is None

    private = await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), "10.0.0.8")
    assert private.status == "skipped"


@pytest.mark.asyncio
async def test_cancelled_error_propagates_from_provider(monkeypatch):
    async def cancel_provider_ptr(provider, ip):  # pylint: disable=unused-argument
        raise asyncio.CancelledError()

    monkeypatch.setattr(ptr_lookup, "_provider_ptr", cancel_provider_ptr)
    monkeypatch.setattr(ptr_lookup, "dns_fallback_candidates", lambda provider: [provider])

    with pytest.raises(asyncio.CancelledError):
        await lookup_ptr_with_fallbacks(_PrimaryTimeoutProvider(), _GLOBAL_IP)
