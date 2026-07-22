"""Reliable PTR enrichment with fallback resolvers and typed failure modes."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple

from app.services.dns_fallbacks import dns_fallback_candidates
from app.services.dns_resolver import (
    CloudflareDNSProvider,
    DemoDNSProvider,
    PublicRecursiveDNSProvider,
    SystemDNSProvider,
    _ip_to_arpa_name,
)

logger = logging.getLogger(__name__)

# Authoritative outcomes may be cached; transient failures must not be.
_POSITIVE_CACHE_TTL_SECONDS = 3_600
_NXDOMAIN_CACHE_TTL_SECONDS = 300
_PTR_RESULT_CACHE: Dict[str, Tuple["PtrLookupResult", float]] = {}

_STATUS_OK = "ok"
_STATUS_NXDOMAIN = "nxdomain"
_STATUS_TIMEOUT = "timeout"
_STATUS_REFUSED = "refused"
_STATUS_SERVFAIL = "servfail"
_STATUS_TRANSIENT = "transient"
_STATUS_INVALID = "invalid"
_STATUS_SKIPPED = "skipped"
_STATUS_UNAVAILABLE = "unavailable"

_TRANSIENT_STATUSES = {
    _STATUS_TIMEOUT,
    _STATUS_REFUSED,
    _STATUS_SERVFAIL,
    _STATUS_TRANSIENT,
}


@dataclass(frozen=True)
class PtrLookupResult:
    """Structured PTR outcome suitable for API/UI diagnostics (no secrets)."""

    hostname: Optional[str] = None
    status: str = _STATUS_UNAVAILABLE
    detail: str = ""
    provider: Optional[str] = None
    authoritative_negative: bool = False

    @property
    def cacheable(self) -> bool:
        return bool(self.hostname) or self.authoritative_negative

    @property
    def transient(self) -> bool:
        return self.status in _TRANSIENT_STATUSES

    def as_public_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["transient"] = self.transient
        return payload


def clear_ptr_lookup_cache() -> None:
    """Test helper: drop process-local PTR cache."""
    _PTR_RESULT_CACHE.clear()


def ptr_label(result: Optional[PtrLookupResult]) -> str:
    """Human-readable PTR status for UI surfaces."""
    if result is None:
        return "PTR unavailable"
    if result.hostname:
        return f"PTR {result.hostname}"
    labels = {
        _STATUS_NXDOMAIN: "PTR unavailable — no PTR record (NXDOMAIN)",
        _STATUS_TIMEOUT: "PTR unavailable — resolver timeout (will retry)",
        _STATUS_REFUSED: "PTR unavailable — resolver refused the query (will retry)",
        _STATUS_SERVFAIL: "PTR unavailable — resolver failure (will retry)",
        _STATUS_TRANSIENT: "PTR unavailable — transient DNS error (will retry)",
        _STATUS_SKIPPED: "PTR skipped — address is not a global unicast IP",
        _STATUS_INVALID: "PTR skipped — invalid IP address",
    }
    if result.status in labels:
        return labels[result.status]
    detail = (result.detail or "").strip()
    if detail:
        return f"PTR unavailable — {detail}"
    return "PTR unavailable"


def _cache_key(ip: str) -> str:
    return ip.strip().lower()


def _cache_get(ip: str) -> Optional[PtrLookupResult]:
    key = _cache_key(ip)
    cached = _PTR_RESULT_CACHE.get(key)
    if cached is None:
        return None
    result, expires_at = cached
    if expires_at <= time.monotonic():
        _PTR_RESULT_CACHE.pop(key, None)
        return None
    return result


def _cache_put(ip: str, result: PtrLookupResult) -> None:
    if not result.cacheable:
        return
    ttl = (
        _POSITIVE_CACHE_TTL_SECONDS
        if result.hostname
        else _NXDOMAIN_CACHE_TTL_SECONDS
    )
    _PTR_RESULT_CACHE[_cache_key(ip)] = (result, time.monotonic() + ttl)


def _classify_dnspython_exc(exc: BaseException) -> PtrLookupResult:
    import dns.exception  # type: ignore[import]
    import dns.resolver  # type: ignore[import]

    if isinstance(exc, dns.resolver.NXDOMAIN):
        return PtrLookupResult(
            status=_STATUS_NXDOMAIN,
            detail="authoritative NXDOMAIN",
            authoritative_negative=True,
        )
    if isinstance(exc, (dns.exception.Timeout, asyncio.TimeoutError)):
        return PtrLookupResult(status=_STATUS_TIMEOUT, detail="DNS query timed out")
    if isinstance(exc, dns.resolver.NoNameservers):
        return PtrLookupResult(status=_STATUS_REFUSED, detail="no usable nameservers")
    message = str(exc).lower()
    if "refused" in message:
        return PtrLookupResult(status=_STATUS_REFUSED, detail="resolver refused the query")
    if "servfail" in message or "server failure" in message:
        return PtrLookupResult(status=_STATUS_SERVFAIL, detail="resolver SERVFAIL")
    if isinstance(exc, dns.exception.DNSException):
        return PtrLookupResult(status=_STATUS_TRANSIENT, detail=type(exc).__name__)
    return PtrLookupResult(status=_STATUS_TRANSIENT, detail=type(exc).__name__)


async def _dnspython_ptr(provider: Any, ip: str) -> PtrLookupResult:
    import dns.asyncresolver  # type: ignore[import]
    import dns.exception  # type: ignore[import]
    import dns.resolver  # type: ignore[import]

    try:
        ptr_name = _ip_to_arpa_name(ip)
    except ValueError:
        return PtrLookupResult(status=_STATUS_INVALID, detail="invalid IP address")

    try:
        if isinstance(provider, PublicRecursiveDNSProvider) and hasattr(provider, "_resolve"):
            answers = await provider._resolve(ptr_name, "PTR")  # pylint: disable=protected-access
        else:
            answers = await dns.asyncresolver.resolve(
                ptr_name, "PTR", lifetime=3.0, raise_on_no_answer=False
            )
        if answers:
            for rdata in answers:
                hostname = str(rdata).rstrip(".")
                if hostname:
                    return PtrLookupResult(
                        hostname=hostname,
                        status=_STATUS_OK,
                        detail="PTR record found",
                        provider=provider.__class__.__name__,
                    )
        return PtrLookupResult(
            status=_STATUS_NXDOMAIN,
            detail="no PTR answer",
            provider=provider.__class__.__name__,
            authoritative_negative=True,
        )
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.exception.DNSException) as exc:
        classified = _classify_dnspython_exc(exc)
        return PtrLookupResult(
            status=classified.status,
            detail=classified.detail,
            provider=provider.__class__.__name__,
            authoritative_negative=classified.authoritative_negative,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return PtrLookupResult(
            status=_STATUS_TRANSIENT,
            detail=type(exc).__name__,
            provider=provider.__class__.__name__,
        )


def _doh_status_result(provider_name: str, status_code: int) -> Optional[PtrLookupResult]:
    mapping = {
        3: PtrLookupResult(
            status=_STATUS_NXDOMAIN,
            detail="DoH NXDOMAIN",
            provider=provider_name,
            authoritative_negative=True,
        ),
        5: PtrLookupResult(
            status=_STATUS_REFUSED,
            detail="DoH REFUSED",
            provider=provider_name,
        ),
        2: PtrLookupResult(
            status=_STATUS_SERVFAIL,
            detail="DoH SERVFAIL",
            provider=provider_name,
        ),
    }
    return mapping.get(status_code)


def _doh_payload_result(provider_name: str, data: Dict[str, Any]) -> PtrLookupResult:
    """Convert a DNS-over-HTTPS response payload into a typed PTR result."""
    status_code = int(data.get("Status", -1) or -1)
    mapped = _doh_status_result(provider_name, status_code)
    if mapped is not None:
        return mapped

    for answer in data.get("Answer", []) or []:
        if answer.get("type") == 12:
            hostname = str(answer.get("data") or "").rstrip(".")
            if hostname:
                return PtrLookupResult(
                    hostname=hostname,
                    status=_STATUS_OK,
                    detail="PTR record found",
                    provider=provider_name,
                )

    if status_code == 0:
        return PtrLookupResult(
            status=_STATUS_NXDOMAIN,
            detail="DoH NOERROR with empty PTR answer",
            provider=provider_name,
            authoritative_negative=True,
        )
    return PtrLookupResult(
        status=_STATUS_TRANSIENT,
        detail=f"DoH status {status_code}",
        provider=provider_name,
    )


async def _cloudflare_ptr(provider: CloudflareDNSProvider, ip: str) -> PtrLookupResult:
    import httpx  # type: ignore[import]

    try:
        ptr_name = _ip_to_arpa_name(ip)
    except ValueError:
        return PtrLookupResult(status=_STATUS_INVALID, detail="invalid IP address")

    params = {"name": ptr_name, "type": "PTR"}
    headers = {"Accept": "application/dns-json"}
    provider_name = provider.__class__.__name__
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                provider.CLOUDFLARE_DOH_URL,
                params=params,
                headers=headers,
                timeout=3.0,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        return PtrLookupResult(
            status=_STATUS_TIMEOUT,
            detail="DoH query timed out",
            provider=provider_name,
        )
    except (httpx.RequestError, httpx.HTTPStatusError) as exc:
        return PtrLookupResult(
            status=_STATUS_TRANSIENT,
            detail=type(exc).__name__,
            provider=provider_name,
        )

    return _doh_payload_result(provider_name, data)


async def _provider_ptr(provider: Any, ip: str) -> PtrLookupResult:
    if isinstance(provider, DemoDNSProvider):
        hostname = await provider.lookup_ptr(ip)
        if hostname:
            return PtrLookupResult(
                hostname=str(hostname).rstrip("."),
                status=_STATUS_OK,
                detail="demo PTR map",
                provider=provider.__class__.__name__,
            )
        return PtrLookupResult(
            status=_STATUS_NXDOMAIN,
            detail="no demo PTR mapping",
            provider=provider.__class__.__name__,
            authoritative_negative=True,
        )
    if isinstance(provider, CloudflareDNSProvider):
        return await _cloudflare_ptr(provider, ip)
    if isinstance(provider, (SystemDNSProvider, PublicRecursiveDNSProvider)):
        return await _dnspython_ptr(provider, ip)

    try:
        hostname = await provider.lookup_ptr(ip)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return PtrLookupResult(
            status=_STATUS_TRANSIENT,
            detail=type(exc).__name__,
            provider=provider.__class__.__name__,
        )
    if hostname:
        return PtrLookupResult(
            hostname=str(hostname).rstrip("."),
            status=_STATUS_OK,
            detail="PTR record found",
            provider=provider.__class__.__name__,
        )
    return PtrLookupResult(
        status=_STATUS_UNAVAILABLE,
        detail="provider returned no PTR",
        provider=provider.__class__.__name__,
    )


async def _lookup_candidate(
    candidate: Any,
    ip: str,
    *,
    timeout: float,
) -> PtrLookupResult:
    try:
        async with asyncio.timeout(timeout):
            return await _provider_ptr(candidate, ip)
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        return PtrLookupResult(
            status=_STATUS_TIMEOUT,
            detail="lookup timed out",
            provider=candidate.__class__.__name__,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.debug(
            "PTR lookup provider failed",
            extra={
                "provider": candidate.__class__.__name__,
                "ip": ip,
                "error": type(exc).__name__,
            },
        )
        return PtrLookupResult(
            status=_STATUS_TRANSIENT,
            detail=type(exc).__name__,
            provider=candidate.__class__.__name__,
        )


async def lookup_ptr_with_fallbacks(  # noqa: C901
    provider: Any,
    ip: str,
    *,
    timeout: float = 3.0,
    use_cache: bool = True,
) -> PtrLookupResult:
    """Resolve PTR using configured fallback resolvers with typed failure modes."""
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return PtrLookupResult(status=_STATUS_INVALID, detail="invalid IP address")
    if not parsed_ip.is_global:
        return PtrLookupResult(status=_STATUS_SKIPPED, detail="non-global IP")

    if use_cache:
        cached = _cache_get(ip)
        if cached is not None:
            return cached

    candidates = dns_fallback_candidates(provider)
    last_result = PtrLookupResult(status=_STATUS_UNAVAILABLE, detail="no resolver candidates")
    for candidate in candidates:
        result = await _lookup_candidate(candidate, ip, timeout=timeout)
        last_result = result
        if result.hostname:
            if use_cache:
                _cache_put(ip, result)
            return result
        if result.authoritative_negative:
            continue

    preferred = last_result
    if use_cache and preferred.cacheable:
        _cache_put(ip, preferred)
    return preferred


async def safe_ptr_hostname(
    provider: Any,
    ip: str,
    *,
    timeout: float = 3.0,
) -> Optional[str]:
    """Compatibility wrapper returning only the PTR hostname."""
    result = await lookup_ptr_with_fallbacks(provider, ip, timeout=timeout)
    return result.hostname
