"""Database-backed DNS result cache."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dns_cache import DNSCache
from app.services.dns_provider_detection import detection_from_json
from app.services.dns_resolver import (
    BaseDNSProvider,
    CloudflareDNSProvider,
    DomainDNSResult,
    GoogleDNSProvider,
    SystemDNSProvider,
)

DEFAULT_DNS_CACHE_TTL_SECONDS = 900
NEGATIVE_DNS_CACHE_TTL_SECONDS = 60
STALE_DNS_EVIDENCE_GRACE_SECONDS = 86_400

logger = logging.getLogger(__name__)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _selectors_key(selectors: List[str]) -> str:
    payload = json.dumps(list(dict.fromkeys(selectors or [])), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _result_to_json(result: DomainDNSResult) -> str:
    return json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))


def _result_from_json(value: str) -> DomainDNSResult:
    data = json.loads(value)
    return DomainDNSResult(
        dmarc=bool(data.get("dmarc")),
        dmarc_record=data.get("dmarc_record"),
        spf=bool(data.get("spf")),
        spf_record=data.get("spf_record"),
        dkim=bool(data.get("dkim")),
        dkim_selectors=list(data.get("dkim_selectors") or []),
        dkim_record=data.get("dkim_record"),
        selectors_checked=list(data.get("selectors_checked") or []),
        dmarc_policy_domain=data.get("dmarc_policy_domain"),
        dmarc_discovery_method=data.get("dmarc_discovery_method"),
        dmarc_tags=dict(data.get("dmarc_tags") or {}),
        dmarc_warnings=list(data.get("dmarc_warnings") or []),
        dmarc_suggestions=list(data.get("dmarc_suggestions") or []),
        nameservers=list(data.get("nameservers") or []),
        dns_provider=detection_from_json(data.get("dns_provider")),
        lookup_status=str(data.get("lookup_status") or "ok"),
        lookup_error=data.get("lookup_error"),
    )


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _has_dns_evidence(result: DomainDNSResult) -> bool:
    return any(
        (
            result.dmarc,
            result.dmarc_record,
            result.spf,
            result.spf_record,
            result.dkim,
            result.dkim_record,
            result.dkim_selectors,
            result.nameservers,
            result.dmarc_policy_domain,
        )
    )


def _negative_ttl_for_result(result: DomainDNSResult, ttl_seconds: int) -> int:
    if _has_dns_evidence(result):
        return ttl_seconds
    return min(ttl_seconds, NEGATIVE_DNS_CACHE_TTL_SECONDS)


def _within_stale_evidence_grace(row: DNSCache, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=STALE_DNS_EVIDENCE_GRACE_SECONDS)


def _stale_cached_evidence(
    row: Optional[DNSCache],
    *,
    now: datetime,
    lookup_error: str,
) -> Optional[Tuple[DomainDNSResult, bool, datetime]]:
    if not row:
        return None
    cached_result = _result_from_json(row.result_json)
    if not _has_dns_evidence(cached_result) or not _within_stale_evidence_grace(row, now):
        return None

    cached_result.lookup_status = "stale_cache"
    cached_result.lookup_error = lookup_error
    return cached_result, True, row.checked_at


def _lookup_failure_result(error_type: str, now: datetime) -> Tuple[DomainDNSResult, bool, datetime]:
    return (
        DomainDNSResult(
            lookup_status="failed",
            lookup_error=f"DNS lookup failed with {error_type}.",
        ),
        False,
        now,
    )


async def _resolve_with_fallback(
    provider: BaseDNSProvider,
    domain: str,
    *,
    selectors: List[str],
) -> DomainDNSResult:
    """Resolve DNS, walking independent resolvers before accepting an empty result."""
    if not isinstance(
        provider,
        (SystemDNSProvider, CloudflareDNSProvider, GoogleDNSProvider),
    ):
        return await provider.check_domain(domain, selectors=selectors)

    fallback_types: List[type[BaseDNSProvider]] = [
        SystemDNSProvider,
        CloudflareDNSProvider,
        GoogleDNSProvider,
    ]
    provider_types = [provider.__class__] + [
        fallback_type
        for fallback_type in fallback_types
        if not isinstance(provider, fallback_type)
    ]
    last_result: Optional[DomainDNSResult] = None
    resolver_errors: List[str] = []

    for index, provider_type in enumerate(provider_types):
        candidate = provider if index == 0 else provider_type()
        try:
            result = await candidate.check_domain(domain, selectors=selectors)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            resolver_errors.append(f"{candidate.__class__.__name__}:{exc.__class__.__name__}")
            logger.debug(
                "DNS resolver %s failed with %s",
                candidate.__class__.__name__,
                exc.__class__.__name__,
            )
            continue

        if _has_dns_evidence(result):
            if index > 0:
                result.lookup_status = "fallback"
                result.lookup_error = (
                    f"No DNS evidence from {provider.__class__.__name__}; "
                    f"using {candidate.__class__.__name__}."
                )
            return result
        last_result = result

    if last_result is not None:
        if resolver_errors:
            last_result.lookup_status = "partial"
            last_result.lookup_error = (
                "No DNS evidence found after fallback resolver checks; "
                f"{len(resolver_errors)} resolver error(s) occurred."
            )
        return last_result

    raise LookupError(
        "All DNS resolvers failed: "
        + ", ".join(resolver_errors or ["no resolver attempted"])
    )


async def resolve_domain_dns_cached(
    db: Session,
    provider: BaseDNSProvider,
    domain: str,
    *,
    selectors: List[str],
    ttl_seconds: int = DEFAULT_DNS_CACHE_TTL_SECONDS,
    refresh: bool = False,
) -> Tuple[DomainDNSResult, bool, datetime]:
    """Resolve DNS for a domain, reusing a fresh cached result when available."""
    now = _utcnow_naive()
    provider_name = provider.__class__.__name__
    selectors_key = _selectors_key(selectors)
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == domain,
            DNSCache.provider == provider_name,
            DNSCache.selectors_key == selectors_key,
        )
        .first()
    )

    if row and not refresh:
        cached_result = _result_from_json(row.result_json)
        cache_ttl = _negative_ttl_for_result(cached_result, ttl_seconds)
        if _is_fresh(row, cache_ttl, now):
            return cached_result, True, row.checked_at

    try:
        result = await _resolve_with_fallback(provider, domain, selectors=selectors)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        stale = _stale_cached_evidence(
            row,
            now=now,
            lookup_error=(
                f"DNS lookup failed with {exc.__class__.__name__}; "
                "using the last known DNS evidence."
            ),
        )
        if stale:
            logger.warning(
                "DNS resolver failed; using last known DNS evidence for %s",
                provider_name,
            )
            return stale
        logger.warning(
            "DNS resolver failed with %s; returning lookup failure evidence",
            exc.__class__.__name__,
        )
        return _lookup_failure_result(exc.__class__.__name__, now)

    if not _has_dns_evidence(result):
        stale = _stale_cached_evidence(
            row,
            now=now,
            lookup_error="DNS resolver returned no DNS evidence; using the last known DNS cache.",
        )
        if stale:
            logger.warning(
                "DNS resolver returned no evidence; keeping last known DNS evidence for %s",
                provider_name,
            )
            return stale

    payload = _result_to_json(result)
    if row is None:
        row = DNSCache(
            domain=domain,
            provider=provider_name,
            selectors_key=selectors_key,
            result_json=payload,
            checked_at=now,
        )
        db.add(row)
    else:
        row.result_json = payload
        row.checked_at = now

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        row = (
            db.query(DNSCache)
            .filter(
                DNSCache.domain == domain,
                DNSCache.provider == provider_name,
                DNSCache.selectors_key == selectors_key,
            )
            .first()
        )
        if row is None:
            raise
        row.result_json = payload
        row.checked_at = now
        db.commit()

    db.refresh(row)
    return result, False, row.checked_at


def get_cached_domain_dns_result(
    db: Session,
    provider: BaseDNSProvider,
    domain: str,
    *,
    selectors: List[str],
) -> Tuple[Optional[DomainDNSResult], bool, Optional[datetime]]:
    """Return the latest cached DNS result without performing network lookups."""
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == domain,
            DNSCache.provider == provider.__class__.__name__,
            DNSCache.selectors_key == _selectors_key(selectors),
        )
        .first()
    )
    if row is None:
        return None, False, None
    return _result_from_json(row.result_json), True, row.checked_at
