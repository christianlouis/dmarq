"""BIMI DNS posture checks for monitored domains."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dns_cache import DNSCache
from app.services.dns_cache import DEFAULT_DNS_CACHE_TTL_SECONDS
from app.services.dns_fallbacks import dns_fallback_candidates
from app.services.dns_resolver import BaseDNSProvider

_CACHE_KEY_PREFIX = "bimi-v1"


@dataclass
class BIMIResult:
    """Operator-facing BIMI posture evidence."""

    status: str = "fail"
    selector: str = "default"
    query_name: str = ""
    dns_record: Optional[str] = None
    logo_url: Optional[str] = None
    certificate_url: Optional[str] = None
    evidence_url: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _result_from_json(value: str) -> BIMIResult:
    data = json.loads(value)
    return BIMIResult(
        status=str(data.get("status") or "fail"),
        selector=str(data.get("selector") or "default"),
        query_name=str(data.get("query_name") or ""),
        dns_record=data.get("dns_record"),
        logo_url=data.get("logo_url"),
        certificate_url=data.get("certificate_url"),
        evidence_url=data.get("evidence_url"),
        errors=list(data.get("errors") or []),
        warnings=list(data.get("warnings") or []),
    )


def _https_url(value: Optional[str]) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _tags(record: str) -> dict[str, str]:
    return {
        part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip()
        for part in record.split(";")
        if "=" in part
    }


def parse_bimi_record(records: List[str]) -> Tuple[Optional[BIMIResult], List[str], List[str]]:
    """Parse BIMI TXT records into a normalized result, warnings, and errors."""
    bimi_records = [record for record in records if record.lower().startswith("v=bimi1")]
    if not bimi_records:
        return None, [], ["No BIMI TXT record was found at the selector."]

    warnings: List[str] = []
    errors: List[str] = []
    if len(bimi_records) > 1:
        warnings.append("Multiple BIMI TXT records were found; publish exactly one.")

    record = bimi_records[0]
    tags = _tags(record)
    logo_url = tags.get("l")
    certificate_url = tags.get("a")
    if tags.get("v", "").lower() != "bimi1":
        errors.append("The BIMI TXT record must start with v=BIMI1.")
    if not logo_url:
        errors.append("The BIMI TXT record must include an l= HTTPS SVG logo URL.")
    elif not _https_url(logo_url):
        errors.append("The BIMI logo URL must use HTTPS.")
    elif not urlparse(logo_url).path.lower().endswith(".svg"):
        warnings.append("The BIMI logo URL should point to an SVG file.")

    if certificate_url and not _https_url(certificate_url):
        errors.append("The BIMI certificate URL must use HTTPS when present.")
    elif not certificate_url:
        warnings.append("No BIMI certificate URL is published; some mailbox providers require one.")

    result = BIMIResult(
        status="pass" if not errors else "fail",
        dns_record=record,
        logo_url=logo_url,
        certificate_url=certificate_url,
        evidence_url=logo_url,
        errors=errors,
        warnings=warnings,
    )
    return result, warnings, errors


async def check_bimi(
    domain: str,
    provider: BaseDNSProvider,
    *,
    selector: str = "default",
) -> BIMIResult:
    """Resolve and validate the BIMI TXT record for a domain selector."""
    normalized_selector = (selector or "default").strip().lower()
    query_name = f"{normalized_selector}._bimi.{domain}"
    result = BIMIResult(selector=normalized_selector, query_name=query_name)
    try:
        records = await provider.lookup_txt(query_name)
    except LookupError as exc:
        result.errors.append(f"BIMI DNS lookup failed: {exc}")
        return result

    parsed, warnings, errors = parse_bimi_record(records)
    if parsed is None:
        result.errors.extend(errors)
        return result
    parsed.selector = normalized_selector
    parsed.query_name = query_name
    parsed.warnings = warnings
    parsed.errors = errors
    return parsed


def _dns_lookup_failed(result: BIMIResult) -> bool:
    return any("DNS lookup failed" in error for error in result.errors)


async def check_bimi_with_fallback(
    domain: str,
    provider: BaseDNSProvider,
    *,
    selector: str = "default",
) -> BIMIResult:
    """Resolve BIMI with public fallback if the primary resolver fails."""
    first_result: Optional[BIMIResult] = None
    for candidate in dns_fallback_candidates(provider):
        result = await check_bimi(domain, candidate, selector=selector)
        if first_result is None:
            first_result = result
        if not _dns_lookup_failed(result):
            return result
    normalized_selector = (selector or "default").strip().lower()
    return first_result or BIMIResult(
        selector=normalized_selector,
        query_name=f"{normalized_selector}._bimi.{domain}",
        errors=["BIMI DNS lookup failed for all configured resolvers."],
    )


async def check_bimi_cached(
    db: Session,
    provider: BaseDNSProvider,
    domain: str,
    *,
    selector: str = "default",
    ttl_seconds: int = DEFAULT_DNS_CACHE_TTL_SECONDS,
    refresh: bool = False,
) -> Tuple[BIMIResult, bool, datetime]:
    """Resolve BIMI posture, reusing the shared DNS cache semantics."""
    normalized_selector = (selector or "default").strip().lower()
    cache_key = f"{_CACHE_KEY_PREFIX}:{normalized_selector}"
    now = _utcnow_naive()
    provider_name = f"{provider.__class__.__name__}:bimi"
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == domain,
            DNSCache.provider == provider_name,
            DNSCache.selectors_key == cache_key,
        )
        .first()
    )
    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _result_from_json(row.result_json), True, row.checked_at

    result = await check_bimi_with_fallback(domain, provider, selector=normalized_selector)
    payload = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
    if row is None:
        row = DNSCache(
            domain=domain,
            provider=provider_name,
            selectors_key=cache_key,
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
                DNSCache.selectors_key == cache_key,
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
