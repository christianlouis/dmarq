"""Database-backed DNS result cache."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dns_cache import DNSCache
from app.services.dns_provider_detection import detection_from_json
from app.services.dns_resolver import BaseDNSProvider, DomainDNSResult

DEFAULT_DNS_CACHE_TTL_SECONDS = 900


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
    )


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


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

    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _result_from_json(row.result_json), True, row.checked_at

    result = await provider.check_domain(domain, selectors=selectors)
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
