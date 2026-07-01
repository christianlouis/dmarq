"""Read-only DANE/TLSA posture checks for monitored mail domains."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dns_cache import DNSCache
from app.services.dns_cache import DEFAULT_DNS_CACHE_TTL_SECONDS
from app.services.dns_resolver import BaseDNSProvider

_CACHE_KEY = "dane-v1"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_VALID_CERTIFICATE_USAGES = {0, 1, 2, 3}
_VALID_SELECTORS = {0, 1}
_VALID_MATCHING_TYPES = {0, 1, 2}


@dataclass
class TLSARecord:
    """One TLSA record observed for an MX host."""

    query_name: str
    mx_host: str
    record: str
    certificate_usage: Optional[int] = None
    selector: Optional[int] = None
    matching_type: Optional[int] = None
    association_data: Optional[str] = None
    valid: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class DANEResult:
    """Operator-facing DANE/TLSA posture evidence."""

    status: str = "fail"
    port: int = 25
    mx_hosts: List[str] = field(default_factory=list)
    records: List[TLSARecord] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _record_from_json(value: dict) -> TLSARecord:
    return TLSARecord(
        query_name=str(value.get("query_name") or ""),
        mx_host=str(value.get("mx_host") or ""),
        record=str(value.get("record") or ""),
        certificate_usage=value.get("certificate_usage"),
        selector=value.get("selector"),
        matching_type=value.get("matching_type"),
        association_data=value.get("association_data"),
        valid=bool(value.get("valid")),
        errors=list(value.get("errors") or []),
        warnings=list(value.get("warnings") or []),
    )


def _result_from_json(value: str) -> DANEResult:
    data = json.loads(value)
    return DANEResult(
        status=str(data.get("status") or "fail"),
        port=int(data.get("port") or 25),
        mx_hosts=list(data.get("mx_hosts") or []),
        records=[_record_from_json(row) for row in data.get("records") or []],
        errors=list(data.get("errors") or []),
        warnings=list(data.get("warnings") or []),
    )


def _safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_tlsa_record(record: str, *, query_name: str, mx_host: str) -> TLSARecord:
    """Parse a TLSA record and return normalized lint evidence."""
    result = TLSARecord(query_name=query_name, mx_host=mx_host, record=record)
    parts = record.split()
    if len(parts) < 4:
        result.errors.append(
            "TLSA records must contain certificate usage, selector, matching type, and data."
        )
        return result

    usage = _safe_int(parts[0])
    selector = _safe_int(parts[1])
    matching_type = _safe_int(parts[2])
    association_data = "".join(parts[3:]).strip()
    result.certificate_usage = usage
    result.selector = selector
    result.matching_type = matching_type
    result.association_data = association_data

    if usage not in _VALID_CERTIFICATE_USAGES:
        result.errors.append("TLSA certificate usage must be 0, 1, 2, or 3.")
    if selector not in _VALID_SELECTORS:
        result.errors.append("TLSA selector must be 0 for full certificate or 1 for SPKI.")
    if matching_type not in _VALID_MATCHING_TYPES:
        result.errors.append("TLSA matching type must be 0, 1, or 2.")
    if not association_data:
        result.errors.append("TLSA association data is empty.")
    elif not _HEX_RE.match(association_data):
        result.errors.append("TLSA association data must be hexadecimal.")
    elif len(association_data) % 2:
        result.errors.append("TLSA association data must contain complete bytes.")

    if usage in {0, 1}:
        result.warnings.append(
            "PKIX TLSA usages still depend on public CA validation; usage 3 is common for DANE-EE."
        )
    if matching_type == 0:
        result.warnings.append(
            "Full-certificate TLSA values are bulky and rotate whenever the certificate changes."
        )

    result.valid = not result.errors
    return result


async def check_dane(domain: str, provider: BaseDNSProvider, *, port: int = 25) -> DANEResult:
    """Resolve MX hosts and lint their SMTP DANE TLSA records."""
    normalized_domain = domain.strip().strip(".").lower()
    result = DANEResult(port=port)
    raw_mx_hosts = await provider.lookup_mx(normalized_domain)
    mx_hosts = raw_mx_hosts if isinstance(raw_mx_hosts, (list, tuple)) else []
    normalized_hosts = (str(host).strip(".").lower() for host in mx_hosts)
    result.mx_hosts = list(dict.fromkeys(host for host in normalized_hosts if host))
    if not result.mx_hosts:
        result.errors.append("No MX hosts were found for DANE/TLSA evaluation.")
        return result

    missing_hosts: List[str] = []
    invalid_hosts: List[str] = []
    for mx_host in result.mx_hosts:
        query_name = f"_{port}._tcp.{mx_host}"
        raw_records = await provider.lookup_tlsa(query_name)
        records = raw_records if isinstance(raw_records, (list, tuple)) else []
        if not records:
            missing_hosts.append(mx_host)
            continue
        parsed_records = [
            parse_tlsa_record(record, query_name=query_name, mx_host=mx_host) for record in records
        ]
        result.records.extend(parsed_records)
        if not any(record.valid for record in parsed_records):
            invalid_hosts.append(mx_host)

    if missing_hosts:
        result.errors.append(
            "No TLSA records were found for MX host(s): " + ", ".join(missing_hosts)
        )
    if invalid_hosts:
        result.errors.append(
            "TLSA records need syntax review for MX host(s): " + ", ".join(invalid_hosts)
        )
    if result.records:
        result.warnings.append(
            "DMARQ validates TLSA syntax and MX coverage, but does not yet validate DNSSEC chains "
            "or compare TLSA hashes with live SMTP certificates."
        )

    valid_hosts = {record.mx_host for record in result.records if record.valid}
    if not result.errors:
        result.status = "pass"
    elif valid_hosts:
        result.status = "partial"
    return result


async def check_dane_cached(
    db: Session,
    provider: BaseDNSProvider,
    domain: str,
    *,
    port: int = 25,
    ttl_seconds: int = DEFAULT_DNS_CACHE_TTL_SECONDS,
    refresh: bool = False,
) -> Tuple[DANEResult, bool, datetime]:
    """Resolve DANE posture, reusing the shared DNS cache semantics."""
    now = _utcnow_naive()
    normalized_domain = domain.strip().strip(".").lower()
    provider_name = f"{provider.__class__.__name__}:dane"
    cache_key = f"{_CACHE_KEY}:{port}"
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == normalized_domain,
            DNSCache.provider == provider_name,
            DNSCache.selectors_key == cache_key,
        )
        .first()
    )
    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _result_from_json(row.result_json), True, row.checked_at

    result = await check_dane(normalized_domain, provider, port=port)
    payload = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
    if row is None:
        row = DNSCache(
            domain=normalized_domain,
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
                DNSCache.domain == normalized_domain,
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
