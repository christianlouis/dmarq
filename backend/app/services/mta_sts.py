"""MTA-STS posture checks for monitored domains."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dns_cache import DNSCache
from app.services.dns_cache import DEFAULT_DNS_CACHE_TTL_SECONDS
from app.services.dns_resolver import BaseDNSProvider

_CACHE_KEY = "mta-sts-v1"
_POLICY_TIMEOUT_SECONDS = 5.0
_VALID_MODES = {"enforce", "testing", "none"}


@dataclass
class MTAStsResult:
    """Operator-facing MTA-STS posture evidence."""

    status: str = "fail"
    dns_record: Optional[str] = None
    policy_url: Optional[str] = None
    policy_text: Optional[str] = None
    mode: Optional[str] = None
    max_age: Optional[int] = None
    mx: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _result_from_json(value: str) -> MTAStsResult:
    data = json.loads(value)
    return MTAStsResult(
        status=str(data.get("status") or "fail"),
        dns_record=data.get("dns_record"),
        policy_url=data.get("policy_url"),
        policy_text=data.get("policy_text"),
        mode=data.get("mode"),
        max_age=data.get("max_age"),
        mx=list(data.get("mx") or []),
        errors=list(data.get("errors") or []),
        warnings=list(data.get("warnings") or []),
    )


def parse_mta_sts_record(records: List[str]) -> Tuple[Optional[str], List[str], List[str]]:
    """Return the selected MTA-STS TXT record, warnings, and errors."""
    sts_records = [record for record in records if record.lower().startswith("v=stsv1")]
    if not sts_records:
        return None, [], ["No _mta-sts TXT record was found."]
    warnings = []
    if len(sts_records) > 1:
        warnings.append("Multiple _mta-sts TXT records were found; publish exactly one.")
    record = sts_records[0]
    tags = {
        part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip()
        for part in record.split(";")
        if "=" in part
    }
    errors = []
    if tags.get("v", "").lower() != "stsv1":
        errors.append("The _mta-sts TXT record must start with v=STSv1.")
    if not tags.get("id"):
        errors.append("The _mta-sts TXT record must include a non-empty id tag.")
    return record, warnings, errors


def parse_mta_sts_policy(  # noqa: C901
    policy_text: str,
) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """Parse and validate an MTA-STS policy file."""
    data: Dict[str, Any] = {"mx": []}
    for raw_line in policy_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mx":
            data.setdefault("mx", []).append(value)
        else:
            data[key] = value

    errors = []
    warnings = []
    if str(data.get("version", "")).upper() != "STSV1":
        errors.append("The policy file must contain version: STSv1.")
    mode = str(data.get("mode", "")).lower()
    if mode not in _VALID_MODES:
        errors.append("The policy file must contain mode: enforce, testing, or none.")
    elif mode in {"testing", "none"}:
        warnings.append(f"MTA-STS policy is valid but not enforcing mail delivery ({mode}).")
    try:
        max_age = int(str(data.get("max_age", "")))
        if max_age <= 0:
            errors.append("The policy max_age must be greater than zero.")
        data["max_age"] = max_age
    except ValueError:
        errors.append("The policy file must contain an integer max_age value.")
    if not data.get("mx"):
        errors.append("The policy file must contain at least one mx entry.")
    return data, warnings, errors


async def check_mta_sts(domain: str, provider: BaseDNSProvider) -> MTAStsResult:
    """Resolve the MTA-STS TXT record and validate the HTTPS policy file."""
    result = MTAStsResult(policy_url=f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
    try:
        records = await provider.lookup_txt(f"_mta-sts.{domain}")
    except LookupError as exc:
        result.errors.append(f"MTA-STS DNS lookup failed: {exc}")
        return result

    record, warnings, errors = parse_mta_sts_record(records)
    result.dns_record = record
    result.warnings.extend(warnings)
    result.errors.extend(errors)
    if record is None:
        return result

    try:
        async with httpx.AsyncClient(
            timeout=_POLICY_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            response = await client.get(result.policy_url)
            response.raise_for_status()
            result.policy_text = response.text
    except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException) as exc:
        result.errors.append(f"MTA-STS policy fetch failed: {exc}")
        return result

    policy, policy_warnings, policy_errors = parse_mta_sts_policy(result.policy_text or "")
    result.warnings.extend(policy_warnings)
    result.errors.extend(policy_errors)
    result.mode = policy.get("mode")
    result.max_age = policy.get("max_age")
    result.mx = list(policy.get("mx") or [])
    result.status = "pass" if not result.errors else "fail"
    return result


async def check_mta_sts_cached(
    db: Session,
    provider: BaseDNSProvider,
    domain: str,
    *,
    ttl_seconds: int = DEFAULT_DNS_CACHE_TTL_SECONDS,
    refresh: bool = False,
) -> Tuple[MTAStsResult, bool, datetime]:
    """Resolve MTA-STS posture, reusing the shared DNS cache semantics."""
    now = _utcnow_naive()
    provider_name = f"{provider.__class__.__name__}:mta-sts"
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == domain,
            DNSCache.provider == provider_name,
            DNSCache.selectors_key == _CACHE_KEY,
        )
        .first()
    )
    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _result_from_json(row.result_json), True, row.checked_at

    result = await check_mta_sts(domain, provider)
    payload = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
    if row is None:
        row = DNSCache(
            domain=domain,
            provider=provider_name,
            selectors_key=_CACHE_KEY,
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
                DNSCache.selectors_key == _CACHE_KEY,
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
