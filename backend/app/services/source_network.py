"""Network ownership enrichment for observed sender IPs."""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dns_cache import DNSCache

_CACHE_PROVIDER = "source-network-intelligence-v1"
_SELECTORS_KEY = "team-cymru-dns-v2"
_ASN_NAME_CACHE: Dict[str, str] = {}

logger = logging.getLogger(__name__)

COUNTRY_NAMES = {
    "AT": "Austria",
    "AU": "Australia",
    "BE": "Belgium",
    "BR": "Brazil",
    "CA": "Canada",
    "CH": "Switzerland",
    "CZ": "Czechia",
    "DE": "Germany",
    "DK": "Denmark",
    "ES": "Spain",
    "FI": "Finland",
    "FR": "France",
    "GB": "United Kingdom",
    "IE": "Ireland",
    "IN": "India",
    "IT": "Italy",
    "JP": "Japan",
    "NL": "Netherlands",
    "NO": "Norway",
    "PL": "Poland",
    "SE": "Sweden",
    "SG": "Singapore",
    "US": "United States",
}

COUNTRY_REGIONS = {
    "AT": "Europe",
    "BE": "Europe",
    "CH": "Europe",
    "CZ": "Europe",
    "DE": "Europe",
    "DK": "Europe",
    "ES": "Europe",
    "FI": "Europe",
    "FR": "Europe",
    "GB": "Europe",
    "IE": "Europe",
    "IT": "Europe",
    "NL": "Europe",
    "NO": "Europe",
    "PL": "Europe",
    "SE": "Europe",
    "AU": "Oceania",
    "BR": "South America",
    "CA": "North America",
    "IN": "Asia",
    "JP": "Asia",
    "SG": "Asia",
    "US": "North America",
}


@dataclass
class SourceNetworkIntelligence:
    """Network ownership and routing context for one source IP."""

    ip: str
    asn: Optional[str] = None
    as_name: Optional[str] = None
    bgp_prefix: Optional[str] = None
    country_code: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    registry: Optional[str] = None
    allocated: Optional[str] = None
    source: str = "unknown"
    checked_at: str = ""
    error: Optional[str] = None


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _query_name(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return f"{'.'.join(reversed(str(address).split('.')))}.origin.asn.cymru.com"
    reversed_nibbles = ".".join(reversed(address.exploded.replace(":", "")))
    return f"{reversed_nibbles}.origin6.asn.cymru.com"


def _normalize_asn(value: str) -> Optional[str]:
    text = value.strip()
    if not text or text.upper() == "NA":
        return None
    return text if text.upper().startswith("AS") else f"AS{text}"


def _asn_name_query(asn: str) -> str:
    normalized = _normalize_asn(asn)
    if not normalized:
        return ""
    return f"{normalized}.asn.cymru.com"


def _iter_cymru_txt_parts(txt_records: Iterable[str]) -> Iterable[List[str]]:
    for record in txt_records:
        cleaned = str(record).strip().strip('"')
        if "|" not in cleaned or cleaned.lower().startswith("as |"):
            continue
        yield [part.strip().strip('"') for part in cleaned.split("|")]


def _as_name_from_cymru_txt(txt_records: Iterable[str]) -> Optional[str]:
    for parts in _iter_cymru_txt_parts(txt_records):
        if len(parts) >= 5 and parts[4]:
            return parts[4]
    return None


async def _lookup_as_name(provider: Any, asn: str) -> Optional[str]:
    normalized = _normalize_asn(asn)
    if not normalized:
        return None
    if normalized in _ASN_NAME_CACHE:
        return _ASN_NAME_CACHE[normalized]
    query = _asn_name_query(normalized)
    if not query:
        return None
    try:
        as_name = _as_name_from_cymru_txt(await provider.lookup_txt(query))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.debug(
            "ASN name lookup failed for %s: %s",
            normalized,
            type(exc).__name__,
        )
        return None
    if as_name:
        _ASN_NAME_CACHE[normalized] = as_name
    return as_name


def _normalize_global_source_ip(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if not address.is_global:
        return None
    return str(address)


def _from_json(value: str) -> SourceNetworkIntelligence:
    data = json.loads(value)
    return SourceNetworkIntelligence(**data)


def _from_cymru_txt(ip: str, txt_records: Iterable[str]) -> SourceNetworkIntelligence:
    checked_at = _utcnow_iso()
    for parts in _iter_cymru_txt_parts(txt_records):
        if len(parts) < 5:
            continue
        country_code = parts[2].upper() if parts[2] else None
        return SourceNetworkIntelligence(
            ip=ip,
            asn=_normalize_asn(parts[0]),
            bgp_prefix=parts[1] or None,
            country_code=country_code,
            country=COUNTRY_NAMES.get(country_code or ""),
            region=COUNTRY_REGIONS.get(country_code or ""),
            registry=parts[3].lower() if parts[3] else None,
            allocated=parts[4] or None,
            as_name=parts[5] if len(parts) >= 6 and parts[5] else None,
            source="team-cymru",
            checked_at=checked_at,
        )
    return SourceNetworkIntelligence(
        ip=ip,
        source="team-cymru",
        checked_at=checked_at,
        error="No ASN record returned.",
    )


async def lookup_source_network(
    provider: Any,
    ip: str,
) -> SourceNetworkIntelligence:
    """Lookup ASN and network context for one public IP using Team Cymru DNS."""
    checked_at = _utcnow_iso()
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return SourceNetworkIntelligence(
            ip=ip,
            source="local",
            checked_at=checked_at,
            error="Invalid source IP.",
        )
    if not address.is_global:
        return SourceNetworkIntelligence(
            ip=ip,
            source="local",
            checked_at=checked_at,
            error="Non-global IP address.",
        )

    try:
        records = await provider.lookup_txt(_query_name(ip))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return SourceNetworkIntelligence(
            ip=ip,
            source="team-cymru",
            checked_at=checked_at,
            error=f"ASN lookup failed: {type(exc).__name__}.",
        )
    result = _from_cymru_txt(ip, records)
    if result.asn and not result.as_name:
        result.as_name = await _lookup_as_name(provider, result.asn)
    return result


async def lookup_source_network_cached(
    db: Session,
    provider: Any,
    ip: str,
    *,
    ttl_seconds: int = 86_400,
    refresh: bool = False,
) -> Tuple[SourceNetworkIntelligence, bool, datetime]:
    """Lookup one IP network context with persistent cache semantics."""
    now = _utcnow_naive()
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == ip,
            DNSCache.provider == _CACHE_PROVIDER,
            DNSCache.selectors_key == _SELECTORS_KEY,
        )
        .first()
    )
    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _from_json(row.result_json), True, row.checked_at

    result = await lookup_source_network(provider, ip)
    payload = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
    if row is None:
        row = DNSCache(
            domain=ip,
            provider=_CACHE_PROVIDER,
            selectors_key=_SELECTORS_KEY,
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
                DNSCache.domain == ip,
                DNSCache.provider == _CACHE_PROVIDER,
                DNSCache.selectors_key == _SELECTORS_KEY,
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


async def lookup_sources_network_cached(
    db: Session,
    provider: Any,
    source_ips: Iterable[str],
    *,
    ttl_seconds: int = 86_400,
    max_ips: int = 100,
    refresh: bool = False,
) -> Dict[str, SourceNetworkIntelligence]:
    """Lookup network context for a bounded set of observed source IPs."""
    results: Dict[str, SourceNetworkIntelligence] = {}
    seen: set[str] = set()
    unique_ips: List[str] = []
    for raw_ip in source_ips:
        ip = _normalize_global_source_ip(raw_ip)
        if ip is None or ip in seen:
            continue
        seen.add(ip)
        unique_ips.append(ip)
        if len(unique_ips) >= max_ips:
            break
    for ip in unique_ips:
        result, _, _ = await lookup_source_network_cached(
            db,
            provider,
            ip,
            ttl_seconds=ttl_seconds,
            refresh=refresh,
        )
        results[ip] = result
    return results


def merge_network_into_geo(
    geo: Dict[str, Any],
    network: Optional[SourceNetworkIntelligence],
) -> Dict[str, Any]:
    """Return source geo metadata enriched with ASN/network ownership."""
    merged = dict(geo)
    if network is None:
        return merged
    if network.country_code and merged.get("country_code") in {None, "", "ZZ"}:
        merged["country_code"] = network.country_code
    if network.country and merged.get("country") in {None, "", "Unknown"}:
        merged["country"] = network.country
    if network.region and merged.get("region") in {None, "", "Unknown"}:
        merged["region"] = network.region
    if network.asn and not merged.get("asn"):
        merged["asn"] = network.asn
    if network.as_name and not merged.get("network"):
        merged["network"] = network.as_name
    merged["bgp_prefix"] = network.bgp_prefix
    merged["registry"] = network.registry
    merged["allocated"] = network.allocated
    merged["network_source"] = network.source
    merged["network_checked_at"] = network.checked_at
    if network.error:
        merged["network_error"] = network.error
    elif merged.get("source") == "inferred":
        merged["source"] = "network"
    return merged
