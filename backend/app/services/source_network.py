"""Network ownership enrichment for observed sender IPs."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.dns_cache import DNSCache
from app.services.dns_fallbacks import dns_fallback_candidates
from app.services.dns_resolver import BaseDNSProvider

_CACHE_PROVIDER = "source-network-intelligence-v1"
_SELECTORS_KEY = "source-network-v4"
_ERROR_CACHE_TTL_SECONDS = 300
_ASN_NAME_CACHE: Dict[str, str] = {}
_IPINFO_LITE_URL = "https://api.ipinfo.io/lite"
_IPGEOLOCATION_URL = "https://api.ipgeolocation.io/v3/ipgeo"
_CLOUDFLARE_RADAR_IP_URL = "https://api.cloudflare.com/client/v4/radar/entities/ip"

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
class SourceNetworkIntelligence:  # pylint: disable=too-many-instance-attributes
    """Network ownership and routing context for one source IP."""

    ip: str
    asn: Optional[str] = None
    as_name: Optional[str] = None
    bgp_prefix: Optional[str] = None
    country_code: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    registry: Optional[str] = None
    allocated: Optional[str] = None
    organization: Optional[str] = None
    domain: Optional[str] = None
    cloudflare_location: Optional[str] = None
    cloudflare_asn_name: Optional[str] = None
    cloudflare_asn_org_name: Optional[str] = None
    radar_url: Optional[str] = None
    source: str = "unknown"
    checked_at: str = ""
    error: Optional[str] = None
    dns_retry_pending: bool = False


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


def _network_lookup_candidates(provider: Any) -> List[Any]:
    """Return independent DNS candidates for production resolver providers."""
    if isinstance(provider, BaseDNSProvider):
        return list(dns_fallback_candidates(provider))
    return [provider]


async def _lookup_as_name(provider: Any, asn: str) -> Optional[str]:
    normalized = _normalize_asn(asn)
    if not normalized:
        return None
    if normalized in _ASN_NAME_CACHE:
        return _ASN_NAME_CACHE[normalized]
    query = _asn_name_query(normalized)
    if not query:
        return None
    for candidate in _network_lookup_candidates(provider):
        try:
            as_name = _as_name_from_cymru_txt(await candidate.lookup_txt(query))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug(
                "ASN name lookup failed for %s via %s: %s",
                normalized,
                candidate.__class__.__name__,
                type(exc).__name__,
            )
            continue
        if as_name:
            _ASN_NAME_CACHE[normalized] = as_name
            return as_name
    return None


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


def _radar_url(ip: str) -> str:
    return f"https://radar.cloudflare.com/ip/{quote(ip, safe='')}"


def _first(*values: Optional[str]) -> Optional[str]:
    for value in values:
        if value not in {None, ""}:
            return value
    return None


def _merge_network_results(
    ip: str,
    *results: Optional[SourceNetworkIntelligence],
) -> Optional[SourceNetworkIntelligence]:
    usable = [result for result in results if result and not result.error]
    if not usable:
        return None

    sources: List[str] = []
    for result in usable:
        if result.source and result.source not in sources:
            sources.append(result.source)

    return SourceNetworkIntelligence(
        ip=ip,
        asn=_first(*(result.asn for result in usable)),
        as_name=_first(*(result.as_name for result in usable)),
        bgp_prefix=_first(*(result.bgp_prefix for result in usable)),
        country_code=_first(*(result.country_code for result in usable)),
        country=_first(*(result.country for result in usable)),
        region=_first(*(result.region for result in usable)),
        city=_first(*(result.city for result in usable)),
        latitude=_first(*(result.latitude for result in usable)),
        longitude=_first(*(result.longitude for result in usable)),
        registry=_first(*(result.registry for result in usable)),
        allocated=_first(*(result.allocated for result in usable)),
        organization=_first(*(result.organization for result in usable)),
        domain=_first(*(result.domain for result in usable)),
        cloudflare_location=_first(*(result.cloudflare_location for result in usable)),
        cloudflare_asn_name=_first(*(result.cloudflare_asn_name for result in usable)),
        cloudflare_asn_org_name=_first(*(result.cloudflare_asn_org_name for result in usable)),
        radar_url=_radar_url(ip),
        source=", ".join(sources),
        checked_at=_utcnow_iso(),
    )


def _set_when_missing(
    target: Dict[str, Any],
    key: str,
    value: Optional[str],
    *,
    missing_values: set[Any],
) -> None:
    if value and target.get(key) in missing_values:
        target[key] = value


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
            radar_url=_radar_url(ip),
            source="team-cymru",
            checked_at=checked_at,
        )
    return SourceNetworkIntelligence(
        ip=ip,
        source="team-cymru",
        checked_at=checked_at,
        error="No ASN record returned.",
    )


async def _lookup_cymru_network(
    provider: Any,
    ip: str,
    checked_at: str,
) -> SourceNetworkIntelligence:
    query = _query_name(ip)
    lookup_errors: List[Exception] = []
    completed_lookup = False
    for candidate in _network_lookup_candidates(provider):
        try:
            records = await candidate.lookup_txt(query)
            completed_lookup = True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            lookup_errors.append(exc)
            logger.debug(
                "ASN origin lookup failed for %s via %s: %s",
                ip,
                candidate.__class__.__name__,
                type(exc).__name__,
            )
            continue
        result = _from_cymru_txt(ip, records)
        if result.error:
            continue
        if result.asn and not result.as_name:
            result.as_name = await _lookup_as_name(candidate, result.asn)
        return result

    error = "No ASN record returned."
    if lookup_errors and not completed_lookup:
        error = f"ASN lookup failed: {type(lookup_errors[-1]).__name__}."
    return SourceNetworkIntelligence(
        ip=ip,
        source="team-cymru",
        checked_at=checked_at,
        error=error,
    )


def _ipinfo_network_sync(
    ip: str, token: str, timeout: float
) -> Optional[SourceNetworkIntelligence]:
    request = Request(
        f"{_IPINFO_LITE_URL}/{quote(ip, safe='')}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "DMARQ source intelligence",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed API host.
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return None
    if not isinstance(payload, dict):
        return None

    asn = _normalize_asn(str(payload.get("asn") or ""))
    country_code = str(payload.get("country_code") or "").upper() or None
    region = str(payload.get("continent") or "").strip() or COUNTRY_REGIONS.get(country_code or "")
    return SourceNetworkIntelligence(
        ip=ip,
        asn=asn,
        as_name=str(payload.get("as_name") or "").strip() or None,
        bgp_prefix=str(payload.get("network") or "").strip() or None,
        country_code=country_code,
        country=str(payload.get("country") or "").strip() or COUNTRY_NAMES.get(country_code or ""),
        region=region or None,
        domain=str(payload.get("as_domain") or "").strip() or None,
        radar_url=_radar_url(ip),
        source="ipinfo-lite",
        checked_at=_utcnow_iso(),
    )


def _ipgeolocation_network_sync(
    ip: str,
    api_key: str,
    timeout: float,
) -> Optional[SourceNetworkIntelligence]:
    query = urlencode({"apiKey": api_key, "ip": ip})
    request = Request(
        f"{_IPGEOLOCATION_URL}?{query}",
        headers={
            "Accept": "application/json",
            "User-Agent": "DMARQ source intelligence",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed API host.
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return None
    if not isinstance(payload, dict):
        return None

    asn_payload = payload.get("asn") if isinstance(payload.get("asn"), dict) else {}
    location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
    country_code = (
        str(
            location.get("country_code2")
            or location.get("country_code")
            or asn_payload.get("country")
            or ""
        ).upper()
        or None
    )
    return SourceNetworkIntelligence(
        ip=ip,
        asn=_normalize_asn(str(asn_payload.get("as_number") or payload.get("asn") or "")),
        as_name=str(asn_payload.get("organization") or "").strip() or None,
        bgp_prefix=str(asn_payload.get("route") or asn_payload.get("network") or "").strip()
        or None,
        country_code=country_code,
        country=str(location.get("country_name") or "").strip()
        or COUNTRY_NAMES.get(country_code or ""),
        region=str(location.get("continent_name") or "").strip()
        or COUNTRY_REGIONS.get(country_code or ""),
        city=str(location.get("city") or "").strip() or None,
        latitude=str(location.get("latitude") or "").strip() or None,
        longitude=str(location.get("longitude") or "").strip() or None,
        organization=str(asn_payload.get("organization") or "").strip() or None,
        radar_url=_radar_url(ip),
        source="ipgeolocation",
        checked_at=_utcnow_iso(),
    )


def _cloudflare_radar_network_sync(
    ip: str,
    token: str,
    timeout: float,
) -> Optional[SourceNetworkIntelligence]:
    query = urlencode({"ip": ip, "format": "JSON"})
    request = Request(
        f"{_CLOUDFLARE_RADAR_IP_URL}?{query}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "DMARQ source intelligence",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed API host.
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return None
    if not isinstance(payload, dict) or payload.get("success") is False:
        return None

    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    ip_payload = result.get("ip") if isinstance(result.get("ip"), dict) else {}
    country_code = str(ip_payload.get("location") or "").upper() or None
    asn_org = str(ip_payload.get("asnOrgName") or "").strip() or None
    asn_name = str(ip_payload.get("asnName") or "").strip() or None
    return SourceNetworkIntelligence(
        ip=ip,
        asn=_normalize_asn(str(ip_payload.get("asn") or "")),
        as_name=asn_org or asn_name,
        country_code=country_code,
        country=str(ip_payload.get("locationName") or "").strip()
        or COUNTRY_NAMES.get(country_code or ""),
        organization=asn_org,
        cloudflare_location=str(ip_payload.get("locationName") or "").strip() or None,
        cloudflare_asn_name=asn_name,
        cloudflare_asn_org_name=asn_org,
        radar_url=_radar_url(ip),
        source="cloudflare-radar",
        checked_at=_utcnow_iso(),
    )


async def _lookup_ipinfo_network(ip: str) -> Optional[SourceNetworkIntelligence]:
    settings = get_settings()
    token = (getattr(settings, "IPINFO_TOKEN", None) or "").strip()
    if not token:
        return None
    return await asyncio.to_thread(
        _ipinfo_network_sync,
        ip,
        token,
        getattr(settings, "IPINFO_TIMEOUT_SECONDS", 2.0),
    )


async def _lookup_ipgeolocation_network(ip: str) -> Optional[SourceNetworkIntelligence]:
    settings = get_settings()
    api_key = (getattr(settings, "IPGEOLOCATION_API_KEY", None) or "").strip()
    if not api_key:
        return None
    return await asyncio.to_thread(
        _ipgeolocation_network_sync,
        ip,
        api_key,
        getattr(settings, "IPGEOLOCATION_TIMEOUT_SECONDS", 2.0),
    )


async def _lookup_cloudflare_radar_network(ip: str) -> Optional[SourceNetworkIntelligence]:
    settings = get_settings()
    token = (
        getattr(settings, "CLOUDFLARE_RADAR_API_TOKEN", None)
        or getattr(settings, "CLOUDFLARE_API_TOKEN", None)
        or ""
    ).strip()
    if not token:
        return None
    return await asyncio.to_thread(
        _cloudflare_radar_network_sync,
        ip,
        token,
        getattr(settings, "CLOUDFLARE_RADAR_TIMEOUT_SECONDS", 2.0),
    )


async def lookup_source_network(
    provider: Any,
    ip: str,
) -> SourceNetworkIntelligence:
    """Lookup ASN and network context for one public IP."""
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

    ipinfo_result = await _lookup_ipinfo_network(ip)
    ipgeolocation_result = await _lookup_ipgeolocation_network(ip)
    cloudflare_radar_result = await _lookup_cloudflare_radar_network(ip)
    api_merged = _merge_network_results(
        ip,
        ipinfo_result,
        ipgeolocation_result,
        cloudflare_radar_result,
    )
    if api_merged and api_merged.asn and api_merged.country_code:
        return api_merged

    result = await _lookup_cymru_network(provider, ip, checked_at)
    merged = _merge_network_results(
        ip,
        ipinfo_result,
        ipgeolocation_result,
        cloudflare_radar_result,
        result,
    )
    if merged and result.error:
        merged.error = result.error
        merged.dns_retry_pending = True
    return merged or result


async def _retry_cached_dns_enrichment(
    provider: Any,
    cached_result: SourceNetworkIntelligence,
) -> SourceNetworkIntelligence:
    """Retry only Cymru DNS while retaining successful API enrichment."""
    checked_at = _utcnow_iso()
    dns_result = await _lookup_cymru_network(provider, cached_result.ip, checked_at)
    cached_data = replace(
        cached_result,
        checked_at=checked_at,
        error=None,
        dns_retry_pending=False,
    )
    merged = _merge_network_results(cached_result.ip, cached_data, dns_result)
    if merged and dns_result.error:
        merged.error = dns_result.error
        merged.dns_retry_pending = True
    return merged or dns_result


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
    cached_result: Optional[SourceNetworkIntelligence] = None
    if row and not refresh:
        cached_result = _from_json(row.result_json)
        cache_ttl = (
            min(ttl_seconds, _ERROR_CACHE_TTL_SECONDS) if cached_result.error else ttl_seconds
        )
        if _is_fresh(row, cache_ttl, now):
            return cached_result, True, row.checked_at

    if cached_result and cached_result.dns_retry_pending:
        result = await _retry_cached_dns_enrichment(provider, cached_result)
    else:
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


def merge_network_into_geo(  # noqa: C901 - centralizes source metadata precedence rules.
    geo: Dict[str, Any],
    network: Optional[SourceNetworkIntelligence],
) -> Dict[str, Any]:
    """Return source geo metadata enriched with ASN/network ownership."""
    merged = dict(geo)
    if network is None:
        return merged

    empty = {None, ""}
    _set_when_missing(merged, "country_code", network.country_code, missing_values={*empty, "ZZ"})
    _set_when_missing(merged, "country", network.country, missing_values={*empty, "Unknown"})
    _set_when_missing(merged, "region", network.region, missing_values={*empty, "Unknown"})
    _set_when_missing(merged, "city", network.city, missing_values=empty)
    _set_when_missing(merged, "latitude", network.latitude, missing_values=empty)
    _set_when_missing(merged, "longitude", network.longitude, missing_values=empty)
    _set_when_missing(merged, "asn", network.asn, missing_values=empty)
    _set_when_missing(merged, "network", network.as_name, missing_values=empty)

    merged["bgp_prefix"] = network.bgp_prefix
    merged["registry"] = network.registry
    merged["allocated"] = network.allocated
    merged["organization"] = network.organization
    merged["domain"] = network.domain
    merged["cloudflare_location"] = network.cloudflare_location
    merged["cloudflare_asn_name"] = network.cloudflare_asn_name
    merged["cloudflare_asn_org_name"] = network.cloudflare_asn_org_name
    merged["radar_url"] = network.radar_url
    merged["network_source"] = network.source
    merged["network_checked_at"] = network.checked_at
    if network.error:
        merged["network_error"] = network.error
    elif merged.get("source") == "inferred":
        merged["source"] = "network"
    return merged
