"""Optional external sender reputation feed lookups.

External reputation feeds are disabled by default. They are intended to enrich
DMARC evidence when an operator explicitly opts in to provider terms, API
credentials, and lookup volume.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Protocol, Tuple

import dns.exception
import dns.resolver
import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.dns_cache import DNSCache
from app.services.dns_resolver import PUBLIC_RECURSIVE_NAMESERVERS

_CACHE_PROVIDER = "source-reputation-feed-v1"


@dataclass(frozen=True)
class FeedProviderConfig:
    """Runtime configuration for one external reputation provider."""

    provider_id: str
    display_name: str
    kind: str = "dnsbl"
    enabled: bool = False
    query_zone: Optional[str] = None
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    max_age_days: int = 90
    listed_threshold: int = 75
    listing_name: Optional[str] = None
    requires_terms: bool = True
    default_enabled: bool = False


@dataclass
class FeedLookupEvidence:
    """One external feed observation."""

    provider_id: str
    provider_name: str
    status: str
    listing: Optional[str] = None
    detail: Optional[str] = None
    checked_at: str = ""


@dataclass
class IPFeedReputation:
    """External feed result set for one IP."""

    ip: str
    listed: bool = False
    evidence: List[FeedLookupEvidence] = field(default_factory=list)


class ReputationFeedProvider(Protocol):
    """Provider interface for sender reputation feed lookups."""

    config: FeedProviderConfig

    async def lookup_ip(self, ip: str) -> FeedLookupEvidence:
        """Return reputation evidence for one IP."""


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _reverse_ip(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        raise ValueError("DNSBL providers in this registry currently support IPv4 sources only.")
    return ".".join(reversed(ip.split(".")))


class DNSBLFeedProvider:
    """DNSBL-backed reputation provider."""

    def __init__(
        self,
        config: FeedProviderConfig,
        *,
        timeout_seconds: float = 2.0,
        resolver: Optional[dns.resolver.Resolver] = None,
    ) -> None:
        self.config = config
        self.timeout_seconds = timeout_seconds
        self._resolver = resolver or self._public_resolver()
        self._resolver.lifetime = timeout_seconds
        self._resolver.timeout = timeout_seconds

    @staticmethod
    def _public_resolver() -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(PUBLIC_RECURSIVE_NAMESERVERS)
        return resolver

    async def lookup_ip(self, ip: str) -> FeedLookupEvidence:
        checked_at = _utcnow_iso()
        if not self.config.query_zone:
            return self._evidence(
                "not_configured",
                checked_at=checked_at,
                detail="Provider query zone is not configured.",
            )

        skipped = self._skip_reason(ip)
        if skipped:
            return self._evidence("skipped", checked_at=checked_at, detail=skipped)

        try:
            query_name = f"{_reverse_ip(ip)}.{self.config.query_zone.strip('.')}"
        except ValueError as exc:
            return self._evidence("skipped", checked_at=checked_at, detail=str(exc))
        try:
            answers = await asyncio.to_thread(self._resolver.resolve, query_name, "A")
        except dns.exception.DNSException as exc:
            return self._dns_error_evidence(exc, checked_at)

        values = [answer.to_text() for answer in answers]
        return self._evidence(
            "listed",
            checked_at=checked_at,
            listing=self.config.listing_name or self.config.display_name,
            detail=", ".join(values),
        )

    def _evidence(
        self,
        status: str,
        *,
        checked_at: str,
        listing: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> FeedLookupEvidence:
        return FeedLookupEvidence(
            provider_id=self.config.provider_id,
            provider_name=self.config.display_name,
            status=status,
            listing=listing,
            detail=detail,
            checked_at=checked_at,
        )

    @staticmethod
    def _skip_reason(ip: str) -> Optional[str]:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return "Invalid IP address."
        if not address.is_global:
            return "Non-global IPs are not sent to external reputation feeds."
        return None

    def _dns_error_evidence(
        self,
        exc: dns.exception.DNSException,
        checked_at: str,
    ) -> FeedLookupEvidence:
        if isinstance(exc, dns.resolver.NXDOMAIN):
            return self._evidence("clean", checked_at=checked_at)
        if isinstance(exc, dns.resolver.NoAnswer):
            return self._evidence(
                "clean",
                checked_at=checked_at,
                detail="No listing response returned.",
            )
        if isinstance(exc, dns.resolver.NoNameservers):
            return self._evidence(
                "error",
                checked_at=checked_at,
                detail="Provider nameservers are unavailable.",
            )
        if isinstance(exc, dns.exception.Timeout):
            return self._evidence("error", checked_at=checked_at, detail="Lookup timed out.")
        return self._evidence("error", checked_at=checked_at, detail=str(exc))


class AbuseIPDBFeedProvider:
    """AbuseIPDB API-backed abuse confidence provider."""

    def __init__(
        self,
        config: FeedProviderConfig,
        *,
        timeout_seconds: float = 2.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.config = config
        self.timeout_seconds = timeout_seconds
        self._client = client

    async def lookup_ip(self, ip: str) -> FeedLookupEvidence:
        checked_at = _utcnow_iso()
        if not self.config.api_key:
            return self._evidence(
                "not_configured",
                checked_at=checked_at,
                detail="Provider API key is not configured.",
            )

        skipped = DNSBLFeedProvider._skip_reason(ip)
        if skipped:
            return self._evidence("skipped", checked_at=checked_at, detail=skipped)

        url = self.config.api_url or "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max(1, int(self.config.max_age_days or 90)),
        }
        headers = {
            "Accept": "application/json",
            "Key": self.config.api_key,
        }
        try:
            payload = await self._fetch_payload(url, params=params, headers=headers)
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
            return self._evidence("error", checked_at=checked_at, detail=str(exc))

        data = payload.get("data") if isinstance(payload, dict) else {}
        if not isinstance(data, dict):
            return self._evidence(
                "error",
                checked_at=checked_at,
                detail="Provider returned an unexpected response shape.",
            )

        score = _int_value(data.get("abuseConfidenceScore"))
        total_reports = _int_value(data.get("totalReports"))
        threshold = max(1, min(100, int(self.config.listed_threshold or 75)))
        detail_parts = [
            f"abuseConfidenceScore={score}",
            f"totalReports={total_reports}",
            f"maxAgeInDays={params['maxAgeInDays']}",
        ]
        for label in ("usageType", "isp", "domain", "countryCode"):
            value = data.get(label)
            if value:
                detail_parts.append(f"{label}={value}")

        if score >= threshold:
            return self._evidence(
                "listed",
                checked_at=checked_at,
                listing=f"AbuseIPDB score {score}",
                detail=", ".join(detail_parts),
            )
        if score > 0 or total_reports > 0:
            return self._evidence(
                "suspicious",
                checked_at=checked_at,
                detail=", ".join(detail_parts),
            )
        return self._evidence("clean", checked_at=checked_at, detail=", ".join(detail_parts))

    async def _fetch_payload(
        self,
        url: str,
        *,
        params: Dict[str, object],
        headers: Dict[str, str],
    ) -> object:
        if self._client is not None:
            response = await self._client.get(url, params=params, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()

    def _evidence(
        self,
        status: str,
        *,
        checked_at: str,
        listing: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> FeedLookupEvidence:
        return FeedLookupEvidence(
            provider_id=self.config.provider_id,
            provider_name=self.config.display_name,
            status=status,
            listing=listing,
            detail=detail,
            checked_at=checked_at,
        )


class StaticFeedProvider:
    """Deterministic provider for tests and demo fixtures."""

    def __init__(self, config: FeedProviderConfig, listings_by_ip: Dict[str, str]) -> None:
        self.config = config
        self._listings_by_ip = listings_by_ip

    async def lookup_ip(self, ip: str) -> FeedLookupEvidence:
        listing = self._listings_by_ip.get(ip)
        return FeedLookupEvidence(
            provider_id=self.config.provider_id,
            provider_name=self.config.display_name,
            status="listed" if listing else "clean",
            listing=listing,
            checked_at=_utcnow_iso(),
        )


def _split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _int_value(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def provider_configs_from_settings(settings: Optional[Settings] = None) -> List[FeedProviderConfig]:
    """Return configured external reputation feed providers."""
    settings = settings or get_settings()
    enabled_ids = set(_split_csv(settings.SOURCE_REPUTATION_FEEDS))
    globally_enabled = bool(settings.SOURCE_REPUTATION_FEEDS_ENABLED)
    spamhaus_zone = settings.SOURCE_REPUTATION_SPAMHAUS_DQS_ZONE
    abusix_zone = settings.SOURCE_REPUTATION_ABUSIX_ZONE
    abuseipdb_key = settings.SOURCE_REPUTATION_ABUSEIPDB_API_KEY
    provider_rows = [
        FeedProviderConfig(
            provider_id="spamhaus_dqs",
            display_name="Spamhaus DQS",
            enabled=globally_enabled and "spamhaus_dqs" in enabled_ids and bool(spamhaus_zone),
            query_zone=spamhaus_zone,
            listing_name="Spamhaus DQS",
            requires_terms=True,
        ),
        FeedProviderConfig(
            provider_id="abusix_mail",
            display_name="Abusix Mail Intelligence",
            enabled=globally_enabled and "abusix_mail" in enabled_ids and bool(abusix_zone),
            query_zone=abusix_zone,
            listing_name="Abusix Mail Intelligence",
            requires_terms=True,
        ),
        FeedProviderConfig(
            provider_id="spamcop_scbl",
            display_name="SpamCop SCBL",
            enabled=globally_enabled and "spamcop_scbl" in enabled_ids,
            query_zone="bl.spamcop.net",
            listing_name="SpamCop SCBL",
            requires_terms=True,
        ),
        FeedProviderConfig(
            provider_id="barracuda_brbl",
            display_name="Barracuda BRBL",
            enabled=globally_enabled and "barracuda_brbl" in enabled_ids,
            query_zone="b.barracudacentral.org",
            listing_name="Barracuda BRBL",
            requires_terms=True,
        ),
        FeedProviderConfig(
            provider_id="abuseipdb",
            display_name="AbuseIPDB",
            kind="api",
            enabled=globally_enabled and "abuseipdb" in enabled_ids and bool(abuseipdb_key),
            api_key=abuseipdb_key,
            api_url="https://api.abuseipdb.com/api/v2/check",
            max_age_days=settings.SOURCE_REPUTATION_ABUSEIPDB_MAX_AGE_DAYS,
            listed_threshold=settings.SOURCE_REPUTATION_ABUSEIPDB_LISTED_THRESHOLD,
            listing_name="AbuseIPDB",
            requires_terms=True,
        ),
    ]
    return provider_rows


def providers_from_settings(settings: Optional[Settings] = None) -> List[ReputationFeedProvider]:
    """Build enabled reputation feed provider instances from runtime settings."""
    settings = settings or get_settings()
    if settings.DEMO_MODE:
        return []
    providers: List[ReputationFeedProvider] = []
    for config in provider_configs_from_settings(settings):
        if not config.enabled:
            continue
        if config.kind == "api" and config.provider_id == "abuseipdb":
            providers.append(
                AbuseIPDBFeedProvider(
                    config,
                    timeout_seconds=settings.SOURCE_REPUTATION_FEED_TIMEOUT_SECONDS,
                )
            )
            continue
        providers.append(
            DNSBLFeedProvider(
                config, timeout_seconds=settings.SOURCE_REPUTATION_FEED_TIMEOUT_SECONDS
            )
        )
    return providers


def feed_registry(settings: Optional[Settings] = None) -> Dict[str, Dict[str, object]]:
    """Return safe metadata for available external reputation providers."""
    return {
        config.provider_id: {
            "provider_id": config.provider_id,
            "display_name": config.display_name,
            "kind": config.kind,
            "enabled": config.enabled,
            "requires_terms": config.requires_terms,
            "default_enabled": config.default_enabled,
            "configured": bool(config.query_zone or config.api_key),
        }
        for config in provider_configs_from_settings(settings)
    }


def _cache_key(ip: str, providers: Iterable[ReputationFeedProvider]) -> str:
    payload = {
        "ip": ip,
        "providers": [
            {
                "provider_id": provider.config.provider_id,
                "kind": provider.config.kind,
                "query_zone": provider.config.query_zone,
                "api_url": provider.config.api_url,
                "max_age_days": provider.config.max_age_days,
                "listed_threshold": provider.config.listed_threshold,
            }
            for provider in providers
        ],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:32]


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _evidence_from_json(value: Dict[str, object]) -> FeedLookupEvidence:
    return FeedLookupEvidence(
        provider_id=str(value.get("provider_id") or ""),
        provider_name=str(value.get("provider_name") or ""),
        status=str(value.get("status") or "unknown"),
        listing=value.get("listing") if value.get("listing") is not None else None,
        detail=value.get("detail") if value.get("detail") is not None else None,
        checked_at=str(value.get("checked_at") or ""),
    )


def _result_from_json(value: str) -> IPFeedReputation:
    data = json.loads(value)
    return IPFeedReputation(
        ip=str(data.get("ip") or ""),
        listed=bool(data.get("listed")),
        evidence=[_evidence_from_json(item) for item in data.get("evidence") or []],
    )


async def lookup_ip_reputation(
    ip: str,
    providers: Iterable[ReputationFeedProvider],
) -> IPFeedReputation:
    """Lookup one IP across configured external reputation providers."""
    provider_rows = list(providers)
    evidence = [await provider.lookup_ip(ip) for provider in provider_rows]
    return IPFeedReputation(
        ip=ip,
        listed=any(item.status == "listed" for item in evidence),
        evidence=evidence,
    )


async def lookup_ip_reputation_cached(
    db: Session,
    ip: str,
    providers: Iterable[ReputationFeedProvider],
    *,
    ttl_seconds: int = 86_400,
    refresh: bool = False,
) -> Tuple[IPFeedReputation, bool, datetime]:
    """Lookup one IP across feeds using a persistent cache."""
    now = _utcnow_naive()
    provider_rows = list(providers)
    if not provider_rows:
        return IPFeedReputation(ip=ip), False, now
    selectors_key = _cache_key(ip, provider_rows)
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == ip,
            DNSCache.provider == _CACHE_PROVIDER,
            DNSCache.selectors_key == selectors_key,
        )
        .first()
    )
    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _result_from_json(row.result_json), True, row.checked_at

    result = await lookup_ip_reputation(ip, provider_rows)
    payload = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
    if row is None:
        row = DNSCache(
            domain=ip,
            provider=_CACHE_PROVIDER,
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
                DNSCache.domain == ip,
                DNSCache.provider == _CACHE_PROVIDER,
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


async def lookup_sources_reputation_cached(
    db: Session,
    source_ips: Iterable[str],
    providers: Iterable[ReputationFeedProvider],
    *,
    ttl_seconds: int = 86_400,
    max_ips: int = 100,
    refresh: bool = False,
) -> Dict[str, IPFeedReputation]:
    """Lookup a bounded set of source IPs across configured reputation feeds."""
    provider_rows = list(providers)
    if not provider_rows:
        return {}
    unique_ips: List[str] = []
    seen: set[str] = set()
    for raw_ip in source_ips:
        ip = str(raw_ip).strip()
        if not ip or ip in seen:
            continue
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not address.is_global:
            continue
        seen.add(ip)
        unique_ips.append(ip)
        if len(unique_ips) >= max_ips:
            break
    results: Dict[str, IPFeedReputation] = {}
    for ip in unique_ips:
        result, _, _ = await lookup_ip_reputation_cached(
            db,
            ip,
            provider_rows,
            ttl_seconds=ttl_seconds,
            refresh=refresh,
        )
        results[ip] = result
    return results
