"""DNS provider detection from authoritative nameserver evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional


@dataclass
class DNSProviderDetection:
    """Likely DNS provider derived from NS records."""

    provider_id: str
    provider_name: str
    confidence: str
    evidence: List[str] = field(default_factory=list)
    connector_available: bool = False
    automation_supported: bool = False
    suggested_action: str = "Use manual DNS instructions until a provider connector is configured."


@dataclass(frozen=True)
class _ProviderPattern:
    provider_id: str
    provider_name: str
    patterns: tuple[str, ...]
    connector_available: bool = False
    automation_supported: bool = False


_PROVIDER_PATTERNS: tuple[_ProviderPattern, ...] = (
    _ProviderPattern(
        "cloudflare",
        "Cloudflare",
        ("cloudflare.com",),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "route53",
        "Amazon Route 53",
        ("awsdns-", "awsdns."),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "googleclouddns",
        "Google Cloud DNS",
        ("googledomains.com",),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "azure_dns",
        "Azure DNS",
        ("azure-dns.",),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "digitalocean",
        "DigitalOcean DNS",
        ("digitalocean.com",),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "hetzner",
        "Hetzner DNS",
        (
            "hetzner.com",
            "hetzner.de",
            "first-ns.de",
            "second-ns.de",
            "second-ns.com",
        ),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "linode",
        "Linode DNS",
        ("linode.com",),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "akamai-edgedns",
        "Akamai Edge DNS / FastDNS",
        ("akam.net", "akadns.net"),
        connector_available=True,
        automation_supported=False,
    ),
    _ProviderPattern(
        "namecheap",
        "Namecheap",
        ("registrar-servers.com",),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "godaddy",
        "GoDaddy",
        ("domaincontrol.com",),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern(
        "powerdns",
        "PowerDNS or custom DNS",
        ("powerdns", "pdns"),
        connector_available=True,
        automation_supported=True,
    ),
    _ProviderPattern("plesk", "Plesk-hosted DNS", ("plesk",)),
    _ProviderPattern("cpanel", "cPanel/WHM-hosted DNS", ("cpanel", "webhostbox.net")),
)


def _normalize_nameserver(value: str) -> str:
    return value.strip().strip(".").lower()


def _action_for(pattern: _ProviderPattern) -> str:
    if pattern.connector_available:
        return (
            f"Connect {pattern.provider_name} in Settings to enable provider-aware "
            "DNS inspection, preview, and explicitly approved repair plans."
        )
    return (
        f"Use the {pattern.provider_name} DNS console or hosting panel with DMARQ's "
        "manual change plan until a connector is available."
    )


def detect_dns_provider(nameservers: Iterable[str]) -> DNSProviderDetection:
    """Return likely DNS provider metadata from authoritative NS names."""
    normalized = [_normalize_nameserver(item) for item in nameservers if item and item.strip()]
    if not normalized:
        return DNSProviderDetection(
            provider_id="unknown",
            provider_name="Unknown DNS provider",
            confidence="unknown",
            evidence=[],
            suggested_action=(
                "No authoritative nameservers were detected. Use manual DNS "
                "instructions or refresh DNS once delegation is visible."
            ),
        )

    for pattern in _PROVIDER_PATTERNS:
        matches = [
            nameserver
            for nameserver in normalized
            if any(marker in nameserver for marker in pattern.patterns)
        ]
        if matches:
            confidence = "high" if len(matches) >= 2 else "medium"
            return DNSProviderDetection(
                provider_id=pattern.provider_id,
                provider_name=pattern.provider_name,
                confidence=confidence,
                evidence=matches,
                connector_available=pattern.connector_available,
                automation_supported=pattern.automation_supported,
                suggested_action=_action_for(pattern),
            )

    return DNSProviderDetection(
        provider_id="custom",
        provider_name="Custom or unrecognized DNS provider",
        confidence="low",
        evidence=normalized[:4],
        suggested_action=(
            "Use manual DNS instructions, or choose a provider connector once "
            "DMARQ supports this DNS platform."
        ),
    )


def detection_from_json(value: Optional[dict]) -> Optional[DNSProviderDetection]:
    """Rehydrate cached provider detection metadata."""
    if not value:
        return None
    return DNSProviderDetection(
        provider_id=str(value.get("provider_id") or "unknown"),
        provider_name=str(value.get("provider_name") or "Unknown DNS provider"),
        confidence=str(value.get("confidence") or "unknown"),
        evidence=list(value.get("evidence") or []),
        connector_available=bool(value.get("connector_available")),
        automation_supported=bool(value.get("automation_supported")),
        suggested_action=str(
            value.get("suggested_action")
            or "Use manual DNS instructions until a provider connector is configured."
        ),
    )
