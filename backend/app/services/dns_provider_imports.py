"""Read-only DNS provider zone discovery and domain import helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.services.cloudflare_dns import discover_cloudflare_zones, import_cloudflare_domains
from app.services.dns_provider_connectors import provider_connector_registry
from app.services.dns_provider_writes import normalize_provider_id


@dataclass
class DNSProviderImportZone:
    """One DNS provider zone that can be imported as a monitored domain."""

    provider: str
    provider_name: str
    zone_id: str
    domain: str
    status: Optional[str] = None
    account_name: Optional[str] = None
    imported: bool = False
    importable: bool = True
    source: str = "dns_zone"
    next_action: str = "Import this DNS zone to monitor DNS posture before reports arrive."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


PROVIDER_NAMES = {
    item["id"]: item["name"]
    for item in provider_connector_registry()
    if item.get("zone_import_status") == "ready"
}


def supported_import_providers() -> List[Dict[str, str]]:
    """Return DNS providers that support zone import."""
    return [{"id": provider_id, "name": name} for provider_id, name in PROVIDER_NAMES.items()]


def _provider_name(provider_id: str) -> str:
    return PROVIDER_NAMES.get(provider_id, provider_id)


async def preview_dns_provider_import(
    db: Session,
    *,
    provider: str,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Return importable zones/domains for a DNS provider without creating rows."""
    provider_id = normalize_provider_id(provider)
    if provider_id != "cloudflare":
        raise LookupError(f"Unsupported DNS provider import: {provider_id}")

    zones = await discover_cloudflare_zones(db, workspace_id=workspace_id)
    items = [
        DNSProviderImportZone(
            provider=provider_id,
            provider_name=_provider_name(provider_id),
            zone_id=str(zone["id"]),
            domain=str(zone["name"]).lower(),
            status=zone.get("status"),
            account_name=zone.get("account_name"),
            imported=bool(zone.get("imported")),
            importable=not bool(zone.get("imported")),
            next_action=(
                "Already monitored in this workspace."
                if zone.get("imported")
                else "Import this Cloudflare zone to monitor DNS posture before reports arrive."
            ),
        ).to_dict()
        for zone in zones
    ]
    return {
        "provider": provider_id,
        "provider_name": _provider_name(provider_id),
        "zones": items,
        "total_discovered": len(items),
        "importable_count": sum(1 for item in items if item["importable"]),
    }


async def import_dns_provider_domains(
    db: Session,
    *,
    provider: str,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Import selected DNS provider zones as monitored domains."""
    provider_id = normalize_provider_id(provider)
    if provider_id != "cloudflare":
        raise LookupError(f"Unsupported DNS provider import: {provider_id}")

    result = await import_cloudflare_domains(
        db,
        requested_domains=requested_domains,
        workspace_id=workspace_id,
    )
    return {
        "provider": provider_id,
        "provider_name": _provider_name(provider_id),
        **result,
    }
