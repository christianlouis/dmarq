"""Read-only OVHcloud DNS zone discovery and export helpers."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.domain import Domain
from app.models.workspace import Workspace
from app.services.organizations import require_organization_plan_limit
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

PROVIDER_NAME = "ovh"


@dataclass
class OVHDNSCredentials:
    """OVH application credentials; values are never returned by APIs."""

    api_base: str
    application_key: Optional[str]
    application_secret: Optional[str]
    consumer_key: Optional[str]

    @property
    def configured(self) -> bool:
        return bool(self.application_key and self.application_secret and self.consumer_key)


class OVHDNSClient:
    """Minimal signed, read-only OVH API client."""

    def __init__(self, credentials: OVHDNSCredentials) -> None:
        self.credentials = credentials

    def _headers(self, method: str, url: str, body: str = "") -> Dict[str, str]:
        if not self.credentials.configured:
            raise LookupError("OVHcloud API credentials are not configured")
        timestamp = str(int(time.time()))
        signature_input = "+".join(
            [
                str(self.credentials.application_secret),
                str(self.credentials.consumer_key),
                method,
                url,
                body,
                timestamp,
            ]
        )
        signature = "$1$" + hashlib.sha1(signature_input.encode("utf-8")).hexdigest()
        return {
            "X-Ovh-Application": str(self.credentials.application_key),
            "X-Ovh-Consumer": str(self.credentials.consumer_key),
            "X-Ovh-Timestamp": timestamp,
            "X-Ovh-Signature": signature,
            "Accept": "application/json",
        }

    async def _get(self, path: str) -> Any:
        url = f"{self.credentials.api_base.rstrip('/')}{path}"
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=self._headers("GET", url))
                response.raise_for_status()
                return response.json()
        except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException) as exc:
            raise LookupError(f"OVHcloud DNS read failed for {path}: {exc}") from exc
        except (ValueError, json.JSONDecodeError) as exc:
            raise LookupError(f"OVHcloud DNS returned invalid JSON for {path}") from exc

    async def list_zones(self) -> List[str]:
        """Return zone names visible to the consumer key."""
        data = await self._get("/domain/zone")
        if not isinstance(data, list):
            raise LookupError("OVHcloud DNS returned an invalid zone list")
        return sorted({str(item).strip().strip(".").lower() for item in data if item})

    async def export_zone(self, zone_name: str) -> str:
        """Return a BIND-style provider-zone export without modifying the zone."""
        data = await self._get(f"/domain/zone/{quote(zone_name, safe='')}/export")
        if isinstance(data, str):
            return data
        if isinstance(data, dict) and isinstance(data.get("zone"), str):
            return data["zone"]
        raise LookupError("OVHcloud DNS returned an invalid zone export")


def get_ovh_dns_credentials() -> OVHDNSCredentials:
    settings = get_settings()
    return OVHDNSCredentials(
        api_base=settings.OVH_API_BASE,
        application_key=settings.OVH_APPLICATION_KEY,
        application_secret=settings.OVH_APPLICATION_SECRET,
        consumer_key=settings.OVH_CONSUMER_KEY,
    )


def build_ovh_dns_client() -> OVHDNSClient:
    credentials = get_ovh_dns_credentials()
    if not credentials.configured:
        raise LookupError("OVHcloud API credentials are not configured")
    return OVHDNSClient(credentials)


def _workspace_id(db: Session, workspace_id: Optional[int]) -> int:
    return workspace_id or assign_default_workspace_to_unscoped_rows(db).id


async def discover_ovh_zones(
    db: Session, *, workspace_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    resolved = _workspace_id(db, workspace_id)
    known = {name for (name,) in db.query(Domain.name).filter(Domain.workspace_id == resolved)}
    client = build_ovh_dns_client()
    return [
        {
            "id": name,
            "name": name,
            "status": "read_only",
            "account_name": "OVHcloud",
            "imported": name in known,
        }
        for name in await client.list_zones()
    ]


async def import_ovh_domains(
    db: Session,
    *,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    resolved = _workspace_id(db, workspace_id)
    workspace = db.query(Workspace).filter(Workspace.id == resolved).first()
    zones = await discover_ovh_zones(db, workspace_id=resolved)
    requested = (
        None
        if requested_domains is None
        else {item.strip().strip(".").lower() for item in requested_domains if item.strip()}
    )
    candidates = [item["name"] for item in zones if requested is None or item["name"] in requested]
    skipped = [
        item["name"] for item in zones if requested is not None and item["name"] not in requested
    ]
    existing_names = (
        {name for (name,) in db.query(Domain.name).filter(Domain.name.in_(candidates))}
        if candidates
        else set()
    )
    new_names = [name for name in candidates if name not in existing_names]
    if workspace and workspace.organization and new_names:
        require_organization_plan_limit(
            db, workspace.organization, "monitored_domains", increment=len(new_names)
        )
    for name in new_names:
        db.add(
            Domain(
                name=name,
                description="DNS-discovered from OVHcloud zone import",
                active=True,
                verified=True,
                workspace_id=resolved,
            )
        )
    db.commit()
    return {
        "imported": new_names,
        "existing": sorted(existing_names),
        "skipped": skipped,
        "total_discovered": len(zones),
    }
