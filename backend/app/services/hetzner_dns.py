"""Hetzner DNS zone discovery and domain import helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.domain import Domain
from app.models.workspace import Workspace
from app.services.organizations import require_organization_plan_limit
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

PROVIDER_NAME = "hetzner"
HETZNER_DNS_API_BASE = "https://api.hetzner.cloud/v1"
HETZNER_DNS_API_TIMEOUT = 30.0


@dataclass
class HetznerDNSCredentials:
    """Resolved Hetzner DNS API credentials."""

    api_token: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.api_token)


class HetznerDNSClient:
    """Small read-only client for Hetzner Console DNS zone discovery."""

    def __init__(
        self,
        *,
        api_token: Optional[str],
        api_base: str = HETZNER_DNS_API_BASE,
    ) -> None:
        self.api_token = api_token
        self.api_base = api_base.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        if not self.api_token:
            raise LookupError("Hetzner DNS API token is not configured")
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
        }

    async def _api_get(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.api_base}{path}"
        try:
            async with httpx.AsyncClient(timeout=HETZNER_DNS_API_TIMEOUT) as client:
                response = await client.get(url, params=params, headers=self._headers())
                response.raise_for_status()
                return response.json()
        except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException) as exc:
            raise LookupError(f"Hetzner DNS API request failed for {path}: {exc}") from exc
        except ValueError as exc:
            raise LookupError(f"Hetzner DNS API returned invalid JSON for {path}") from exc

    async def list_zones(self) -> List[Dict[str, Any]]:
        """Return DNS zones visible to the configured Hetzner token."""
        zones: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = await self._api_get("/zones", params={"page": page, "per_page": 50})
            result = data.get("zones") or data.get("result") or data.get("data") or []
            if not isinstance(result, list):
                return zones
            zones.extend(result)

            pagination = (data.get("meta") or {}).get("pagination") or data.get("pagination") or {}
            next_page = pagination.get("next_page")
            if next_page:
                page = int(next_page)
                continue
            last_page = int(pagination.get("last_page") or page)
            if page >= last_page:
                break
            page += 1
        return zones


def get_hetzner_dns_credentials() -> HetznerDNSCredentials:
    """Resolve Hetzner DNS API credentials from environment settings."""
    settings = get_settings()
    return HetznerDNSCredentials(
        api_token=settings.HETZNER_DNS_API_TOKEN or settings.HETZNER_API_TOKEN,
    )


def build_hetzner_dns_client() -> HetznerDNSClient:
    """Return a Hetzner DNS client configured from environment settings."""
    credentials = get_hetzner_dns_credentials()
    if not credentials.configured:
        raise LookupError("Hetzner DNS API token is not configured")
    return HetznerDNSClient(api_token=credentials.api_token)


def _workspace_domain_names(db: Session, workspace_id: Optional[int]) -> set[str]:
    query = db.query(Domain.name)
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    return {name for (name,) in query.all()}


async def discover_hetzner_zones(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return Hetzner DNS zones visible to the configured token with import state."""
    client = build_hetzner_dns_client()
    known_domains = _workspace_domain_names(db, workspace_id)
    zones = await client.list_zones()
    discovered: List[Dict[str, Any]] = []
    for zone in zones:
        name = str(zone.get("name") or "").strip().lower()
        zone_id = zone.get("id")
        if not zone_id or not name:
            continue
        discovered.append(
            {
                "id": str(zone_id),
                "name": name,
                "status": zone.get("status") or zone.get("mode"),
                "account_name": "Hetzner DNS",
                "imported": name in known_domains,
            }
        )
    return discovered


async def import_hetzner_domains(
    db: Session,
    *,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create Domain rows for Hetzner DNS zones."""
    if workspace_id is None:
        workspace = assign_default_workspace_to_unscoped_rows(db)
        workspace_id = workspace.id
    else:
        workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()

    zones = await discover_hetzner_zones(db, workspace_id=workspace_id)
    requested = {domain.strip().lower() for domain in requested_domains or [] if domain.strip()}
    candidate_names: List[str] = []
    imported: List[str] = []
    existing: List[str] = []
    skipped: List[str] = []

    for zone in zones:
        name = str(zone["name"]).lower()
        if requested and name not in requested:
            skipped.append(name)
            continue
        candidate_names.append(name)

    existing_names = set()
    if candidate_names:
        existing_names = {
            row[0]
            for row in (
                db.query(Domain.name)
                .filter(Domain.name.in_(candidate_names), Domain.workspace_id == workspace_id)
                .all()
            )
        }
    new_names = [name for name in candidate_names if name not in existing_names]
    if workspace and workspace.organization and new_names:
        require_organization_plan_limit(
            db,
            workspace.organization,
            "monitored_domains",
            increment=len(new_names),
        )

    for name in candidate_names:
        if name in existing_names:
            existing.append(name)
        else:
            db.add(
                Domain(
                    name=name,
                    description="DNS-discovered from Hetzner DNS zone import",
                    active=True,
                    verified=True,
                    workspace_id=workspace_id,
                )
            )
            imported.append(name)

    db.commit()
    return {
        "imported": imported,
        "existing": existing,
        "skipped": skipped,
        "total_discovered": len(zones),
    }
