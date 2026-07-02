"""Linode DNS domain discovery and monitored-domain import helpers."""

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

PROVIDER_NAME = "linode"
LINODE_API_BASE = "https://api.linode.com/v4"
LINODE_API_TIMEOUT = 30.0
LINODE_PAGE_SIZE = 500


@dataclass
class LinodeDNSCredentials:
    """Resolved Linode API credentials for DNS domain discovery."""

    api_token: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.api_token)


class LinodeDNSClient:
    """Small read-only client for Linode DNS domain discovery."""

    def __init__(
        self,
        *,
        api_token: Optional[str],
        api_base: str = LINODE_API_BASE,
    ) -> None:
        self.api_token = api_token
        self.api_base = api_base.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        if not self.api_token:
            raise LookupError("Linode API token is not configured")
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
        }

    async def _api_get(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        url = f"{self.api_base}{path}"
        try:
            if client is not None:
                response = await client.get(url, params=params, headers=self._headers())
                response.raise_for_status()
                return response.json()

            async with httpx.AsyncClient(timeout=LINODE_API_TIMEOUT) as http_client:
                response = await http_client.get(url, params=params, headers=self._headers())
            response.raise_for_status()
            return response.json()
        except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException) as exc:
            raise LookupError(f"Linode API request failed for {path}: {exc}") from exc
        except ValueError as exc:
            raise LookupError(f"Linode API returned invalid JSON for {path}") from exc

    async def list_domains(self) -> List[Dict[str, Any]]:
        """Return DNS domains visible to the configured Linode token."""
        domains: List[Dict[str, Any]] = []
        page = 1
        async with httpx.AsyncClient(timeout=LINODE_API_TIMEOUT) as client:
            while True:
                data = await self._api_get(
                    "/domains",
                    params={"page": page, "page_size": LINODE_PAGE_SIZE},
                    client=client,
                )
                result = data.get("data") or []
                if not isinstance(result, list):
                    return domains
                domains.extend(result)

                pages = int(data.get("pages") or page)
                if page >= pages:
                    break
                page += 1
        return domains


def get_linode_dns_credentials() -> LinodeDNSCredentials:
    """Resolve Linode API credentials from environment settings."""
    settings = get_settings()
    return LinodeDNSCredentials(
        api_token=settings.LINODE_API_TOKEN or settings.LINODE_TOKEN,
    )


def build_linode_dns_client() -> LinodeDNSClient:
    """Return a Linode DNS client configured from environment settings."""
    credentials = get_linode_dns_credentials()
    if not credentials.configured:
        raise LookupError("Linode API token is not configured")
    return LinodeDNSClient(api_token=credentials.api_token)


def _resolve_workspace_id(db: Session, workspace_id: Optional[int]) -> int:
    if workspace_id is not None:
        return workspace_id
    return assign_default_workspace_to_unscoped_rows(db).id


def _workspace_domain_names(db: Session, workspace_id: Optional[int]) -> set[str]:
    resolved_workspace_id = _resolve_workspace_id(db, workspace_id)
    query = db.query(Domain.name).filter(Domain.workspace_id == resolved_workspace_id)
    return {name for (name,) in query.all()}


def _normalize_domain_name(domain: str) -> str:
    return domain.strip().strip(".").lower()


async def discover_linode_domains(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return Linode DNS domains visible to the configured token with import state."""
    client = build_linode_dns_client()
    known_domains = _workspace_domain_names(db, workspace_id)
    domains = await client.list_domains()
    discovered: List[Dict[str, Any]] = []
    for domain in domains:
        name = _normalize_domain_name(str(domain.get("domain") or ""))
        domain_id = domain.get("id")
        if not domain_id or not name:
            continue
        discovered.append(
            {
                "id": str(domain_id),
                "name": name,
                "status": domain.get("type"),
                "account_name": "Linode DNS",
                "imported": name in known_domains,
            }
        )
    return discovered


async def import_linode_domains(
    db: Session,
    *,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create Domain rows for Linode DNS domains."""
    workspace_id = _resolve_workspace_id(db, workspace_id)
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()

    zones = await discover_linode_domains(db, workspace_id=workspace_id)
    requested = None
    if requested_domains is not None:
        requested = {
            _normalize_domain_name(domain)
            for domain in requested_domains
            if _normalize_domain_name(domain)
        }
    candidate_names: List[str] = []
    imported: List[str] = []
    existing: List[str] = []
    skipped: List[str] = []
    seen_candidates: set[str] = set()

    for zone in zones:
        name = str(zone["name"]).lower()
        if requested is not None and name not in requested:
            skipped.append(name)
            continue
        if name in seen_candidates:
            continue
        seen_candidates.add(name)
        candidate_names.append(name)

    existing_names = set()
    if candidate_names:
        existing_names = {
            row[0] for row in db.query(Domain.name).filter(Domain.name.in_(candidate_names)).all()
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
                    description="DNS-discovered from Linode DNS domain import",
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
