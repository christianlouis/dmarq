"""Akamai Edge DNS / FastDNS zone discovery and monitored-domain import helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.domain import Domain
from app.models.workspace import Workspace
from app.services.organizations import require_organization_plan_limit
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

PROVIDER_NAME = "akamai-edgedns"
AKAMAI_EDGE_DNS_PAGE_SIZE = 100


@dataclass
class AkamaiEdgeDNSCredentials:
    """Resolved EdgeGrid credential hints for Edge DNS zone discovery."""

    edgerc_path: Optional[str] = None
    edgerc_section: str = "default"
    host: Optional[str] = None
    client_token: Optional[str] = None
    client_secret: Optional[str] = None
    access_token: Optional[str] = None
    account_switch_key: Optional[str] = None

    @property
    def configured(self) -> bool:
        if self.edgerc_path:
            return True
        return all([self.host, self.client_token, self.client_secret, self.access_token])


class AkamaiEdgeDNSClient:
    """Small read-only client for Akamai Edge DNS/FastDNS zone discovery."""

    def __init__(self, *, session: Any, base_url: str, account_switch_key: Optional[str] = None):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.account_switch_key = account_switch_key

    @staticmethod
    def _zone_name(zone: Dict[str, Any]) -> str:
        return str(zone.get("zone") or zone.get("name") or "").strip().strip(".").lower()

    @staticmethod
    def _zone_id(zone: Dict[str, Any]) -> str:
        return AkamaiEdgeDNSClient._zone_name(zone)

    @staticmethod
    def _zone_status(zone: Dict[str, Any]) -> Optional[str]:
        for key in ("type", "zoneType", "activationState", "status"):
            if zone.get(key):
                return str(zone[key])
        return None

    @staticmethod
    def _account_name(zone: Dict[str, Any]) -> str:
        contract_id = zone.get("contractId") or zone.get("contract_id")
        group_id = zone.get("groupId") or zone.get("group_id")
        if contract_id and group_id:
            return f"Akamai contract {contract_id} / group {group_id}"
        if contract_id:
            return f"Akamai contract {contract_id}"
        return "Akamai Edge DNS"

    def _api_get_sync(self, path: str, *, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        request_params = dict(params or {})
        if self.account_switch_key:
            request_params.setdefault("accountSwitchKey", self.account_switch_key)

        response = self.session.get(f"{self.base_url}{path}", params=request_params)
        try:
            response.raise_for_status()
            return response.json()
        except ValueError as exc:
            raise LookupError(f"Akamai Edge DNS API returned invalid JSON for {path}") from exc
        except Exception as exc:
            raise LookupError(f"Akamai Edge DNS API request failed for {path}: {exc}") from exc

    async def _api_get(
        self, path: str, *, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return await asyncio.to_thread(self._api_get_sync, path, params=params)

    async def list_zones(self) -> List[Dict[str, Any]]:
        """Return Edge DNS zones visible to the configured EdgeGrid credentials."""
        zones: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = await self._api_get(
                "/config-dns/v2/zones",
                params={"page": page, "pageSize": AKAMAI_EDGE_DNS_PAGE_SIZE},
            )
            page_zones = data.get("zones") or data.get("data") or data.get("items") or []
            if not isinstance(page_zones, list):
                return zones
            zones.extend(page_zones)

            metadata = data.get("metadata") or data.get("page") or {}
            total_pages_value = (
                metadata.get("totalPages") or metadata.get("total_pages") or metadata.get("lastPage")
            )
            total_pages = int(total_pages_value or page)
            if page >= total_pages:
                break
            if total_pages_value is None and len(page_zones) < AKAMAI_EDGE_DNS_PAGE_SIZE:
                break
            page += 1
        return zones


def get_akamai_edgedns_credentials() -> AkamaiEdgeDNSCredentials:
    """Resolve Akamai EdgeGrid credentials from environment settings."""
    settings = get_settings()
    return AkamaiEdgeDNSCredentials(
        edgerc_path=settings.AKAMAI_EDGERC_PATH,
        edgerc_section=settings.AKAMAI_EDGERC_SECTION or "default",
        host=settings.AKAMAI_HOST,
        client_token=settings.AKAMAI_CLIENT_TOKEN,
        client_secret=settings.AKAMAI_CLIENT_SECRET,
        access_token=settings.AKAMAI_ACCESS_TOKEN,
        account_switch_key=settings.AKAMAI_ACCOUNT_SWITCH_KEY or settings.AKAMAI_ACCOUNT_KEY,
    )


def build_akamai_edgedns_client() -> AkamaiEdgeDNSClient:
    """Return an Akamai Edge DNS client configured from EdgeGrid credentials."""
    credentials = get_akamai_edgedns_credentials()
    if not credentials.configured:
        raise LookupError("Akamai EdgeGrid credentials are not configured")

    try:
        import requests  # type: ignore[import]
        from akamai.edgegrid import EdgeGridAuth, EdgeRc  # type: ignore[import]
    except ImportError as exc:
        raise LookupError(
            "edgegrid-python and requests are required for Akamai Edge DNS import"
        ) from exc

    session = requests.Session()
    if credentials.edgerc_path:
        edgerc = EdgeRc(credentials.edgerc_path)
        session.auth = EdgeGridAuth.from_edgerc(edgerc, credentials.edgerc_section)
        host = edgerc.get(credentials.edgerc_section, "host")
        try:
            edgerc_account_key = edgerc.get(credentials.edgerc_section, "account_key")
        except Exception:
            edgerc_account_key = None
        account_key = credentials.account_switch_key or edgerc_account_key
    else:
        session.auth = EdgeGridAuth(
            client_token=credentials.client_token,
            client_secret=credentials.client_secret,
            access_token=credentials.access_token,
        )
        host = credentials.host
        account_key = credentials.account_switch_key

    if not host:
        raise LookupError("Akamai EdgeGrid host is not configured")
    return AkamaiEdgeDNSClient(
        session=session,
        base_url=f"https://{str(host).strip().removeprefix('https://').rstrip('/')}",
        account_switch_key=account_key,
    )


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


async def discover_akamai_edgedns_zones(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return Akamai Edge DNS zones visible to EdgeGrid credentials with import state."""
    client = build_akamai_edgedns_client()
    known_domains = _workspace_domain_names(db, workspace_id)
    zones = await client.list_zones()
    discovered: List[Dict[str, Any]] = []
    for zone in zones:
        name = AkamaiEdgeDNSClient._zone_name(zone)  # pylint: disable=protected-access
        zone_id = AkamaiEdgeDNSClient._zone_id(zone)  # pylint: disable=protected-access
        if not zone_id or not name:
            continue
        discovered.append(
            {
                "id": zone_id,
                "name": name,
                "status": AkamaiEdgeDNSClient._zone_status(zone),  # pylint: disable=protected-access
                "account_name": AkamaiEdgeDNSClient._account_name(  # pylint: disable=protected-access
                    zone
                ),
                "imported": name in known_domains,
            }
        )
    return discovered


async def import_akamai_edgedns_domains(
    db: Session,
    *,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create Domain rows for Akamai Edge DNS zones."""
    workspace_id = _resolve_workspace_id(db, workspace_id)
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()

    zones = await discover_akamai_edgedns_zones(db, workspace_id=workspace_id)
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
                    description="DNS-discovered from Akamai Edge DNS zone import",
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
