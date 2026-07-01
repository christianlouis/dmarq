"""Amazon Route 53 hosted-zone discovery and domain import helpers."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.domain import Domain
from app.models.workspace import Workspace
from app.services.organizations import require_organization_plan_limit
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

try:  # pragma: no cover - exercised through monkeypatched fakes in tests.
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:  # pragma: no cover - depends on optional runtime dependency.
    boto3 = None  # type: ignore[assignment]
    BotoCoreError = ClientError = NoCredentialsError = Exception  # type: ignore[misc]

PROVIDER_NAME = "route53"
ROUTE53_ROLE_SESSION_NAME = "dmarq-route53-zone-import"


@dataclass
class Route53DNSCredentials:
    """Resolved Route 53 credential hints for the boto3 credential chain."""

    profile_name: Optional[str] = None
    region_name: Optional[str] = None
    role_arn: Optional[str] = None
    external_id: Optional[str] = None

    @property
    def configured(self) -> bool:
        return any(
            [
                self.profile_name,
                self.role_arn,
                os.getenv("AWS_ACCESS_KEY_ID"),
                os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"),
                os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"),
                os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"),
            ]
        )


class Route53DNSClient:
    """Small read-only client for Route 53 hosted-zone discovery."""

    def __init__(self, *, route53_client: Any, account_name: str = "Amazon Route 53") -> None:
        self.route53_client = route53_client
        self.account_name = account_name

    @staticmethod
    def _zone_id(zone: Dict[str, Any]) -> str:
        return str(zone.get("Id") or zone.get("id") or "").rsplit("/", maxsplit=1)[-1]

    @staticmethod
    def _zone_name(zone: Dict[str, Any]) -> str:
        return str(zone.get("Name") or zone.get("name") or "").strip().strip(".").lower()

    @staticmethod
    def _zone_status(zone: Dict[str, Any]) -> str:
        config = zone.get("Config") or zone.get("config") or {}
        return "private" if config.get("PrivateZone") or config.get("private_zone") else "public"

    def _list_zones_sync(self) -> List[Dict[str, Any]]:
        try:
            paginator = self.route53_client.get_paginator("list_hosted_zones")
            pages = paginator.paginate()
            zones: List[Dict[str, Any]] = []
            for page in pages:
                page_zones = page.get("HostedZones") or page.get("hosted_zones") or []
                if isinstance(page_zones, list):
                    zones.extend(page_zones)
            return zones
        except (BotoCoreError, ClientError, NoCredentialsError) as exc:
            raise LookupError(f"Route 53 hosted-zone listing failed: {exc}") from exc

    async def list_zones(self) -> List[Dict[str, Any]]:
        """Return Route 53 hosted zones visible to the configured AWS credentials."""
        return await asyncio.to_thread(self._list_zones_sync)


def get_route53_dns_credentials() -> Route53DNSCredentials:
    """Resolve Route 53 credential hints from settings and standard AWS env vars."""
    settings = get_settings()
    return Route53DNSCredentials(
        profile_name=settings.DMARQ_ROUTE53_PROFILE or settings.AWS_PROFILE,
        region_name=settings.AWS_REGION,
        role_arn=settings.DMARQ_ROUTE53_ROLE_ARN,
        external_id=settings.DMARQ_ROUTE53_EXTERNAL_ID,
    )


def _build_route53_boto_client(credentials: Route53DNSCredentials) -> Any:
    if boto3 is None:
        raise LookupError("boto3 is not installed; Route 53 DNS import is unavailable")

    session_kwargs: Dict[str, str] = {}
    if credentials.profile_name:
        session_kwargs["profile_name"] = credentials.profile_name
    if credentials.region_name:
        session_kwargs["region_name"] = credentials.region_name

    session = boto3.Session(**session_kwargs)
    if not credentials.role_arn:
        return session.client("route53")

    assume_kwargs = {
        "RoleArn": credentials.role_arn,
        "RoleSessionName": ROUTE53_ROLE_SESSION_NAME,
    }
    if credentials.external_id:
        assume_kwargs["ExternalId"] = credentials.external_id
    try:
        assumed = session.client("sts").assume_role(**assume_kwargs)
    except (BotoCoreError, ClientError, NoCredentialsError) as exc:
        raise LookupError(f"Route 53 role assumption failed: {exc}") from exc

    temporary = assumed["Credentials"]
    return session.client(
        "route53",
        aws_access_key_id=temporary["AccessKeyId"],
        aws_secret_access_key=temporary["SecretAccessKey"],
        aws_session_token=temporary["SessionToken"],
    )


def build_route53_dns_client() -> Route53DNSClient:
    """Return a Route 53 client configured from the boto3 credential chain."""
    credentials = get_route53_dns_credentials()
    account_name = credentials.profile_name or "Amazon Route 53"
    if credentials.role_arn:
        account_name = f"Route 53 role {credentials.role_arn.rsplit('/', maxsplit=1)[-1]}"
    return Route53DNSClient(
        route53_client=_build_route53_boto_client(credentials),
        account_name=account_name,
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


async def discover_route53_zones(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return Route 53 hosted zones visible to AWS credentials with import state."""
    client = build_route53_dns_client()
    known_domains = _workspace_domain_names(db, workspace_id)
    zones = await client.list_zones()
    discovered: List[Dict[str, Any]] = []
    for zone in zones:
        zone_id = Route53DNSClient._zone_id(zone)  # pylint: disable=protected-access
        name = Route53DNSClient._zone_name(zone)  # pylint: disable=protected-access
        if not zone_id or not name:
            continue
        discovered.append(
            {
                "id": zone_id,
                "name": name,
                "status": Route53DNSClient._zone_status(zone),  # pylint: disable=protected-access
                "account_name": client.account_name,
                "imported": name in known_domains,
            }
        )
    return discovered


async def import_route53_domains(
    db: Session,
    *,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create Domain rows for Route 53 hosted zones."""
    workspace_id = _resolve_workspace_id(db, workspace_id)
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()

    zones = await discover_route53_zones(db, workspace_id=workspace_id)
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
                    description="DNS-discovered from Route 53 hosted-zone import",
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
