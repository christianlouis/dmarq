"""DNS provider connector metadata for import and repair planning."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class DNSProviderConnector:
    """Operator-facing provider connector metadata."""

    id: str
    name: str
    tier: int
    auth_models: List[str]
    zone_import_status: str
    record_read_status: str
    record_write_status: str
    dry_run_supported: bool
    verification_supported: bool
    rollback_supported: bool
    minimum_permissions: List[str] = field(default_factory=list)
    setup_hint: str = ""
    docs_url: Optional[str] = None

    @property
    def zone_import_ready(self) -> bool:
        return self.zone_import_status == "ready"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["zone_import_ready"] = self.zone_import_ready
        return payload


_CONNECTORS: tuple[DNSProviderConnector, ...] = (
    DNSProviderConnector(
        id="cloudflare",
        name="Cloudflare",
        tier=1,
        auth_models=["api_token"],
        zone_import_status="ready",
        record_read_status="ready",
        record_write_status="ready",
        dry_run_supported=True,
        verification_supported=True,
        rollback_supported=True,
        minimum_permissions=[
            "Zone:Read",
            "DNS:Read",
            "DNS:Edit only when one-click repair is enabled",
        ],
        setup_hint=(
            "Create a scoped Cloudflare API token with read-only zone/DNS access first; "
            "add DNS edit permission only when you want approved repair actions."
        ),
        docs_url="https://developers.cloudflare.com/api/resources/zones/methods/list/",
    ),
    DNSProviderConnector(
        id="route53",
        name="Amazon Route 53",
        tier=1,
        auth_models=["iam_role_external_id", "aws_profile", "environment_credentials"],
        zone_import_status="planned",
        record_read_status="planned",
        record_write_status="lexicon_available",
        dry_run_supported=True,
        verification_supported=False,
        rollback_supported=True,
        minimum_permissions=[
            "route53:ListHostedZones",
            "route53:ListResourceRecordSets",
            "route53:ChangeResourceRecordSets only when repair is enabled",
        ],
        setup_hint=(
            "Prefer IAM role assumption with an external ID for hosted deployments; "
            "static access keys should be limited to self-hosted environments."
        ),
        docs_url="https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html",
    ),
    DNSProviderConnector(
        id="akamai_edgedns",
        name="Akamai Edge DNS / FastDNS",
        tier=1,
        auth_models=["edgegrid"],
        zone_import_status="planned",
        record_read_status="planned",
        record_write_status="planned",
        dry_run_supported=False,
        verification_supported=False,
        rollback_supported=True,
        minimum_permissions=[
            "Edge DNS read access",
            "Edge DNS edit access only when repair is enabled",
        ],
        setup_hint=(
            "Use Akamai EdgeGrid credentials for Edge DNS/FastDNS zone access. "
            "Akamai EAA is an access frontdoor option, not the DNS connector."
        ),
        docs_url="https://techdocs.akamai.com/edge-dns/reference/edge-dns-api",
    ),
    DNSProviderConnector(
        id="hetzner",
        name="Hetzner DNS",
        tier=1,
        auth_models=["api_token", "lexicon_environment"],
        zone_import_status="planned",
        record_read_status="planned",
        record_write_status="lexicon_available",
        dry_run_supported=True,
        verification_supported=False,
        rollback_supported=True,
        minimum_permissions=[
            "DNS zone read access",
            "DNS record write access only when repair is enabled",
        ],
        setup_hint=(
            "Use a scoped Hetzner DNS API token; keep the connection read-only until "
            "you explicitly want provider-approved repair actions."
        ),
        docs_url="https://www.hetzner.com/dns/",
    ),
    DNSProviderConnector(
        id="linode",
        name="Linode DNS",
        tier=1,
        auth_models=["personal_access_token", "lexicon_environment"],
        zone_import_status="planned",
        record_read_status="planned",
        record_write_status="lexicon_available",
        dry_run_supported=True,
        verification_supported=False,
        rollback_supported=True,
        minimum_permissions=[
            "Domains read access",
            "Domains write access only when repair is enabled",
        ],
        setup_hint=(
            "Use a Linode token scoped to domains. Linode/Akamai Cloud users can "
            "connect DNS context separately from application login."
        ),
        docs_url="https://techdocs.akamai.com/linode-api/reference/get-domains",
    ),
)


def provider_connector_registry() -> List[Dict[str, Any]]:
    """Return all known DNS provider connector metadata."""
    return [connector.to_dict() for connector in _CONNECTORS]


def provider_connector_metadata(provider_id: str) -> Optional[Dict[str, Any]]:
    """Return metadata for one connector by normalized provider ID."""
    normalized = provider_id.strip().lower().replace("_", "-")
    aliases = {
        "akamai-edgedns": "akamai_edgedns",
        "akamai": "akamai_edgedns",
        "edgedns": "akamai_edgedns",
        "fastdns": "akamai_edgedns",
    }
    canonical = aliases.get(normalized, normalized.replace("-", "_"))
    for connector in _CONNECTORS:
        if connector.id == canonical:
            return connector.to_dict()
    return None
