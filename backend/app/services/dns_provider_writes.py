"""Provider-backed DNS write planning and execution."""

from __future__ import annotations

import asyncio
import importlib.util
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.workspace import Workspace
from app.services.cloudflare_dns import (
    build_cloudflare_provider,
    get_zone_for_domain,
    sync_dns_record_changes,
)

SUPPORTED_AUTOMATED_RECORD_TYPES = {"TXT", "CNAME"}
SUPPORTED_AUTOMATED_OPERATIONS = {"create", "update"}
NATIVE_PROVIDERS = {"cloudflare"}
LEXICON_PROVIDERS = {
    "aliyun",
    "azure",
    "cloudns",
    "digitalocean",
    "dnsimple",
    "dnsmadeeasy",
    "gandi",
    "godaddy",
    "googleclouddns",
    "hetzner",
    "ionos",
    "linode",
    "namecheap",
    "ovh",
    "powerdns",
    "route53",
    "vultr",
}


class DNSProviderWriteError(ValueError):
    """Raised when a provider write cannot be safely prepared or applied."""


@dataclass
class DNSWriteMutation:
    """Concrete provider mutation derived from a DMARQ DNS change plan."""

    # pylint: disable=too-many-instance-attributes

    operation: str
    record_type: str
    name: str
    content: str
    ttl: int
    provider: str
    zone_id: Optional[str] = None
    zone_name: Optional[str] = None
    record_id: Optional[str] = None
    current_values: List[str] = field(default_factory=list)
    blocked_reason: Optional[str] = None

    @property
    def applicable(self) -> bool:
        return self.blocked_reason is None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "record_type": self.record_type,
            "name": self.name,
            "content": self.content,
            "ttl": self.ttl,
            "provider": self.provider,
            "zone_id": self.zone_id,
            "zone_name": self.zone_name,
            "record_id": self.record_id,
            "current_values": self.current_values,
            "applicable": self.applicable,
            "blocked_reason": self.blocked_reason,
        }


@dataclass
class DNSWriteVerification:
    """Provider-side verification evidence for an applied DNS mutation."""

    status: str
    verified: bool
    checked_values: List[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "verified": self.verified,
            "checked_values": self.checked_values,
            "message": self.message,
        }


@dataclass
class DNSWriteResult:
    """Result of previewing or applying one DNS provider mutation."""

    provider: str
    dry_run: bool
    applied: bool
    mutation: DNSWriteMutation
    provider_result: Optional[Dict[str, Any]] = None
    changes: List[Dict[str, Any]] = field(default_factory=list)
    verification: DNSWriteVerification = field(
        default_factory=lambda: DNSWriteVerification(
            status="not_run",
            verified=False,
            message="Verification only runs after a confirmed provider apply.",
        )
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "dry_run": self.dry_run,
            "applied": self.applied,
            "mutation": self.mutation.to_dict(),
            "provider_result": self.provider_result,
            "changes": self.changes,
            "verification": self.verification.to_dict(),
        }


class DNSWriteProvider(Protocol):
    """Provider-specific DNS write operations."""

    provider_id: str

    async def prepare_mutation(
        self,
        db: Session,
        *,
        domain: str,
        plan: Dict[str, Any],
        value_override: Optional[str],
        ttl: int,
    ) -> DNSWriteMutation:
        """Return the concrete mutation for the supplied plan."""

    async def apply_mutation(
        self,
        db: Session,
        *,
        domain: str,
        mutation: DNSWriteMutation,
    ) -> DNSWriteResult:
        """Apply the concrete mutation and return provider evidence."""


def normalize_provider_id(provider: str) -> str:
    """Normalize user-facing provider IDs for registry lookups."""
    return provider.strip().lower().replace("_", "-")


def provider_capabilities() -> List[Dict[str, Any]]:
    """Return available DNS write provider capabilities."""
    capabilities = [
        {
            "id": "cloudflare",
            "name": "Cloudflare",
            "mode": "native",
            "record_types": sorted(SUPPORTED_AUTOMATED_RECORD_TYPES),
            "operations": sorted(SUPPORTED_AUTOMATED_OPERATIONS),
            "credentials": "DMARQ Cloudflare settings or environment",
            "status": "ready",
        }
    ]
    lexicon_available = lexicon_runtime_available()
    for provider_id in sorted(LEXICON_PROVIDERS):
        capabilities.append(
            {
                "id": provider_id,
                "name": provider_id,
                "mode": "lexicon",
                "record_types": sorted(SUPPORTED_AUTOMATED_RECORD_TYPES),
                "operations": ["create", "update"],
                "credentials": "Lexicon provider environment/configuration",
                "status": "ready" if lexicon_available else "dependency_missing",
            }
        )
    return capabilities


def lexicon_runtime_available() -> bool:
    """Return whether the optional Lexicon runtime can be imported."""
    return bool(
        importlib.util.find_spec("lexicon.client") and importlib.util.find_spec("lexicon.config")
    )


def _plan_value(plan: Dict[str, Any], value_override: Optional[str]) -> str:
    value = (value_override or plan.get("proposed_value") or "").strip()
    if not value:
        raise DNSProviderWriteError("This DNS plan does not include an apply-ready record value")
    if "<" in value or ">" in value:
        raise DNSProviderWriteError(
            "This DNS plan needs a provider-specific value before it can be applied"
        )
    return value


def _validate_plan_for_automation(plan: Dict[str, Any]) -> None:
    operation = str(plan.get("operation") or "").lower()
    record_type = str(plan.get("record_type") or "").upper()
    if operation not in SUPPORTED_AUTOMATED_OPERATIONS:
        raise DNSProviderWriteError(
            f"Operation '{operation}' is not safe for automatic DNS writes yet"
        )
    if record_type not in SUPPORTED_AUTOMATED_RECORD_TYPES:
        raise DNSProviderWriteError(
            f"Record type '{record_type}' is not supported for automatic DNS writes yet"
        )


def _verification_from_records(
    *,
    mutation: DNSWriteMutation,
    records: List[Dict[str, Any]],
) -> DNSWriteVerification:
    """Return provider-side evidence that the expected record is now visible."""
    checked_values = [
        str(record.get("content") or "")
        for record in records
        if (not record.get("type") or str(record.get("type") or "").upper() == mutation.record_type)
        and (
            not record.get("name")
            or str(record.get("name") or "").rstrip(".").lower()
            == mutation.name.rstrip(".").lower()
        )
    ]
    verified = mutation.content in checked_values
    if verified:
        return DNSWriteVerification(
            status="verified",
            verified=True,
            checked_values=checked_values,
            message="Provider API returned the expected DNS record after apply.",
        )
    return DNSWriteVerification(
        status="failed",
        verified=False,
        checked_values=checked_values,
        message=(
            "Provider API did not return the expected DNS record after apply; "
            "verify propagation and provider state before treating this as repaired."
        ),
    )


def _noop_verification(mutation: DNSWriteMutation) -> DNSWriteVerification:
    """Return verification evidence for an unchanged record."""
    verified = mutation.content in mutation.current_values
    return DNSWriteVerification(
        status="already_current" if verified else "failed",
        verified=verified,
        checked_values=mutation.current_values,
        message=(
            "Provider already has the expected DNS value."
            if verified
            else "Provider preview marked this record unchanged, but the expected value was not present."
        ),
    )


class CloudflareDNSWriteProvider:
    """DNS write provider backed by DMARQ's native Cloudflare client."""

    provider_id = "cloudflare"

    async def prepare_mutation(
        self,
        db: Session,
        *,
        domain: str,
        plan: Dict[str, Any],
        value_override: Optional[str],
        ttl: int,
    ) -> DNSWriteMutation:
        _validate_plan_for_automation(plan)
        value = _plan_value(plan, value_override)
        record_type = str(plan["record_type"]).upper()
        record_name = str(plan["name"])
        zone = await get_zone_for_domain(db, domain)
        matches = [
            record
            for record in zone.get("records", [])
            if str(record.get("type") or "").upper() == record_type
            and str(record.get("name") or "").rstrip(".").lower() == record_name.rstrip(".").lower()
        ]
        current_values = [str(record.get("content") or "") for record in matches]
        if len(matches) > 1:
            return DNSWriteMutation(
                operation=str(plan["operation"]).lower(),
                record_type=record_type,
                name=record_name,
                content=value,
                ttl=ttl,
                provider=self.provider_id,
                zone_id=zone.get("id"),
                zone_name=zone.get("name"),
                current_values=current_values,
                blocked_reason=(
                    "Multiple provider records match this name/type; merge them manually first"
                ),
            )
        if matches and current_values[0] == value:
            operation = "noop"
        elif matches:
            operation = "update"
        else:
            operation = "create"
        return DNSWriteMutation(
            operation=operation,
            record_type=record_type,
            name=record_name,
            content=value,
            ttl=ttl,
            provider=self.provider_id,
            zone_id=zone.get("id"),
            zone_name=zone.get("name"),
            record_id=matches[0].get("id") if matches else None,
            current_values=current_values,
        )

    async def apply_mutation(
        self,
        db: Session,
        *,
        domain: str,
        mutation: DNSWriteMutation,
    ) -> DNSWriteResult:
        if not mutation.applicable:
            raise DNSProviderWriteError(mutation.blocked_reason or "DNS mutation is blocked")
        if mutation.operation == "noop":
            return DNSWriteResult(
                provider=self.provider_id,
                dry_run=False,
                applied=False,
                mutation=mutation,
                provider_result={"status": "unchanged"},
                verification=_noop_verification(mutation),
            )

        provider = build_cloudflare_provider(db)
        if not mutation.zone_id:
            raise DNSProviderWriteError("Cloudflare zone ID could not be resolved")
        if mutation.operation == "update":
            if not mutation.record_id:
                raise DNSProviderWriteError("Cloudflare record ID is required for updates")
            provider_result = await provider.update_dns_record(
                zone_id=mutation.zone_id,
                record_id=mutation.record_id,
                record_type=mutation.record_type,
                name=mutation.name,
                content=mutation.content,
                ttl=mutation.ttl,
            )
        elif mutation.operation == "create":
            provider_result = await provider.create_dns_record(
                zone_id=mutation.zone_id,
                record_type=mutation.record_type,
                name=mutation.name,
                content=mutation.content,
                ttl=mutation.ttl,
            )
        else:
            raise DNSProviderWriteError(f"Unsupported Cloudflare operation: {mutation.operation}")

        records = await provider.list_dns_records(zone_id=mutation.zone_id)
        changes = sync_dns_record_changes(
            db,
            domain=domain,
            zone_id=mutation.zone_id,
            records=records,
        )
        verification = _verification_from_records(mutation=mutation, records=records)
        return DNSWriteResult(
            provider=self.provider_id,
            dry_run=False,
            applied=True,
            mutation=mutation,
            provider_result=provider_result,
            changes=changes,
            verification=verification,
        )


class LexiconDNSWriteProvider:
    """DNS write provider backed by dns-lexicon for API-backed providers."""

    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id

    async def prepare_mutation(
        self,
        db: Session,  # pylint: disable=unused-argument
        *,
        domain: str,
        plan: Dict[str, Any],
        value_override: Optional[str],
        ttl: int,
    ) -> DNSWriteMutation:
        if not lexicon_runtime_available():
            raise DNSProviderWriteError("dns-lexicon is not installed in this DMARQ runtime")
        _validate_plan_for_automation(plan)
        value = _plan_value(plan, value_override)
        record_type = str(plan["record_type"]).upper()
        record_name = str(plan["name"])
        current = await asyncio.to_thread(
            self._list_records,
            domain,
            record_type,
            record_name,
        )
        current_values = [str(record.get("content") or "") for record in current]
        if len(current) > 1:
            return DNSWriteMutation(
                operation=str(plan["operation"]).lower(),
                record_type=record_type,
                name=record_name,
                content=value,
                ttl=ttl,
                provider=self.provider_id,
                current_values=current_values,
                blocked_reason=(
                    "Multiple provider records match this name/type; merge them manually first"
                ),
            )
        operation = "noop" if current_values == [value] else ("update" if current else "create")
        return DNSWriteMutation(
            operation=operation,
            record_type=record_type,
            name=record_name,
            content=value,
            ttl=ttl,
            provider=self.provider_id,
            record_id=str(current[0].get("id") or "") if current else None,
            current_values=current_values,
        )

    async def apply_mutation(
        self,
        db: Session,  # pylint: disable=unused-argument
        *,
        domain: str,
        mutation: DNSWriteMutation,
    ) -> DNSWriteResult:
        if not mutation.applicable:
            raise DNSProviderWriteError(mutation.blocked_reason or "DNS mutation is blocked")
        if mutation.operation == "noop":
            return DNSWriteResult(
                provider=self.provider_id,
                dry_run=False,
                applied=False,
                mutation=mutation,
                provider_result={"status": "unchanged"},
                verification=_noop_verification(mutation),
            )
        provider_result = await asyncio.to_thread(self._apply_record, domain, mutation)
        if not provider_result:
            raise DNSProviderWriteError(
                f"Lexicon provider '{self.provider_id}' did not apply the DNS mutation"
            )
        records = await asyncio.to_thread(
            self._list_records,
            domain,
            mutation.record_type,
            mutation.name,
        )
        return DNSWriteResult(
            provider=self.provider_id,
            dry_run=False,
            applied=True,
            mutation=mutation,
            provider_result={"ok": True},
            verification=_verification_from_records(mutation=mutation, records=records),
        )

    def _client_config(self, domain: str):
        from lexicon.config import ConfigResolver  # pylint: disable=import-outside-toplevel

        return (
            ConfigResolver()
            .with_env()
            .with_dict(
                {
                    "provider_name": self.provider_id,
                    "domain": domain,
                }
            )
        )

    def _list_records(
        self,
        domain: str,
        record_type: str,
        record_name: str,
    ) -> List[Dict[str, Any]]:
        from lexicon.client import Client  # pylint: disable=import-outside-toplevel

        with Client(self._client_config(domain)) as operations:
            return operations.list_records(record_type, record_name)

    def _apply_record(self, domain: str, mutation: DNSWriteMutation) -> bool:
        from lexicon.client import Client  # pylint: disable=import-outside-toplevel

        with Client(self._client_config(domain)) as operations:
            if mutation.operation == "create":
                return bool(
                    operations.create_record(
                        mutation.record_type,
                        mutation.name,
                        mutation.content,
                        ttl=mutation.ttl,
                    )
                )
            if mutation.operation == "update":
                return bool(
                    operations.update_record(
                        mutation.record_id,
                        mutation.record_type,
                        mutation.name,
                        mutation.content,
                        ttl=mutation.ttl,
                    )
                )
        raise DNSProviderWriteError(f"Unsupported Lexicon operation: {mutation.operation}")


def build_dns_write_provider(provider_id: str) -> DNSWriteProvider:
    """Return the configured DNS write provider implementation."""
    normalized = normalize_provider_id(provider_id)
    if normalized in NATIVE_PROVIDERS:
        return CloudflareDNSWriteProvider()
    if normalized in LEXICON_PROVIDERS:
        return LexiconDNSWriteProvider(normalized)
    raise DNSProviderWriteError(f"Unsupported DNS provider: {provider_id}")


async def preview_dns_write(
    db: Session,
    *,
    domain: str,
    plan: Dict[str, Any],
    provider_id: str,
    value_override: Optional[str] = None,
    ttl: int = 1,
) -> DNSWriteResult:
    """Return the provider mutation without applying it."""
    provider = build_dns_write_provider(provider_id)
    mutation = await provider.prepare_mutation(
        db,
        domain=domain,
        plan=plan,
        value_override=value_override,
        ttl=ttl,
    )
    return DNSWriteResult(
        provider=normalize_provider_id(provider_id),
        dry_run=True,
        applied=False,
        mutation=mutation,
    )


async def apply_dns_write(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    plan: Dict[str, Any],
    provider_id: str,
    value_override: Optional[str] = None,
    ttl: int = 1,
) -> DNSWriteResult:
    """Apply one provider-backed DNS mutation after validation."""
    if get_settings().DEMO_MODE:
        raise DNSProviderWriteError("Provider DNS writes are disabled in demo mode")
    if workspace.id is None:
        raise DNSProviderWriteError("Workspace must be persisted before applying DNS changes")
    provider = build_dns_write_provider(provider_id)
    mutation = await provider.prepare_mutation(
        db,
        domain=domain,
        plan=plan,
        value_override=value_override,
        ttl=ttl,
    )
    result = await provider.apply_mutation(db, domain=domain, mutation=mutation)
    db.flush()
    return result
