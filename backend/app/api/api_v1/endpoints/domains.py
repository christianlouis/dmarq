import asyncio
import csv
import hashlib
import html
import io
import ipaddress
import json
import logging
import secrets
from dataclasses import asdict
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.services.akamai_edgedns import get_akamai_edgedns_credentials
from app.services.bimi import BIMIResult, check_bimi_cached
from app.services.cloudflare_dns import (
    analyze_dns_records,
    discover_cloudflare_zones,
    get_cloudflare_credentials,
    get_zone_for_domain,
    import_cloudflare_domains,
    list_dns_record_changes,
    sync_dns_record_changes,
    verify_cloudflare_domain_ownership,
)
from app.services.cloudflare_oauth import (
    build_cloudflare_authorization_url,
    build_cloudflare_oauth_state,
    cloudflare_oauth_configured,
    cloudflare_scope_profile_metadata,
    cloudflare_scopes_for_profile,
    decode_cloudflare_oauth_state,
    exchange_cloudflare_oauth_code,
    normalize_cloudflare_scope_profile,
    persist_cloudflare_oauth_tokens,
)
from app.services.dane import check_dane_cached
from app.services.demo_data import DEMO_DAYS, build_demo_health_score_history
from app.services.dns_cache import (
    get_cached_domain_dns_result,
    get_latest_cached_domain_dns_evidence,
    resolve_domain_dns_cached,
)
from app.services.dns_guidance import MailAuthSetupDefaults, build_dns_guidance
from app.services.dns_provider_connectors import (
    provider_connector_metadata,
    provider_connector_registry,
)
from app.services.dns_provider_imports import (
    import_dns_provider_domains,
    preview_dns_provider_import,
    supported_import_providers,
)
from app.services.dns_provider_writes import (
    DNSProviderWriteError,
    apply_dns_write,
    normalize_provider_id,
    preview_dns_write,
    provider_capabilities,
    simulate_demo_dns_preview,
    simulate_demo_dns_write,
)
from app.services.dns_resolver import (
    CloudflareDNSProvider,
    DomainDNSResult,
    PublicRecursiveDNSProvider,
    extract_dmarc_policy,
    get_default_provider,
)
from app.services.health_score import build_health_summary, score_domain_health
from app.services.health_score_snapshots import (
    aggregate_workspace_health_points,
    build_health_evidence_export_rows,
    build_health_score_history,
    build_workspace_health_score_history,
    list_health_score_snapshots,
    list_workspace_health_score_snapshots,
    upsert_health_score_snapshot,
)
from app.services.hetzner_dns import get_hetzner_dns_credentials
from app.services.linode_dns import get_linode_dns_credentials
from app.services.mail_service_imports import (
    MailServiceImportError,
    import_mail_service_domains,
    mail_service_context_from_domain,
    mail_service_dns_records_for_domain,
    preview_mail_service_import,
    supported_mail_service_import_providers,
)
from app.services.migration_import import preview_migration_import
from app.services.mta_sts import MTAStsResult, check_mta_sts_cached
from app.services.organizations import (
    OrganizationPlanLimitError,
    require_organization_plan_limit,
)
from app.services.remediation_dispatch import (
    attach_remediation_dispatch_previews,
    summarize_remediation_activity,
)
from app.services.remediation_queue import build_remediation_queue
from app.services.report_persistence import (
    domain_summaries_from_db,
    hydrate_domain_report_store_from_db,
    hydrate_report_store_from_db,
)
from app.services.report_store import ReportStore
from app.services.route53_dns import get_route53_dns_credentials
from app.services.sender_intelligence import (
    build_source_intelligence,
    identify_sender,
    source_geo_for,
)
from app.services.source_network import (
    SourceNetworkIntelligence,
    lookup_sources_network_cached,
    merge_network_into_geo,
)
from app.services.source_reputation import (
    SourceReputation,
    build_source_reputation_cached,
    reputation_presentation,
    source_reputation_by_ip,
)
from app.services.source_reputation_feeds import feed_registry
from app.services.webhook_events import delivery_to_dict, enqueue_webhook_event
from app.services.workspace_access import (
    PERMISSION_DOMAINS_WRITE,
    PERMISSION_REPORTS_READ,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import audit_log_to_dict, record_workspace_audit_log
from app.services.workspaces import (
    workspace_domain_query,
)
from app.utils.domain_validator import normalize_domain_name, validate_domain_config

logger = logging.getLogger(__name__)

router = APIRouter()
DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE = 500
REMEDIATION_NOTIFICATION_LIFECYCLE_STATES = {
    "previewed",
    "acknowledged",
    "snoozed",
    "resolved",
    "rejected",
}


def _authorized_domain_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    permission: str = PERMISSION_DOMAINS_WRITE,
    selected_workspace_id: Optional[int] = None,
):
    """Authorize workspace domain/DNS setup before legacy repair writes."""
    return resolve_authorized_workspace(
        db,
        auth_context,
        permission,
        selected_workspace_id=selected_workspace_id,
    )


def _authorized_domain_read_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    selected_workspace_id: Optional[int] = None,
):
    """Authorize read-only domain/report/DNS visibility for the default workspace."""
    return _authorized_domain_workspace(
        auth_context,
        db,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=selected_workspace_id,
    )


def _raise_plan_limit_error(exc: OrganizationPlanLimitError) -> None:
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=exc.to_detail(),
    ) from exc


def _setting_value(db: Session, key: str) -> Optional[str]:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value else None


def _int_setting_value(db: Session, key: str, default: int) -> int:
    value = _setting_value(db, key)
    try:
        return default if value in {None, ""} else int(value)
    except (TypeError, ValueError):
        return default


def _normalize_optional_mailbox(value: Optional[str]) -> Optional[str]:
    """Return a trimmed mailbox override or None when the operator cleared it."""
    mailbox = (value or "").strip()
    if not mailbox:
        return None
    if mailbox.lower().startswith("mailto:"):
        mailbox = mailbox[7:].strip()
    if any(character in mailbox for character in (";", ",")):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="DMARC report mailbox must be a single email address",
        )
    if mailbox.count("@") != 1 or mailbox.startswith("@") or mailbox.endswith("@"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="DMARC report mailbox must be a valid email address",
        )
    if any(character.isspace() for character in mailbox):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="DMARC report mailbox must not contain whitespace",
        )
    return mailbox


def _mail_auth_setup_defaults(
    db: Session, domain: Optional[Domain] = None
) -> MailAuthSetupDefaults:
    report_mailbox = (
        domain.dmarc_report_mailbox
        if domain is not None and domain.dmarc_report_mailbox
        else _setting_value(db, "dmarc.report_mailbox")
    )
    return MailAuthSetupDefaults(
        report_mailbox=report_mailbox,
        tls_report_mailbox=_setting_value(db, "dmarc.tls_report_mailbox"),
        policy=_setting_value(db, "dmarc.default_policy") or "none",
        percentage=_int_setting_value(db, "dmarc.default_percentage", 100),
        adkim=_setting_value(db, "dmarc.default_adkim") or "r",
        aspf=_setting_value(db, "dmarc.default_aspf") or "r",
    )


def _public_base_url(request: Request, db: Session) -> str:
    """Return the externally visible base URL for provider OAuth redirects."""
    configured = get_settings().PUBLIC_BASE_URL or _setting_value(db, "general.base_url")
    if configured:
        return configured.rstrip("/")

    base_url = str(request.base_url).rstrip("/")
    forwarded_proto = (
        (request.headers.get("x-forwarded-proto") or "").split(",", maxsplit=1)[0].strip()
    )
    if forwarded_proto in {"http", "https"} and "://" in base_url:
        _, rest = base_url.split("://", maxsplit=1)
        return f"{forwarded_proto}://{rest}".rstrip("/")
    return base_url


def _normalize_reported_policy(policy_value: Any) -> Optional[str]:
    """Return the effective DMARC p= policy from stored summary values."""
    if isinstance(policy_value, dict):
        return policy_value.get("p")
    return policy_value


class DomainBase(BaseModel):
    """Base Domain schema"""

    name: str
    description: Optional[str] = None
    policy: Optional[str] = None


class DomainResponse(DomainBase):
    """Domain response schema"""

    reports_count: int = 0
    emails_count: int = 0
    compliance_rate: float = 0.0
    dkim_selectors: List[str] = Field(default_factory=list)
    dmarc_report_mailbox: Optional[str] = None
    mail_service_context: List[Dict[str, Any]] = Field(default_factory=list)


class DomainCreate(BaseModel):
    """Payload for creating a monitored domain."""

    name: str
    description: Optional[str] = None
    dkim_selectors: Optional[List[str]] = None
    dmarc_report_mailbox: Optional[str] = None


class DomainUpdate(BaseModel):
    """Payload for updating editable monitored-domain metadata."""

    description: Optional[str] = None
    dkim_selectors: Optional[List[str]] = None
    dmarc_report_mailbox: Optional[str] = None


class DomainStatsResponse(BaseModel):
    """Domain statistics for the domain details page"""

    complianceRate: float
    totalEmails: int
    failedEmails: int
    reportCount: int


class DomainOwnershipResponse(BaseModel):
    """Domain ownership proof state and DNS instructions."""

    domain: str
    verified: bool
    proof_record_name: str
    proof_record_type: str = "TXT"
    proof_record_value: str
    proof_reason: str
    next_steps: List[str] = Field(default_factory=list)


class DomainOwnershipVerifyResponse(DomainOwnershipResponse):
    """Result of a live ownership proof check."""

    checked: bool = True
    matched: bool
    observed_values: List[str] = Field(default_factory=list)


class MigrationReadinessItem(BaseModel):
    """One safe migration readiness checklist item."""

    key: str
    status: str
    title: str
    detail: str
    action: str
    evidence: List[str] = Field(default_factory=list)
    href: Optional[str] = None


class MigrationExportLink(BaseModel):
    """Portable export surface available during migration or offboarding."""

    label: str
    href: str
    format: str
    detail: str


class MigrationReadinessResponse(BaseModel):
    """Migration and data-portability readiness for one monitored domain."""

    domain: str
    status: str
    readiness_score: int
    summary: str
    parallel_reporting_days: int
    report_count: int
    source_count: int
    checklist: List[MigrationReadinessItem]
    export_links: List[MigrationExportLink]
    supported_sources: List[str] = Field(default_factory=list)
    docs_url: str = "https://github.com/christianlouis/dmarq/blob/main/docs/user_guide/migration.md"


class MigrationParityMetric(BaseModel):
    """One DMARQ-vs-legacy migration parity comparison."""

    key: str
    label: str
    status: str
    unit: str
    dmarq_value: Any
    dmarq_display: str
    baseline_value: Optional[Any] = None
    baseline_display: str = "Not provided"
    delta: Optional[float] = None
    detail: str


class MigrationParityResponse(BaseModel):
    """Migration parity dashboard for one monitored domain."""

    domain: str
    status: str
    summary: str
    baseline_required: bool
    tolerance_percent: float
    metrics: List[MigrationParityMetric]
    next_steps: List[str] = Field(default_factory=list)


class MigrationImportPreviewRequest(BaseModel):
    """Read-only historical export preview request."""

    content: Any
    format: str = Field(default="auto", pattern="^(auto|csv|json)$")
    source_platform: Optional[str] = None
    max_rows: int = Field(default=50, ge=1, le=500)


class MigrationImportBaseline(BaseModel):
    """Suggested legacy baseline values derived from a historical export."""

    report_count: int
    total_emails: int
    source_count: int
    compliance_rate: float
    policy: Optional[str] = None
    date_start: Optional[str] = None
    date_end: Optional[str] = None


class MigrationImportPreviewRow(BaseModel):
    """One normalized read-only export row."""

    row_key: Optional[str] = None
    report_import_key: Optional[str] = None
    import_status: Optional[str] = None
    domain: Optional[str] = None
    report_id: Optional[str] = None
    begin_date: Optional[str] = None
    end_date: Optional[str] = None
    source_ip: Optional[str] = None
    count: int
    dkim: Optional[str] = None
    spf: Optional[str] = None
    disposition: Optional[str] = None
    policy: Optional[str] = None
    org_name: Optional[str] = None


class MigrationImportPreviewResponse(BaseModel):
    """Read-only preview of a historical DMARC platform export."""

    domain: str
    status: str
    source_platform: Optional[str] = None
    format: str
    import_mode: str = "preview_only"
    row_count: int
    normalized_count: int
    ignored_count: int
    rejected_count: int
    truncated_count: int
    importable_row_count: int
    planned_report_count: int
    existing_report_count: int
    duplicate_row_count: int
    needs_report_id_count: int
    batch_fingerprint: str
    detected_columns: List[str]
    mapped_columns: Dict[str, str]
    warnings: List[str] = Field(default_factory=list)
    baseline: MigrationImportBaseline
    sample_rows: List[MigrationImportPreviewRow] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)


class DNSRecordResponse(BaseModel):
    """DNS record information for a domain"""

    dmarc: bool
    dmarcRecord: Optional[str] = None
    spf: bool
    spfRecord: Optional[str] = None
    dkim: bool
    dkimSelectors: List[str] = []
    cached: bool = False
    checkedAt: Optional[str] = None
    dmarcWarnings: List[str] = []
    dmarcSuggestions: List[str] = []
    nameservers: List[str] = []
    dnsProvider: Optional[Dict[str, Any]] = None
    providerContext: Optional[Dict[str, Any]] = None
    lookupStatus: str = "ok"
    lookupError: Optional[str] = None


class DNSGuidanceRecordResponse(BaseModel):
    """Suggested DNS record for setup or repair."""

    code: str
    record_type: str
    name: str
    value: str
    purpose: str
    priority: str = "recommended"


class DNSLintFindingResponse(BaseModel):
    """Machine-readable DNS lint finding."""

    code: str
    severity: str
    title: str
    detail: str
    action: str
    record_type: str
    record_name: str
    target_record: Optional[DNSGuidanceRecordResponse] = None
    evidence: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)


class DNSChangePlanItemResponse(BaseModel):
    """Read-only DNS change plan for operator review."""

    plan_id: str
    finding_code: str
    severity: str
    operation: str
    record_type: str
    name: str
    proposed_value: Optional[str] = None
    current_values: List[str] = Field(default_factory=list)
    rationale: str
    risk: str
    rollback: str
    expected_health_impact: str
    manual_steps: List[str] = Field(default_factory=list)
    requires_approval: bool = True
    applies_automatically: bool = False
    provider_write_available: bool = False
    provider_value_required: bool = False
    safety_notes: List[str] = Field(default_factory=list)


class DNSChangePlanResponse(BaseModel):
    """Read-only DNS change plan response for one domain."""

    domain: str
    status: str
    read_only: bool = True
    provider_write_available: bool = False
    dns_provider: Optional[Dict[str, Any]] = None
    recommended_provider: Optional[str] = None
    available_write_providers: List[str] = Field(default_factory=list)
    safety_notes: List[str] = Field(default_factory=list)
    apply_endpoint: Optional[str] = None
    plans: List[DNSChangePlanItemResponse]


def read_only_dns_change_plan_response(payload: Any) -> DNSChangePlanResponse:
    """Return an automation-safe DNS plan payload without write affordances."""
    data = payload.model_dump() if hasattr(payload, "model_dump") else dict(payload)
    plans = []
    for plan in data.get("plans") or []:
        plan_data = plan.model_dump() if hasattr(plan, "model_dump") else dict(plan)
        plans.append(
            {
                **plan_data,
                "provider_write_available": False,
                "applies_automatically": False,
            }
        )
    return DNSChangePlanResponse(
        domain=data["domain"],
        status=data["status"],
        read_only=True,
        provider_write_available=False,
        dns_provider=data.get("dns_provider"),
        recommended_provider=None,
        available_write_providers=[],
        safety_notes=[
            "Public automation responses are read-only and never expose DNS write affordances."
        ],
        apply_endpoint=None,
        plans=plans,
    )


DNS_AUTOMATION_OPERATIONS = {"create", "update"}
DNS_AUTOMATION_RECORD_TYPES = {"TXT", "CNAME"}
DNS_PROVIDER_ID_ALIASES = {
    "azure-dns": "azure",
    "azure_dns": "azure",
}


def _canonical_dns_provider_id(provider: Optional[str]) -> str:
    """Normalize detected and requested DNS provider IDs for comparisons."""
    raw_provider = str(provider or "").strip().lower()
    normalized_provider = normalize_provider_id(raw_provider)
    return (
        DNS_PROVIDER_ID_ALIASES.get(raw_provider)
        or DNS_PROVIDER_ID_ALIASES.get(normalized_provider)
        or normalized_provider
    )


def _ready_dns_write_provider_ids() -> List[str]:
    """Return configured provider IDs that can be used for DNS write previews."""
    return [
        provider["id"] for provider in provider_capabilities() if provider.get("status") == "ready"
    ]


def _recommended_dns_write_provider(
    dns_provider: Optional[Dict[str, Any]], available_providers: List[str]
) -> Optional[str]:
    """Map detected DNS provider metadata to an available writer implementation."""
    if not dns_provider:
        return available_providers[0] if available_providers else None
    provider_id = _detected_dns_provider_id(dns_provider)
    if provider_id in available_providers:
        return provider_id
    return None


def _detected_dns_provider_id(dns_provider: Optional[Dict[str, Any]]) -> Optional[str]:
    """Return a known detected provider ID, ignoring custom/unknown detections."""
    if not dns_provider:
        return None
    provider_id = _canonical_dns_provider_id(dns_provider.get("provider_id"))
    if provider_id in {"", "custom", "unknown"}:
        return None
    return provider_id


def _provider_credentials_configured(db: Session, provider_id: Optional[str]) -> bool:
    """Return whether DMARQ has non-secret connection material for a DNS provider."""
    normalized = _canonical_dns_provider_id(provider_id)
    try:
        if normalized == "cloudflare":
            return get_cloudflare_credentials(db).configured
        if normalized == "route53":
            return get_route53_dns_credentials().configured
        if normalized == "akamai-edgedns":
            return get_akamai_edgedns_credentials().configured
        if normalized == "hetzner":
            return get_hetzner_dns_credentials().configured
        if normalized == "linode":
            return get_linode_dns_credentials().configured
    except Exception as exc:  # pragma: no cover - defensive, no secret values are exposed.
        logger.info("DNS provider credential readiness check failed for %s: %s", normalized, exc)
    return False


def _dns_provider_repair_context(
    db: Session,
    *,
    dns_provider: Optional[Dict[str, Any]],
    nameservers: List[str],
) -> Dict[str, Any]:
    """Build read-only provider connection and DNS repair readiness guidance."""
    provider_id = _detected_dns_provider_id(dns_provider)
    provider_name = (
        dns_provider.get("provider_name") if dns_provider else "Unknown DNS provider"
    ) or "Unknown DNS provider"
    connector = provider_connector_metadata(provider_id or "") if provider_id else None
    import_provider_ids = {provider["id"] for provider in supported_import_providers()}
    write_provider_ids = set(_ready_dns_write_provider_ids())
    connected = _provider_credentials_configured(db, provider_id)
    confidence = (dns_provider or {}).get("confidence") or "unknown"
    can_import = bool(provider_id and provider_id in import_provider_ids and connector)
    write_connector_ready = bool(provider_id and provider_id in write_provider_ids and connector)
    can_repair = bool(connected and write_connector_ready)

    if not dns_provider or not nameservers:
        status = "manual"
        summary = "DMARQ has not seen authoritative nameserver evidence for this domain yet."
        cta_label = "Refresh DNS"
        cta_href = "#dns-records"
        next_steps = [
            "Refresh DNS after delegation is visible.",
            "Use the manual DNS instructions until a provider can be detected.",
        ]
    elif not connector:
        status = "manual"
        summary = f"{provider_name} was detected, but DMARQ does not have a connector for it yet."
        cta_label = "Use manual change plan"
        cta_href = "#dns-guidance"
        next_steps = [
            "Review the DNS lint findings and manual change plan.",
            "Apply changes in the provider console with a human approval step.",
        ]
    elif connected and can_repair:
        status = "connected"
        summary = (
            f"{provider_name} is connected. DMARQ can import zones, verify ownership, "
            "preview safe DNS repairs, and apply approved changes."
        )
        cta_label = "Open DNS change plan"
        cta_href = "#dns-guidance"
        next_steps = [
            "Review the DNS lint findings and generated change plans.",
            "Preview the provider mutation before applying any DNS change.",
            "Approve only changes whose zone, record name, old value, and new value match intent.",
        ]
    elif connected:
        status = "read_only"
        summary = (
            f"{provider_name} is connected for read/import context, but automatic repair is "
            "not enabled for this provider yet."
        )
        cta_label = "Import provider zones"
        cta_href = "/settings#provider-integrations"
        next_steps = [
            "Import visible provider zones to monitor DNS posture before reports arrive.",
            "Use manual DNS changes until write support is available for this connector.",
        ]
    else:
        status = "connect"
        summary = (
            f"{provider_name} appears authoritative for this domain. Connect it to verify "
            "ownership, import zones, and unlock provider-aware repair previews."
        )
        cta_label = f"Connect {provider_name}"
        cta_href = "/settings#provider-integrations"
        next_steps = [
            "Connect the provider with read-only zone and DNS permissions first.",
            "Import the zone so DMARQ can confirm account-level ownership.",
            "Add write scope only when you want human-approved one-click DNS repair.",
        ]

    return {
        "status": status,
        "detected_provider_id": provider_id,
        "detected_provider_name": provider_name,
        "confidence": confidence,
        "connected": connected,
        "can_import_zones": can_import,
        "can_preview_repairs": write_connector_ready,
        "can_apply_repairs": can_repair,
        "connector": connector,
        "summary": summary,
        "cta_label": cta_label,
        "cta_href": cta_href,
        "next_steps": next_steps,
        "nameservers": nameservers,
    }


def _ensure_dns_provider_selection_is_safe(
    *, requested_provider: str, provider_match_target: Optional[str], allow_mismatch: bool
) -> None:
    """Block accidental writes through a connector that does not match NS detection."""
    if not provider_match_target:
        return
    selected_provider = _canonical_dns_provider_id(requested_provider)
    if selected_provider == provider_match_target:
        return
    if allow_mismatch:
        return
    raise DNSProviderWriteError(
        "Selected DNS provider does not match the detected provider for this domain. "
        "Preview with the recommended provider or explicitly allow a provider mismatch."
    )


def _dns_provider_mismatch_audit_details(
    *,
    requested_provider: str,
    recommended_provider: Optional[str],
    detected_provider: Optional[str],
    allow_mismatch: bool,
) -> Dict[str, Any]:
    """Return non-secret provider mismatch details for DNS write audit logs."""
    selected_provider = _canonical_dns_provider_id(requested_provider)
    provider_match_target = recommended_provider or detected_provider
    return {
        "detected_provider": detected_provider,
        "recommended_provider": recommended_provider,
        "provider_match_target": provider_match_target,
        "selected_provider": selected_provider,
        "provider_mismatch": bool(
            provider_match_target and selected_provider != provider_match_target
        ),
        "provider_mismatch_override": bool(
            provider_match_target and selected_provider != provider_match_target and allow_mismatch
        ),
    }


def _provider_mismatch_safety_note(
    *,
    requested_provider: str,
    recommended_provider: Optional[str],
    detected_provider: Optional[str],
    allow_mismatch: bool,
) -> Optional[str]:
    """Return a UI/API safety note for intentional provider mismatches."""
    details = _dns_provider_mismatch_audit_details(
        requested_provider=requested_provider,
        recommended_provider=recommended_provider,
        detected_provider=detected_provider,
        allow_mismatch=allow_mismatch,
    )
    if not details["provider_mismatch"]:
        return None
    if allow_mismatch:
        return "Provider mismatch override was explicitly requested for this DNS change."
    return "Selected provider does not match the detected provider for this domain."


def _dns_plan_provider_write_available(plan: Dict[str, Any]) -> bool:
    """Return whether a change plan is safe enough to preview through a provider."""
    return (
        plan.get("operation") in DNS_AUTOMATION_OPERATIONS
        and plan.get("record_type") in DNS_AUTOMATION_RECORD_TYPES
        and not plan.get("provider_value_required")
        and bool(plan.get("proposed_value"))
        and "<" not in str(plan.get("proposed_value") or "")
    )


def _dns_plan_safety_notes(plan: Dict[str, Any], *, provider_write_available: bool) -> List[str]:
    """Explain why a plan is apply-ready or intentionally manual-only."""
    notes: List[str] = []
    if provider_write_available:
        notes.append("Preview the provider mutation before applying this DNS change.")
        if plan.get("current_values"):
            notes.append("Existing provider values will be shown in the preview before approval.")
        return notes
    if plan.get("operation") not in DNS_AUTOMATION_OPERATIONS:
        notes.append("This operation is review-only and is not safe for automatic DNS writes.")
    if plan.get("record_type") not in DNS_AUTOMATION_RECORD_TYPES:
        notes.append("Only TXT and CNAME records are provider-write enabled right now.")
    if plan.get("provider_value_required"):
        notes.append("A provider-specific final value is required before automation is safe.")
    proposed_value = str(plan.get("proposed_value") or "")
    if not proposed_value:
        notes.append("No concrete target value is available for an automated write.")
    elif "<" in proposed_value:
        notes.append("Placeholder values must be replaced with provider-confirmed values first.")
    return notes or ["Manual review is required before this DNS change can be automated."]


def _dns_change_plan_safety_notes(
    *, recommended_provider: Optional[str], available_providers: List[str]
) -> List[str]:
    """Return response-level safety guidance for operator-controlled DNS writes."""
    notes = [
        "DNS writes are never automatic; every provider change requires explicit approval.",
        "Use preview first to confirm zone, record, old value, new value, and TTL.",
    ]
    if recommended_provider:
        notes.append(f"Recommended provider for this domain: {recommended_provider}.")
    elif not available_providers:
        notes.append("No ready DNS write provider is configured; use the manual steps.")
    else:
        notes.append(
            "Detected DNS provider does not match a ready write connector; "
            "choose a provider manually only if it manages this zone."
        )
    return notes


class DNSProviderCapabilityResponse(BaseModel):
    """DNS provider write capability metadata."""

    id: str
    name: str
    mode: str
    record_types: List[str]
    operations: List[str]
    credentials: str
    status: str
    import_available: bool = False
    tier: Optional[int] = None
    auth_models: List[str] = Field(default_factory=list)
    zone_import_status: Optional[str] = None
    record_read_status: Optional[str] = None
    record_write_status: Optional[str] = None
    dry_run_supported: bool = False
    verification_supported: bool = False
    rollback_supported: bool = False
    minimum_permissions: List[str] = Field(default_factory=list)
    setup_hint: Optional[str] = None
    docs_url: Optional[str] = None
    credentials_configured: bool = False
    connection_status: str = "not_configured"
    connection_hint: str = "Configure provider credentials before discovery or repair."


class DNSProviderCapabilitiesResponse(BaseModel):
    """Supported DNS provider write capabilities."""

    providers: List[DNSProviderCapabilityResponse]


class DNSWriteApplyRequest(BaseModel):
    """Request to preview or apply one DNS change plan."""

    plan_id: str
    provider: str = "cloudflare"
    confirm: bool = False
    dry_run: bool = True
    allow_provider_mismatch: bool = False
    value: Optional[str] = None
    ttl: int = Field(default=1, ge=1, le=86400)


class DNSWriteMutationResponse(BaseModel):
    """Concrete provider mutation derived from a DNS change plan."""

    operation: str
    record_type: str
    name: str
    content: str
    ttl: int
    provider: str
    zone_id: Optional[str] = None
    zone_name: Optional[str] = None
    record_id: Optional[str] = None
    current_values: List[str] = Field(default_factory=list)
    applicable: bool
    blocked_reason: Optional[str] = None


class DNSWriteVerificationResponse(BaseModel):
    """Provider-side verification evidence after a DNS apply."""

    status: str
    verified: bool
    checked_values: List[str] = Field(default_factory=list)
    message: str = ""


class DNSWriteRollbackResponse(BaseModel):
    """Human-reviewed rollback guidance for a provider DNS mutation."""

    summary: str
    steps: List[str] = Field(default_factory=list)
    previous_values: List[str] = Field(default_factory=list)
    record_type: str
    name: str
    provider: str
    requires_manual_review: bool = True


class DNSWriteResultResponse(BaseModel):
    """DNS write preview/apply response."""

    provider: str
    dry_run: bool
    applied: bool
    mutation: DNSWriteMutationResponse
    provider_result: Optional[Dict[str, Any]] = None
    changes: List[Dict[str, Any]] = Field(default_factory=list)
    verification: DNSWriteVerificationResponse
    rollback: DNSWriteRollbackResponse


class DNSGuidanceResponse(BaseModel):
    """Typed DNS lint and setup guidance for one domain."""

    domain: str
    status: str
    findings: List[DNSLintFindingResponse]
    target_records: List[DNSGuidanceRecordResponse]
    dns_provider: Optional[Dict[str, Any]] = None
    change_plans: List[DNSChangePlanItemResponse] = Field(default_factory=list)


class DNSBulkGuidanceItem(BaseModel):
    """Bulk DNS lint summary for one domain."""

    domain: str
    status: str
    finding_count: int
    highest_severity: str
    findings: List[DNSLintFindingResponse]
    target_records: List[DNSGuidanceRecordResponse]


class DNSBulkGuidanceResponse(BaseModel):
    """Bulk DNS lint response for monitored domains."""

    domains: List[DNSBulkGuidanceItem]


class DNSHealthEvidence(BaseModel):
    """Evidence backing a DNS health recommendation."""

    label: str
    value: str
    href: str


class DNSHealthCheck(BaseModel):
    """Single DNS health check result."""

    key: str
    label: str
    status: str
    message: str
    evidence: List[DNSHealthEvidence] = Field(default_factory=list)


class DNSHealthRecommendation(BaseModel):
    """Actionable DNS or enforcement recommendation."""

    type: str
    severity: str
    title: str
    detail: str
    action: str
    evidence: List[DNSHealthEvidence] = Field(default_factory=list)


class DNSHealthResponse(BaseModel):
    """Evidence-linked DNS health summary for a domain."""

    status: str
    policy: str
    compliance_rate: float
    total_emails: int
    failed_emails: int
    dns_lookup_status: str = "ok"
    dns_lookup_error: Optional[str] = None
    checks: List[DNSHealthCheck]
    recommendations: List[DNSHealthRecommendation]


class PostureCoverageItem(BaseModel):
    """Operator-facing coverage state for one posture area."""

    key: str
    label: str
    status: str
    message: str
    evidence_count: int
    href: str


class PostureChangeSummary(BaseModel):
    """Concise summary of observed posture drift."""

    title: str
    detail: str
    severity: str
    observed_at: Optional[str] = None
    evidence: List[DNSHealthEvidence] = Field(default_factory=list)


class OperatorPlaybook(BaseModel):
    """Short remediation playbook for a posture recommendation."""

    key: str
    title: str
    summary: str
    steps: List[str]
    evidence: List[DNSHealthEvidence] = Field(default_factory=list)


class DomainHealthGrade(BaseModel):
    """Dashboard-consistent health grade for a single monitored domain."""

    domain: str
    score: int
    grade: str
    status: str
    factors: Dict[str, float] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)


class PostureDashboardResponse(BaseModel):
    """Evidence-first posture dashboard response for a domain."""

    domain: str
    status: str
    score: int
    health: DomainHealthGrade
    summary: str
    coverage: List[PostureCoverageItem]
    recommendations: List[DNSHealthRecommendation]
    changes: List[PostureChangeSummary]
    playbooks: List[OperatorPlaybook]


class RemediationAutomation(BaseModel):
    """Automation eligibility for one remediation item."""

    eligible: bool = False
    requires_approval: bool = True
    provider: Optional[str] = None
    plan_id: Optional[str] = None
    apply_endpoint: Optional[str] = None
    reason: str = ""


class RemediationEvidence(BaseModel):
    """Evidence attached to one remediation queue item."""

    label: str
    value: str


class RemediationGuidancePath(BaseModel):
    """Operator-facing path for completing a remediation item."""

    key: str
    label: str
    summary: str
    owner: str


class RemediationActionPlan(BaseModel):
    """Operator-facing action plan for one remediation queue item."""

    owner: str
    diagnosis: str
    prerequisites: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    guidance_paths: List[RemediationGuidancePath] = Field(default_factory=list)
    completion_criteria: str
    automation_path: str


class RemediationNotification(BaseModel):
    """Read-only notification routing metadata for one remediation item."""

    state: str
    event: str
    channel: str
    dedupe_key: str
    reason: str
    next_transition: str
    payload_preview: Dict[str, Any] = Field(default_factory=dict)
    history: List[Dict[str, Any]] = Field(default_factory=list)
    dispatch: Dict[str, Any] = Field(default_factory=dict)


class RemediationQueueItem(BaseModel):
    """One prioritized operator action for a domain."""

    id: str
    source: str
    state: str
    severity: str
    confidence: str
    title: str
    detail: str
    next_steps: List[str] = Field(default_factory=list)
    evidence: List[RemediationEvidence] = Field(default_factory=list)
    blast_radius: str
    prerequisites: List[str] = Field(default_factory=list)
    expected_health_score_impact: str
    action_plan: RemediationActionPlan
    automation: RemediationAutomation
    notification: RemediationNotification


class RemediationQueueResponse(BaseModel):
    """Prioritized remediation queue for a domain."""

    domain: str
    status: str
    summary: Dict[str, int]
    items: List[RemediationQueueItem]


class RemediationNotificationAuditRequest(BaseModel):
    """Operator lifecycle marker for one remediation notification preview."""

    item_id: str
    lifecycle_state: str
    event: Optional[str] = None
    dedupe_key: Optional[str] = None
    note: Optional[str] = None


class RemediationNotificationAuditResponse(BaseModel):
    """Persisted audit marker for one remediation notification lifecycle step."""

    domain: str
    item_id: str
    event: str
    dedupe_key: str
    lifecycle_state: str
    audit: Dict[str, Any]


class RemediationNotificationDispatchRequest(BaseModel):
    """Explicit operator request to enqueue one remediation notification."""

    item_id: str
    confirm: bool = False
    event: Optional[str] = None
    dedupe_key: Optional[str] = None
    note: Optional[str] = None


class RemediationNotificationDispatchResponse(BaseModel):
    """Persisted webhook delivery state for one approved remediation dispatch."""

    domain: str
    item_id: str
    event: str
    dedupe_key: str
    delivery_enqueued: bool
    delivery_count: int
    deliveries: List[Dict[str, Any]] = Field(default_factory=list)
    dispatch: Dict[str, Any] = Field(default_factory=dict)
    audit: Dict[str, Any]


class HealthScoreHistoryPoint(BaseModel):
    """One persisted health score history point."""

    date: str
    score: int
    grade: str
    status: str
    policy: Optional[str] = None
    compliance_rate: int
    total_emails: int
    failed_emails: int
    report_count: int
    dns_posture_score: int
    policy_strength_score: int
    report_confidence_score: int
    top_actions: List[Dict[str, Any]] = Field(default_factory=list)


class HealthScoreHistoryResponse(BaseModel):
    """Score history and trend metadata for one domain."""

    domain: str
    points: List[HealthScoreHistoryPoint]
    current_score: Optional[int] = None
    previous_score: Optional[int] = None
    score_delta: Optional[int] = None
    current_grade: Optional[str] = None
    previous_grade: Optional[str] = None
    top_drivers: List[Dict[str, Any]] = Field(default_factory=list)


class WorkspaceHealthScoreHistoryPoint(HealthScoreHistoryPoint):
    """One workspace-level health score history point."""

    domain_count: int


class WorkspaceHealthScoreHistoryResponse(BaseModel):
    """Score history and trend metadata for the selected workspace."""

    scope: str
    points: List[WorkspaceHealthScoreHistoryPoint]
    current_score: Optional[int] = None
    previous_score: Optional[int] = None
    score_delta: Optional[int] = None
    current_grade: Optional[str] = None
    previous_grade: Optional[str] = None
    top_drivers: List[Dict[str, Any]] = Field(default_factory=list)


class MTAStsResponse(BaseModel):
    """MTA-STS posture result for a domain."""

    status: str
    dns_record: Optional[str] = None
    policy_url: Optional[str] = None
    policy_text: Optional[str] = None
    mode: Optional[str] = None
    max_age: Optional[int] = None
    mx: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    cached: bool = False
    checked_at: Optional[str] = None


class BIMIResponse(BaseModel):
    """BIMI posture result for a domain."""

    status: str
    selector: str = "default"
    query_name: str
    dns_record: Optional[str] = None
    logo_url: Optional[str] = None
    certificate_url: Optional[str] = None
    evidence_url: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    cached: bool = False
    checked_at: Optional[str] = None


class TLSARecordResponse(BaseModel):
    """One observed TLSA record for an MX host."""

    query_name: str
    mx_host: str
    record: str
    certificate_usage: Optional[int] = None
    selector: Optional[int] = None
    matching_type: Optional[int] = None
    association_data: Optional[str] = None
    valid: bool = False
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class TLSASuggestionResponse(BaseModel):
    """One TLSA record suggestion derived from a live MX certificate."""

    query_name: str
    mx_host: str
    record: str = ""
    certificate_usage: int = 3
    selector: int = 1
    matching_type: int = 1
    association_data: str = ""
    status: str = "unavailable"
    source: str = "smtp-starttls-live-certificate"
    error: Optional[str] = None


class DANEResponse(BaseModel):
    """DANE/TLSA posture result for a domain."""

    status: str
    port: int = 25
    mx_hosts: List[str] = Field(default_factory=list)
    records: List[TLSARecordResponse] = Field(default_factory=list)
    suggested_records: List[TLSASuggestionResponse] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    cached: bool = False
    checked_at: Optional[str] = None


class CloudflareZoneResponse(BaseModel):
    """Cloudflare zone available for import."""

    id: str
    name: str
    status: Optional[str] = None
    account_name: Optional[str] = None
    imported: bool = False


class CloudflareImportRequest(BaseModel):
    """Optional list of Cloudflare domains to import."""

    domains: Optional[List[str]] = None


class CloudflareImportResponse(BaseModel):
    """Cloudflare domain import summary."""

    imported: List[str]
    existing: List[str]
    skipped: List[str]
    total_discovered: int


class CloudflareOAuthAuthorizeResponse(BaseModel):
    """Cloudflare OAuth authorization details."""

    authorization_url: str
    redirect_uri: str
    scopes: str
    scope_profile: str


class CloudflareOAuthStatusResponse(BaseModel):
    """Cloudflare connector status for the settings UI."""

    oauth_configured: bool
    connected: bool
    auth_mode: Optional[str] = None
    scopes: Optional[str] = None
    scope_profile: str = "read_only"
    scope_profiles: List[Dict[str, Any]] = Field(default_factory=list)
    connected_at: Optional[str] = None


class CloudflareOwnershipVerifyResponse(BaseModel):
    """Cloudflare-backed domain ownership verification result."""

    domain: str
    verified: bool
    provider: str = "cloudflare"
    zone_id: Optional[str] = None
    zone_name: Optional[str] = None
    zone_status: Optional[str] = None
    account_name: Optional[str] = None
    proof_reason: str
    next_steps: List[str] = Field(default_factory=list)


class DNSProviderImportZoneResponse(BaseModel):
    """DNS provider zone that can be imported as a monitored domain."""

    provider: str
    provider_name: str
    zone_id: str
    domain: str
    status: Optional[str] = None
    account_name: Optional[str] = None
    imported: bool = False
    importable: bool = True
    source: str = "dns_zone"
    next_action: str


class DNSProviderImportPreviewResponse(BaseModel):
    """Read-only DNS provider domain import preview."""

    provider: str
    provider_name: str
    zones: List[DNSProviderImportZoneResponse]
    total_discovered: int
    importable_count: int


class DNSProviderImportRequest(BaseModel):
    """Optional DNS provider domains to import after preview."""

    domains: Optional[List[str]] = None


class DNSProviderImportResponse(BaseModel):
    """DNS provider domain import summary."""

    provider: str
    provider_name: str
    imported: List[str]
    existing: List[str]
    skipped: List[str]
    total_discovered: int


class RequiredDNSRecordResponse(BaseModel):
    """DNS record requested by an external service."""

    record_type: str
    name: str
    value: str
    purpose: str


class MailServiceImportDomainResponse(BaseModel):
    """Mail service sender domain that can be imported as a monitored domain."""

    provider: str
    provider_name: str
    external_id: str
    domain: str
    verification_state: str
    imported: bool = False
    importable: bool = True
    required_dns_records: List[RequiredDNSRecordResponse] = Field(default_factory=list)
    source: str = "mail_service_sender"
    next_action: str


class MailServiceImportPreviewResponse(BaseModel):
    """Read-only mail service sender-domain import preview."""

    provider: str
    provider_name: str
    domains: List[MailServiceImportDomainResponse]
    total_discovered: int
    importable_count: int


class MailServiceImportRequest(BaseModel):
    """Optional sender domains to import after preview."""

    domains: Optional[List[str]] = None


class MailServiceImportResponse(BaseModel):
    """Mail service sender-domain import summary."""

    provider: str
    provider_name: str
    imported: List[str]
    existing: List[str]
    skipped: List[str]
    total_discovered: int


class CloudflareDNSAnalysisResponse(BaseModel):
    """Cloudflare-managed DNS analysis and recent change details."""

    zone: Dict[str, Any]
    records: List[Dict[str, Any]]
    checks: Dict[str, Any]
    suggestions: List[Dict[str, str]]
    changes: List[Dict[str, Any]]
    history: List[Dict[str, Any]]


class DNSChangeHistoryResponse(BaseModel):
    """Recent DNS record changes for a domain."""

    history: List[Dict[str, Any]]


class TimelinePoint(BaseModel):
    """Data point for compliance timeline"""

    date: str
    total: int
    volume: int
    passed: int
    failed: int
    compliance_rate: float
    failure_rate: float


class ReportEntry(BaseModel):
    """Summary of a DMARC report"""

    id: str
    org_name: str
    begin_date: int
    end_date: int
    total_emails: int
    pass_rate: float
    policy: str


class SourceRecommendation(BaseModel):
    """Actionable recommendation for a sending source"""

    type: str
    severity: str
    title: str
    detail: str
    action: str


class SourceReputationEvidence(BaseModel):
    """Evidence used for sender IP reputation scoring."""

    label: str
    value: str
    source: str


class SourceReputationResponse(BaseModel):
    """Passive reputation posture for one observed sending IP."""

    ip: str
    status: str
    status_label: str
    status_detail: str
    risk_score: int
    summary: str
    evidence_summary: str
    feed_status: str
    feed_summary: str
    listings: List[str] = Field(default_factory=list)
    evidence: List[SourceReputationEvidence] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    checked_at: str


class SenderIdentity(BaseModel):
    """Recognized sender identity for a sending source."""

    id: str
    name: str
    provider: Optional[str] = None
    category: str
    status: str
    confidence: int
    reason: str
    evidence: List[str] = Field(default_factory=list)
    remediation_hint: str
    docs_url: Optional[str] = None


class SourceGeo(BaseModel):
    """Coarse source geography from report metadata or inferred demo intelligence."""

    country: str
    country_code: str
    region: str
    asn: Optional[str] = None
    network: Optional[str] = None
    bgp_prefix: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    registry: Optional[str] = None
    allocated: Optional[str] = None
    organization: Optional[str] = None
    domain: Optional[str] = None
    cloudflare_location: Optional[str] = None
    cloudflare_asn_name: Optional[str] = None
    cloudflare_asn_org_name: Optional[str] = None
    radar_url: Optional[str] = None
    network_source: Optional[str] = None
    network_checked_at: Optional[str] = None
    network_error: Optional[str] = None
    source: str


class SourceAnomaly(BaseModel):
    """A notable sender, geography, volume, or alignment change."""

    type: str
    severity: str
    title: str
    domain: str
    source_ip: Optional[str] = None
    region: Optional[str] = None
    message_count: int = 0
    failed_count: int = 0
    detail: str
    action: str


class SourceRegionSummary(BaseModel):
    """Aggregate message volume for a coarse source region."""

    region: str
    country_codes: List[str] = Field(default_factory=list)
    message_count: int = 0
    source_count: int = 0
    failed_count: int = 0
    failure_rate: float = 0.0
    networks: List[str] = Field(default_factory=list)


class SourceVolumeHistoryEntry(BaseModel):
    """Per-day message volume for a sending source."""

    date: str
    count: int = 0
    passed: int = 0
    failed: int = 0


class SourceEntry(BaseModel):
    """Summary of a sending source"""

    ip: str
    count: int
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    active_days: int = 0
    report_count: int = 0
    volume_history: List[SourceVolumeHistoryEntry] = Field(default_factory=list)
    spf: str
    dkim: str
    dmarc: str
    disposition: str
    spf_pass_count: int = 0
    spf_fail_count: int = 0
    dkim_pass_count: int = 0
    dkim_fail_count: int = 0
    dmarc_pass_count: int = 0
    dmarc_fail_count: int = 0
    disposition_counts: Dict[str, int] = Field(default_factory=dict)
    hostname: Optional[str] = None
    sender: SenderIdentity
    geo: SourceGeo
    anomalies: List[SourceAnomaly] = Field(default_factory=list)
    reputation: Optional[SourceReputationResponse] = None
    spf_fix_hint: Optional[str] = None
    recommendations: List[SourceRecommendation] = Field(default_factory=list)


class DomainReportsResponse(BaseModel):
    """Domain reports with compliance timeline"""

    reports: List[ReportEntry]
    compliance_timeline: List[TimelinePoint]


class DomainSourcesResponse(BaseModel):
    """Domain sending sources"""

    sources: List[SourceEntry]


class SourceIntelligenceResponse(BaseModel):
    """Domain-level source intelligence summary."""

    domain: str
    period_days: int
    recent_days: int = 0
    regions: List[SourceRegionSummary] = Field(default_factory=list)
    anomalies: List[SourceAnomaly] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)


class DomainSourceReputationResponse(BaseModel):
    """Domain-level sender IP reputation response."""

    domain: str
    status: str
    checked_at: str
    sources: List[SourceReputationResponse] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)
    feeds: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    cached: bool = False


class DomainSummaryResponse(BaseModel):
    """Domain summary for dashboard"""

    total_domains: int
    total_emails: int
    overall_pass_rate: float
    reports_processed: int
    domains: List[Dict[str, Any]]
    health_summary: Dict[str, Any] = Field(default_factory=dict)


REMEDIATION_DNS_ACTION_TYPES = {
    "missing_dmarc",
    "missing_spf",
    "missing_dkim",
    "dmarc_lint",
}
REMEDIATION_REPUTATION_ACTION_TYPES = {
    "source_reputation_listed",
    "source_reputation_review",
}
REMEDIATION_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _remediation_loop_state(action: Dict[str, Any]) -> str:
    """Classify current health actions into dashboard remediation buckets."""
    action_type = str(action.get("type") or "")
    severity = str(action.get("severity") or "info")
    if action_type in REMEDIATION_DNS_ACTION_TYPES and severity in {"critical", "high"}:
        return "needs_approval"
    if action_type in {"low_compliance", *REMEDIATION_REPUTATION_ACTION_TYPES}:
        return "investigate"
    return "manual_action"


def _remediation_loop_context(state: str, action: Dict[str, Any]) -> Dict[str, str]:
    """Return operator-facing context for a dashboard remediation bucket."""
    action_type = str(action.get("type") or "")
    if state == "needs_approval":
        return {
            "state_label": "Needs approval",
            "owner": "Domain DNS operator",
            "automation_path": "provider_preview",
            "completion_criteria": "DNS change is previewed, approved, applied, and verified.",
            "why": "A high-impact DNS or policy finding can move through a controlled approval path.",
        }
    if state == "investigate":
        return {
            "state_label": "Investigate",
            "owner": (
                "Mail operations owner"
                if action_type not in REMEDIATION_REPUTATION_ACTION_TYPES
                else "Deliverability owner"
            ),
            "automation_path": "investigate",
            "completion_criteria": "Sender legitimacy is confirmed before any DNS or policy change.",
            "why": "This finding needs evidence review before DMARQ can suggest a safe repair.",
        }
    return {
        "state_label": "Manual action",
        "owner": "Mail or DNS operator",
        "automation_path": "manual",
        "completion_criteria": "The operator completes the recommended action and refreshes evidence.",
        "why": "This item is not safe or specific enough for one-click repair yet.",
    }


def _dashboard_remediation_item(
    domain_name: str,
    action: Dict[str, Any],
    *,
    include_detail: bool = True,
) -> Dict[str, Any]:
    """Convert one health action into a dashboard remediation-loop item."""
    state = _remediation_loop_state(action)
    context = _remediation_loop_context(state, action)
    item = {
        "domain": domain_name,
        "state": state,
        "severity": str(action.get("severity") or "info"),
        "title": str(action.get("title") or "Review remediation item"),
        "next_step": str(action.get("next_step") or "Review the domain evidence."),
        "score_impact": int(action.get("score_impact") or 0),
        "type": str(action.get("type") or "health_action"),
        **context,
    }
    if include_detail:
        item["detail"] = str(action.get("detail") or "")
    return item


def _build_dashboard_remediation_loop(
    domains: List[Dict[str, Any]],
    remediation_activity: Dict[str, Any],
) -> Dict[str, Any]:
    """Return a visible remediation-loop summary for the workspace dashboard."""
    counters = {
        "fixed": int((remediation_activity.get("summary") or {}).get("resolved") or 0),
        "needs_approval": 0,
        "manual_action": 0,
        "investigate": 0,
    }
    items: List[Dict[str, Any]] = []

    for domain in domains:
        domain_name = str(domain.get("domain_name") or domain.get("id") or "")
        health = domain.get("health") or {}
        for action in health.get("actions") or []:
            state = _remediation_loop_state(action)
            counters[state] += 1
            items.append(_dashboard_remediation_item(domain_name, action))

    items.sort(
        key=lambda item: (
            item["state"] != "needs_approval",
            -REMEDIATION_SEVERITY_RANK.get(str(item.get("severity") or "info"), 0),
            -int(item.get("score_impact") or 0),
            str(item.get("domain") or ""),
        )
    )
    total_open = counters["needs_approval"] + counters["manual_action"] + counters["investigate"]
    return {
        **counters,
        "total_open": total_open,
        "dispatch_enqueued": int(
            (remediation_activity.get("summary") or {}).get("dispatch_enqueued") or 0
        ),
        "operator_follow_up": int(
            (remediation_activity.get("summary") or {}).get("needs_operator_follow_up") or 0
        ),
        "status": "clear" if total_open == 0 else "needs_attention",
        "items": items[:5],
    }


def _domain_remediation_workload(domain: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize current remediation work for one dashboard domain row."""
    counters = {
        "needs_approval": 0,
        "manual_action": 0,
        "investigate": 0,
    }
    items: List[Dict[str, Any]] = []
    domain_name = str(domain.get("domain_name") or domain.get("id") or "")
    for action in (domain.get("health") or {}).get("actions") or []:
        state = _remediation_loop_state(action)
        counters[state] += 1
        items.append(_dashboard_remediation_item(domain_name, action, include_detail=False))

    items.sort(
        key=lambda item: (
            item["state"] != "needs_approval",
            -REMEDIATION_SEVERITY_RANK.get(str(item.get("severity") or "info"), 0),
            -int(item.get("score_impact") or 0),
        )
    )
    total_open = counters["needs_approval"] + counters["manual_action"] + counters["investigate"]
    return {
        **counters,
        "total_open": total_open,
        "status": "clear" if total_open == 0 else "needs_attention",
        "primary": items[0] if items else None,
    }


class SelectorRequest(BaseModel):
    """Request body for adding a DKIM selector"""

    selector: str = Field(..., min_length=1, description="DKIM selector name")


def _get_selectors_from_reports(store: "ReportStore", domain: str) -> List[str]:
    """Extract DKIM selectors seen in stored DMARC reports for *domain*.

    DMARC aggregate report records include DKIM auth results that carry the
    selector used by the sending server.  Collecting these gives us a set of
    real-world selectors to verify against live DNS, in addition to any
    manually configured selectors.
    """
    selectors: List[str] = []
    for report in store.get_domain_reports(domain):
        for record in report.get("records", []):
            dkim_entries = record.get("dkim") or []
            for dkim_entry in dkim_entries:
                if not isinstance(dkim_entry, dict):
                    continue
                sel = dkim_entry.get("selector", "").strip()
                if sel and sel not in selectors:
                    selectors.append(sel)
    return selectors


def _normalize_domain_selectors(selectors: Optional[List[str]]) -> List[str]:
    """Normalize user-supplied DKIM selectors while preserving order."""
    normalized: List[str] = []
    seen = set()
    for selector in selectors or []:
        value = selector.strip() if selector else ""
        if value and value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized


def _domain_update_fields(payload: BaseModel) -> set[str]:
    """Return fields explicitly present in a Pydantic v1/v2 payload."""
    fields = getattr(payload, "model_fields_set", None)
    if fields is None:
        fields = getattr(payload, "__fields_set__", set())
    return set(fields)


def _ownership_record_name(domain: str) -> str:
    return f"_dmarq-verify.{domain}"


def _ownership_record_value(token: str) -> str:
    return f"dmarq-verify={token}"


def _ensure_domain_verification_token(db: Session, domain: Domain) -> str:
    locked_domain = db.query(Domain).filter(Domain.id == domain.id).with_for_update().one_or_none()
    if locked_domain is None:
        db.refresh(domain)
        locked_domain = domain

    token = str(locked_domain.verification_token or "").strip()
    if token:
        return token
    token = secrets.token_urlsafe(24)
    locked_domain.verification_token = token
    db.commit()
    db.refresh(locked_domain)
    db.refresh(domain)
    return str(locked_domain.verification_token or "").strip()


def _domain_ownership_response(domain: Domain, token: str) -> DomainOwnershipResponse:
    return DomainOwnershipResponse(
        domain=domain.name,
        verified=bool(domain.verified),
        proof_record_name=_ownership_record_name(domain.name),
        proof_record_value=_ownership_record_value(token),
        proof_reason=(
            "Report mailbox access is enough to ingest and view DMARC reports. "
            "DNS ownership proof is required before DMARQ treats the domain as verified "
            "for DNS writes, one-click repair, and trusted ownership workflows."
        ),
        next_steps=[
            "Publish the TXT proof record in the domain's DNS zone.",
            "Wait for DNS propagation, then use Check ownership on this page.",
            "Connect the DNS provider when you want DMARQ to preview or apply approved repairs.",
        ],
    )


def _get_domain_selectors_from_db(db: Session, domain_name: str) -> List[str]:
    """Return the manually configured DKIM selectors for *domain_name* from the DB."""
    domain_db = db.query(Domain).filter(Domain.name == domain_name).first()
    if domain_db and domain_db.dkim_selectors:
        return [s.strip() for s in domain_db.dkim_selectors.split(",") if s.strip()]
    return []


def _get_domain_selectors_map_from_db(db: Session, domain_names: List[str]) -> Dict[str, List[str]]:
    """Return manually configured DKIM selectors for all requested domains."""
    if not domain_names:
        return {}

    unique_names = list(dict.fromkeys(domain_names))
    selectors_by_domain: Dict[str, List[str]] = {}
    for index in range(0, len(unique_names), DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE):
        chunk = unique_names[index : index + DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE]
        rows = db.query(Domain.name, Domain.dkim_selectors).filter(Domain.name.in_(chunk)).all()
        for name, selectors in rows:
            selectors_by_domain[name] = _normalize_domain_selectors((selectors or "").split(","))
    return selectors_by_domain


def _selectors_from_dkim_auth_details(raw_details: str) -> List[str]:
    try:
        details = json.loads(raw_details or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(details, list):
        return []
    selectors: List[str] = []
    for detail in details:
        if not isinstance(detail, dict):
            continue
        selector = str(detail.get("selector") or "").strip()
        if selector and selector not in selectors:
            selectors.append(selector)
    return selectors


def _get_report_selectors_map_from_db(
    db: Session,
    domain_names: List[str],
    *,
    workspace_id: Optional[int] = None,
) -> Dict[str, List[str]]:
    """Return DKIM selectors observed in persisted report records."""
    if not domain_names:
        return {}

    unique_names = list(dict.fromkeys(domain_names))
    selectors_by_domain: Dict[str, List[str]] = {}
    for index in range(0, len(unique_names), DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE):
        chunk = unique_names[index : index + DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE]
        query = (
            db.query(Domain.name, ReportRecord.dkim_auth_details)
            .join(DMARCReport, DMARCReport.domain_id == Domain.id)
            .join(ReportRecord, ReportRecord.report_id == DMARCReport.id)
            .filter(Domain.name.in_(chunk))
            .filter(ReportRecord.dkim_auth_details.isnot(None))
        )
        if workspace_id is not None:
            query = query.filter(Domain.workspace_id == workspace_id)
        for domain_name, raw_details in query.all():
            domain_selectors = selectors_by_domain.setdefault(domain_name, [])
            for selector in _selectors_from_dkim_auth_details(raw_details):
                if selector and selector not in domain_selectors:
                    domain_selectors.append(selector)
    return selectors_by_domain


def _policy_enforcement_suggestions(
    dmarc_policy: Optional[str],
    summary: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Suggest policy enforcement when report history supports moving beyond monitoring."""
    if dmarc_policy != "none":
        return []
    total_count = int(summary.get("total_count", 0) or 0)
    compliance_rate = float(summary.get("compliance_rate", 0.0) or 0.0)
    if total_count >= 100 and compliance_rate >= 98.0:
        return [
            {
                "type": "policy_enforcement_ready",
                "severity": "info",
                "message": (
                    "Recent reports show very high DMARC compliance. Consider moving from "
                    "p=none to p=quarantine with a limited pct value."
                ),
            }
        ]
    if total_count >= 100 and compliance_rate >= 90.0:
        return [
            {
                "type": "policy_enforcement_review",
                "severity": "info",
                "message": (
                    "DMARC compliance is trending high. Review remaining failures before "
                    "moving the domain policy beyond p=none."
                ),
            }
        ]
    return []


def _domain_names_for_summary(
    db: Session,
    store: ReportStore,
    workspace=None,
    include_unscoped_report_domains: bool = True,
) -> List[str]:
    report_domains = store.get_domains()
    stored_query = db.query(Domain.name).filter(Domain.active == True)  # noqa: E712
    if workspace is not None:
        stored_query = stored_query.filter(Domain.workspace_id == workspace.id)
    stored_domains = [name for (name,) in stored_query.order_by(Domain.name).all()]

    if workspace is None:
        scoped_report_domains = report_domains
    else:
        stored_scope = {
            name: workspace_id
            for name, workspace_id in db.query(Domain.name, Domain.workspace_id)
            .filter(Domain.name.in_(report_domains))
            .all()
        }
        scoped_report_domains = [
            name
            for name in report_domains
            if stored_scope.get(name) == workspace.id
            or (include_unscoped_report_domains and name not in stored_scope)
        ]
    return list(dict.fromkeys(stored_domains + scoped_report_domains))


def _domain_exists(db: Session, store: ReportStore, domain_name: str, workspace=None) -> bool:
    row = db.query(Domain.id, Domain.workspace_id).filter(Domain.name == domain_name).first()
    if row:
        return workspace is None or row.workspace_id == workspace.id
    return domain_name in store.get_domains()


def _require_verified_domain_for_dns_write(
    db: Session, workspace: Workspace, domain_name: str
) -> None:
    """Require explicit DNS ownership proof before mutating provider DNS."""
    domain = workspace_domain_query(db, workspace).filter(Domain.name == domain_name).first()
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Add this domain to the workspace and verify ownership before applying live "
                "DNS changes. You can still preview the proposed DNS repair first."
            ),
        )
    if not domain.verified:
        proof_name = _ownership_record_name(domain.name)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Verify domain ownership before applying live DNS changes. Publish the "
                f"{proof_name} TXT proof shown on the domain ownership page, use Check "
                "ownership after DNS propagation, then retry this repair. DNS previews remain "
                "available before verification."
            ),
        )


def _stored_domain_exists(db: Session, domain_id: str) -> bool:
    query = db.query(Domain.id)
    if domain_id.isdigit() and query.filter(Domain.id == int(domain_id)).first() is not None:
        return True
    return query.filter(Domain.name == domain_id).first() is not None


def _allows_legacy_report_only_fallback(db: Session) -> bool:
    return db.query(Workspace.id).limit(2).count() <= 1


def _resolve_domain_name_for_read(
    db: Session,
    store: ReportStore,
    domain_id: str,
    workspace,
) -> str:
    """Resolve a domain path segment to the canonical workspace domain name."""
    domain = workspace_domain_query(db, workspace).filter(Domain.name == domain_id).first()
    if domain is None and domain_id.isdigit():
        domain = workspace_domain_query(db, workspace).filter(Domain.id == int(domain_id)).first()
    if domain is not None:
        return str(domain.name)
    if _domain_exists(db, store, domain_id, workspace):
        return domain_id
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Domain not found",
    )


def _single_domain_report_store_for_read(
    db: Session,
    domain_id: str,
    workspace: Workspace,
) -> tuple[str, ReportStore]:
    """Return a ReportStore containing only the requested domain's persisted reports."""
    store = ReportStore()
    domain = workspace_domain_query(db, workspace).filter(Domain.name == domain_id).first()
    if domain is None and domain_id.isdigit():
        domain = workspace_domain_query(db, workspace).filter(Domain.id == int(domain_id)).first()
    if domain is not None and not get_settings().DEMO_MODE:
        domain_name = str(domain.name)
        hydrate_domain_report_store_from_db(
            db,
            store,
            domain_name,
            workspace_id=workspace.id,
        )
        return domain_name, store

    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    try:
        domain_name = _resolve_domain_name_for_read(db, store, domain_id, workspace)
    except HTTPException as exc:
        if (
            exc.status_code != status.HTTP_404_NOT_FOUND
            or _stored_domain_exists(db, domain_id)
            or not _allows_legacy_report_only_fallback(db)
        ):
            raise
        legacy_store = ReportStore.get_instance()
        if _domain_exists(db, legacy_store, domain_id, workspace):
            domain_name = _resolve_domain_name_for_read(db, legacy_store, domain_id, workspace)
            return domain_name, legacy_store
        hydrate_report_store_from_db(db, store)
        domain_name = _resolve_domain_name_for_read(db, store, domain_id, workspace)
    return domain_name, store


def _record_evidence(
    label: str, value: Optional[str], href: str = "#dns-records"
) -> DNSHealthEvidence:
    return DNSHealthEvidence(label=label, value=value or "Not found", href=href)


def _summary_evidence(
    label: str, value: object, href: str = "#compliance-chart"
) -> DNSHealthEvidence:
    return DNSHealthEvidence(label=label, value=str(value), href=href)


def _dns_check(
    key: str,
    label: str,
    present: bool,
    present_message: str,
    missing_message: str,
    evidence: List[DNSHealthEvidence],
) -> DNSHealthCheck:
    return DNSHealthCheck(
        key=key,
        label=label,
        status="pass" if present else "fail",
        message=present_message if present else missing_message,
        evidence=evidence,
    )


def _enforcement_recommendation(
    policy: str,
    summary: Dict[str, Any],
) -> DNSHealthRecommendation:
    total = int(summary.get("total_count", 0) or 0)
    failed = int(summary.get("failed_count", 0) or 0)
    compliance = float(summary.get("compliance_rate", 0.0) or 0.0)
    evidence = [
        _summary_evidence("Policy", f"p={policy}", "#dns-records"),
        _summary_evidence("Total messages", total),
        _summary_evidence("Compliance", f"{compliance}%"),
        _summary_evidence("Failed messages", failed, "#sending-sources"),
    ]
    if policy != "none":
        return DNSHealthRecommendation(
            type="policy_already_enforced",
            severity="info",
            title="DMARC policy is already enforced",
            detail="This domain is already beyond monitoring mode.",
            action="Continue watching failure trends before tightening further.",
            evidence=evidence,
        )
    if total < 100:
        return DNSHealthRecommendation(
            type="policy_needs_more_data",
            severity="warning",
            title="Collect more report volume before enforcement",
            detail="DMARQ needs at least 100 observed messages before recommending quarantine.",
            action="Keep p=none until more aggregate reports arrive.",
            evidence=evidence,
        )
    if compliance >= 98.0 and failed <= max(2, int(total * 0.02)):
        return DNSHealthRecommendation(
            type="policy_enforcement_ready",
            severity="info",
            title="Ready to plan quarantine",
            detail="Recent report volume is high and failures are low enough to plan enforcement.",
            action="Move gradually: set p=quarantine with a low pct value, then watch failures.",
            evidence=evidence,
        )
    if compliance >= 90.0:
        return DNSHealthRecommendation(
            type="policy_enforcement_review",
            severity="warning",
            title="Close remaining failures before enforcement",
            detail="Compliance is improving, but failures still need review before policy changes.",
            action="Review failing sources and SPF/DKIM alignment before changing p=none.",
            evidence=evidence,
        )
    return DNSHealthRecommendation(
        type="policy_not_ready",
        severity="error",
        title="Not ready for enforcement",
        detail="Current DMARC compliance is too low for a safe policy change.",
        action="Fix unauthenticated or unknown senders before moving beyond p=none.",
        evidence=evidence,
    )


def _dmarc_tags(record: Optional[str]) -> Dict[str, str]:
    if not record:
        return {}
    return {
        part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip().lower()
        for part in record.split(";")
        if "=" in part
    }


def _bimi_dmarc_readiness(record: Optional[str]) -> tuple[bool, List[str], List[DNSHealthEvidence]]:
    tags = _dmarc_tags(record)
    policy = tags.get("p", "none")
    subdomain_policy = tags.get("sp")
    pct = tags.get("pct", "100")
    issues = []
    if policy not in {"quarantine", "reject"}:
        issues.append("DMARC policy must be p=quarantine or p=reject for BIMI.")
    if pct != "100":
        issues.append("DMARC pct must be 100 or omitted for BIMI.")
    if subdomain_policy and subdomain_policy not in {"quarantine", "reject"}:
        issues.append("DMARC subdomain policy must also be enforced when sp= is present.")
    evidence = [
        _record_evidence("DMARC TXT", record),
        _summary_evidence("Policy", f"p={policy}", "#dns-records"),
        _summary_evidence(
            "Subdomain policy", f"sp={subdomain_policy or 'inherit'}", "#dns-records"
        ),
        _summary_evidence("Percentage", f"pct={pct}", "#dns-records"),
    ]
    return not issues, issues, evidence


def _bimi_check(result: BIMIResult, dmarc_ready: bool) -> DNSHealthCheck:
    evidence = [
        _record_evidence("BIMI TXT", result.dns_record, "#bimi-posture"),
        _record_evidence("Logo URL", result.logo_url, "#bimi-posture"),
    ]
    if result.certificate_url:
        evidence.append(
            _record_evidence("Certificate URL", result.certificate_url, "#bimi-posture")
        )
    if result.status == "pass" and dmarc_ready:
        message = "BIMI record is published and DMARC is enforcement-ready."
    elif result.status == "pass":
        message = "BIMI record is published, but DMARC enforcement is not ready."
    else:
        message = result.errors[0] if result.errors else "BIMI posture needs attention."
    return DNSHealthCheck(
        key="bimi",
        label="BIMI",
        status="pass" if result.status == "pass" and dmarc_ready else "fail",
        message=message,
        evidence=evidence,
    )


def _bimi_recommendation(
    result: BIMIResult,
    dmarc_ready: bool,
    dmarc_issues: List[str],
    dmarc_evidence: List[DNSHealthEvidence],
) -> Optional[DNSHealthRecommendation]:
    bimi_evidence = _bimi_check(result, dmarc_ready).evidence
    if result.status == "pass" and dmarc_ready and not result.warnings:
        return None
    if result.status == "pass" and not dmarc_ready:
        return DNSHealthRecommendation(
            type="bimi_dmarc_not_ready",
            severity="warning",
            title="DMARC enforcement is blocking BIMI readiness",
            detail="; ".join(dmarc_issues),
            action="Move DMARC to quarantine or reject at pct=100 before relying on BIMI.",
            evidence=dmarc_evidence + bimi_evidence,
        )
    if result.status == "pass":
        return DNSHealthRecommendation(
            type="bimi_review",
            severity="info",
            title="BIMI record needs provider-readiness review",
            detail="; ".join(result.warnings),
            action=(
                "Confirm the SVG logo profile and add a certificate URL if mailbox "
                "providers require one."
            ),
            evidence=bimi_evidence,
        )
    return DNSHealthRecommendation(
        type="missing_bimi",
        severity="info",
        title="Publish BIMI after DMARC enforcement",
        detail="; ".join(result.errors or ["No BIMI record is published."]),
        action="Publish a BIMI TXT record at default._bimi with an HTTPS SVG logo URL.",
        evidence=dmarc_evidence + bimi_evidence,
    )


def _mta_sts_check(result: MTAStsResult) -> DNSHealthCheck:
    evidence = [
        _record_evidence("MTA-STS TXT", result.dns_record, "#dns-records"),
        _record_evidence("Policy URL", result.policy_url, "#mta-sts-posture"),
    ]
    if result.mode:
        evidence.append(_record_evidence("Mode", result.mode, "#mta-sts-posture"))
    if result.mx:
        evidence.append(_record_evidence("MX patterns", ", ".join(result.mx), "#mta-sts-posture"))
    message = (
        "MTA-STS DNS and HTTPS policy are valid."
        if result.status == "pass"
        else (result.errors[0] if result.errors else "MTA-STS posture needs attention.")
    )
    return DNSHealthCheck(
        key="mta_sts",
        label="MTA-STS",
        status=result.status,
        message=message,
        evidence=evidence,
    )


def _mta_sts_recommendation(result: MTAStsResult) -> Optional[DNSHealthRecommendation]:
    if result.status == "pass" and not result.warnings:
        return None
    severity = "warning" if result.status == "pass" else "error"
    if result.status == "pass":
        title = "MTA-STS policy needs review"
        detail = "; ".join(result.warnings)
        action = "Move the policy to mode: enforce once MX coverage is confirmed."
        recommendation_type = "mta_sts_review"
    elif not result.dns_record:
        title = "Publish MTA-STS"
        detail = "; ".join(result.errors or ["MTA-STS is not configured."])
        action = "Publish _mta-sts TXT and a valid HTTPS policy at the well-known URL."
        recommendation_type = "missing_mta_sts"
    elif result.policy_text is None:
        title = "Host the MTA-STS policy"
        detail = "; ".join(result.errors or ["The MTA-STS policy URL is not reachable."])
        action = (
            "Keep the existing _mta-sts TXT record if its id is current, then make "
            f"{result.policy_url} reachable over HTTPS with a valid policy file. "
            "Rotate the TXT id after publishing the policy so receivers refetch it."
        )
        recommendation_type = "mta_sts_policy_unreachable"
    else:
        title = "Fix the MTA-STS policy file"
        detail = "; ".join(result.errors or ["The MTA-STS policy file is not valid."])
        action = (
            "Update the policy file so it includes version: STSv1, mode, max_age, "
            "and at least one mx entry."
        )
        recommendation_type = "mta_sts_policy_invalid"
    return DNSHealthRecommendation(
        type=recommendation_type,
        severity=severity,
        title=title,
        detail=detail,
        action=action,
        evidence=_mta_sts_check(result).evidence,
    )


async def _build_domain_dns_health(  # pylint: disable=too-many-locals
    db: Session,
    store: ReportStore,
    domain_id: str,
    *,
    refresh: bool = False,
) -> DNSHealthResponse:
    """Build the shared DNS/posture health payload for a monitored domain."""
    manual_selectors = _get_domain_selectors_from_db(db, domain_id)
    report_selectors = _get_selectors_from_reports(store, domain_id)
    combined_selectors = list(dict.fromkeys(manual_selectors + report_selectors))

    provider = get_default_provider(db)
    result, _, _ = await resolve_domain_dns_cached(
        db,
        provider,
        domain_id,
        selectors=combined_selectors,
        refresh=refresh,
    )
    mta_sts_result, _, _ = await check_mta_sts_cached(
        db,
        provider,
        domain_id,
        refresh=refresh,
    )
    bimi_result, _, _ = await check_bimi_cached(
        db,
        provider,
        domain_id,
        refresh=refresh,
    )
    summary = store.get_domain_summary(domain_id)
    policy = extract_dmarc_policy(result.dmarc_record) or "none"
    bimi_dmarc_ready, bimi_dmarc_issues, bimi_dmarc_evidence = _bimi_dmarc_readiness(
        result.dmarc_record
    )
    checks = [
        _dns_check(
            "dmarc",
            "DMARC",
            result.dmarc,
            "DMARC record is published.",
            "No DMARC record was found.",
            [_record_evidence("DMARC TXT", result.dmarc_record)],
        ),
        _dns_check(
            "spf",
            "SPF",
            result.spf,
            "SPF record is published.",
            "No SPF record was found at the domain root.",
            [_record_evidence("SPF TXT", result.spf_record)],
        ),
        _dns_check(
            "dkim",
            "DKIM",
            result.dkim,
            "At least one DKIM selector resolved.",
            "No DKIM record was found for configured or observed selectors.",
            [
                _record_evidence(
                    "Selectors checked",
                    ", ".join(combined_selectors or result.selectors_checked or []),
                ),
                _record_evidence("DKIM TXT", result.dkim_record),
            ],
        ),
        _mta_sts_check(mta_sts_result),
        _bimi_check(bimi_result, bimi_dmarc_ready),
    ]
    recommendations: List[DNSHealthRecommendation] = []
    for check in checks:
        if check.status == "fail" and check.key not in {"mta_sts", "bimi"}:
            recommendations.append(
                DNSHealthRecommendation(
                    type=f"missing_{check.key}",
                    severity="error" if check.key == "dmarc" else "warning",
                    title=f"{check.label} needs attention",
                    detail=check.message,
                    action=(
                        f"Publish or repair the {check.label} DNS record, then "
                        "refresh DNS health."
                    ),
                    evidence=check.evidence,
                )
            )
    recommendations.append(_enforcement_recommendation(policy, summary))
    mta_sts_recommendation = _mta_sts_recommendation(mta_sts_result)
    if mta_sts_recommendation:
        recommendations.append(mta_sts_recommendation)
    bimi_recommendation = _bimi_recommendation(
        bimi_result,
        bimi_dmarc_ready,
        bimi_dmarc_issues,
        bimi_dmarc_evidence,
    )
    if bimi_recommendation:
        recommendations.append(bimi_recommendation)

    failed_checks = sum(1 for check in checks if check.status == "fail")
    health_status = (
        "healthy" if failed_checks == 0 else "degraded" if failed_checks < 3 else "critical"
    )
    return DNSHealthResponse(
        status=health_status,
        policy=policy,
        compliance_rate=float(summary.get("compliance_rate", 0.0) or 0.0),
        total_emails=int(summary.get("total_count", 0) or 0),
        failed_emails=int(summary.get("failed_count", 0) or 0),
        dns_lookup_status=result.lookup_status,
        dns_lookup_error=result.lookup_error,
        checks=checks,
        recommendations=recommendations,
    )


async def _build_domain_dns_guidance(
    db: Session,
    store: ReportStore,
    domain_id: str,
    *,
    refresh: bool = False,
    locale: Optional[str] = None,
) -> Dict[str, Any]:
    """Build typed DNS lint findings and target records for a monitored domain."""
    manual_selectors = _get_domain_selectors_from_db(db, domain_id)
    report_selectors = _get_selectors_from_reports(store, domain_id)
    combined_selectors = list(dict.fromkeys(manual_selectors + report_selectors))

    provider = get_default_provider(db)
    dns_result, _, _ = await resolve_domain_dns_cached(
        db,
        provider,
        domain_id,
        selectors=combined_selectors,
        refresh=refresh,
    )
    mta_sts_result, _, _ = await check_mta_sts_cached(
        db,
        provider,
        domain_id,
        refresh=refresh,
    )
    bimi_result, _, _ = await check_bimi_cached(
        db,
        provider,
        domain_id,
        refresh=refresh,
    )
    dane_result, _, _ = await check_dane_cached(
        db,
        provider,
        domain_id,
        refresh=refresh,
    )
    mail_service_records = await mail_service_dns_records_for_domain(db, domain_id)
    stored_domain = db.query(Domain).filter(Domain.name == domain_id).first()
    guidance = await build_dns_guidance(
        domain_id,
        provider,
        dns_result,
        mta_sts_result,
        bimi_result,
        dane_result,
        monitored_selectors=combined_selectors,
        observed_selectors=report_selectors,
        mail_service_records=mail_service_records,
        setup_defaults=_mail_auth_setup_defaults(db, stored_domain),
        locale=locale or get_settings().default_locale,
    )
    return asdict(guidance)


def _highest_severity(findings: List[Dict[str, Any]]) -> str:
    order = {"error": 3, "warning": 2, "info": 1}
    highest = "info"
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        if order.get(severity, 0) > order.get(highest, 0):
            highest = severity
    return highest


def _coverage_href(check: DNSHealthCheck) -> str:
    if check.evidence:
        return check.evidence[0].href
    return "#posture-dashboard"


def _posture_summary(health: DNSHealthResponse) -> str:
    if health.status == "healthy":
        return "All configured posture checks are passing."
    failed = sum(1 for check in health.checks if check.status == "fail")
    area = "area" if failed == 1 else "areas"
    if health.status == "degraded":
        verb = "needs" if failed == 1 else "need"
        return f"{failed} posture {area} {verb} review before this domain is fully ready."
    return f"{failed} posture {area} need attention before this domain is safe to tighten."


def _change_title(change: Dict[str, Any]) -> str:
    record_type = change.get("record_type") or "DNS"
    record_name = change.get("record_name") or "record"
    change_type = change.get("change_type") or "changed"
    return f"{record_type} {record_name} {change_type}"


def _change_summaries(changes: List[Dict[str, Any]]) -> List[PostureChangeSummary]:
    if not changes:
        return [
            PostureChangeSummary(
                title="No tracked DNS drift yet",
                detail=(
                    "Provider-backed DNS change tracking has not observed a DMARC, SPF, "
                    "DKIM, MTA-STS, or BIMI record change for this domain."
                ),
                severity="info",
                evidence=[
                    DNSHealthEvidence(
                        label="Change history",
                        value="No provider-backed DNS changes recorded",
                        href="#posture-changes",
                    )
                ],
            )
        ]

    summaries: List[PostureChangeSummary] = []
    for change in changes[:5]:
        previous = change.get("previous_content") or "none"
        current = change.get("current_content") or "none"
        summaries.append(
            PostureChangeSummary(
                title=_change_title(change),
                detail="DNS provider history recorded a posture-relevant record change.",
                severity=(
                    "warning" if change.get("change_type") in {"modified", "removed"} else "info"
                ),
                observed_at=change.get("observed_at"),
                evidence=[
                    DNSHealthEvidence(
                        label="Previous", value=str(previous), href="#posture-changes"
                    ),
                    DNSHealthEvidence(label="Current", value=str(current), href="#posture-changes"),
                ],
            )
        )
    return summaries


def _playbook_steps(recommendation: DNSHealthRecommendation) -> List[str]:
    playbooks = {
        "missing_dmarc": [
            "Publish one TXT record at _dmarc for this domain.",
            "Start with p=none and rua pointing at the reporting mailbox DMARQ imports.",
            "Refresh DNS health and wait for aggregate reports before tightening policy.",
        ],
        "missing_spf": [
            "List every service that is allowed to send mail for this domain.",
            "Publish one root SPF TXT record that includes those senders.",
            "Keep the SPF record to a single TXT value and refresh DNS health.",
        ],
        "missing_dkim": [
            "Add the sending provider's DKIM selector to this domain in DMARQ.",
            "Publish the provider's selector TXT record in DNS.",
            "Refresh DNS health and confirm at least one selector resolves.",
        ],
        "policy_enforcement_ready": [
            "Review the linked failed sources before changing policy.",
            "Move to quarantine gradually with a small pct value.",
            "Watch DMARC failures for several report cycles before increasing pct.",
        ],
        "policy_enforcement_review": [
            "Open the linked sending sources and identify the remaining failures.",
            "Fix SPF or DKIM alignment for legitimate senders.",
            "Re-check readiness after compliance is consistently above the threshold.",
        ],
        "policy_not_ready": [
            "Treat unknown full-fail senders as untrusted until verified.",
            "Configure SPF and DKIM for legitimate sources first.",
            "Keep monitoring mode until failures drop to a safe level.",
        ],
        "missing_mta_sts": [
            "Publish _mta-sts TXT with a stable id value.",
            "Host a valid policy file at the linked well-known HTTPS URL.",
            "Start in testing mode, then move to enforce after MX coverage is verified.",
        ],
        "mta_sts_policy_unreachable": [
            "Keep the existing _mta-sts TXT record unless the id needs rotation.",
            "Create DNS for the mta-sts host and make the linked HTTPS policy URL reachable.",
            "Serve a valid policy file, then rotate the TXT id to force receivers to refetch it.",
        ],
        "mta_sts_policy_invalid": [
            "Open the linked policy file and correct invalid or missing fields.",
            "Include version: STSv1, mode, max_age, and all expected MX patterns.",
            "Rotate the _mta-sts TXT id after publishing the corrected policy.",
        ],
        "mta_sts_review": [
            "Open the linked policy evidence and confirm all MX hosts are covered.",
            "Fix policy warnings and increase max_age when stable.",
            "Move to enforce only after successful validation.",
        ],
        "missing_bimi": [
            "Complete DMARC enforcement prerequisites first.",
            "Publish a default._bimi TXT record with an HTTPS SVG logo URL.",
            "Add a certificate URL if the mailbox providers you care about require it.",
        ],
        "bimi_dmarc_not_ready": [
            "Move DMARC to quarantine or reject at pct=100.",
            "Confirm subdomain policy does not weaken enforcement.",
            "Refresh BIMI readiness after the DMARC record is updated.",
        ],
        "bimi_review": [
            "Confirm the logo is a valid HTTPS SVG asset.",
            "Add or verify the certificate URL for providers that require it.",
            "Refresh BIMI readiness and keep the evidence links with the record.",
        ],
    }
    return playbooks.get(
        recommendation.type,
        [
            recommendation.action,
            "Use the linked evidence to confirm the record or report data.",
            "Refresh posture after the change is published.",
        ],
    )


def _operator_playbooks(
    recommendations: List[DNSHealthRecommendation],
) -> List[OperatorPlaybook]:
    return [
        OperatorPlaybook(
            key=recommendation.type,
            title=recommendation.title,
            summary=recommendation.action,
            steps=_playbook_steps(recommendation),
            evidence=recommendation.evidence,
        )
        for recommendation in recommendations
        if recommendation.severity in {"error", "warning"}
        or recommendation.type.startswith("policy_")
    ][:6]


async def _build_domain_health_grade(
    db: Session,
    domain_id: str,
    store: ReportStore,
    *,
    refresh: bool = False,
) -> Dict[str, Any]:
    """Build the dashboard-grade health object for a domain detail page."""
    manual_selectors = _get_domain_selectors_from_db(db, domain_id)
    report_selectors = _get_selectors_from_reports(store, domain_id)
    combined_selectors = list(dict.fromkeys(manual_selectors + report_selectors))
    provider = get_default_provider(db)
    try:
        dns, _, _ = await resolve_domain_dns_cached(
            db,
            provider,
            domain_id,
            selectors=combined_selectors,
            refresh=refresh,
        )
    except (asyncio.TimeoutError, LookupError, OSError) as exc:
        dns = DomainDNSResult(
            lookup_status="failed",
            lookup_error=f"DNS lookup failed: {exc}",
        )
    summary = store.get_domain_summary(domain_id)
    live_policy = extract_dmarc_policy(dns.dmarc_record)
    reported_policy = _normalize_reported_policy(summary.get("policy", {}))
    sources = store.get_domain_sources(domain_id)
    reports = store.get_domain_reports(domain_id)
    intelligence = build_source_intelligence(
        domain_id,
        reports,
        sources,
        period_days=30,
    )
    sender_by_ip = {
        str(source.get("source_ip") or "unknown"): identify_sender(
            str(source.get("source_ip") or "unknown"),
            source,
            hostname=None,
            domain=domain_id,
        )
        for source in sources
    }
    reputation_result, _, _ = await build_source_reputation_cached(
        db,
        domain_id,
        reports,
        sources,
        senders_by_ip=sender_by_ip,
        anomalies_by_ip=intelligence.get("anomalies_by_ip", {}),
        days=30,
        refresh=refresh,
    )
    dmarc_policy, dmarc_policy_source = _dmarc_policy_with_source(
        dns,
        live_policy=live_policy,
        reported_policy=reported_policy,
    )
    dns_evidence_source = _dns_evidence_source(dns)
    dns_pending = bool(getattr(dns, "pending", False))
    dns_lookup_status = _dns_lookup_status(dns)
    domain_row = {
        "id": domain_id,
        "domain_name": domain_id,
        "total_emails": summary.get("total_count", 0),
        "passed_count": summary.get("passed_count", 0),
        "failed_count": summary.get("failed_count", 0),
        "pass_rate": summary.get("compliance_rate", 0),
        "report_count": summary.get("reports_processed", 0),
        "dmarc_status": dns.dmarc,
        "dmarc_policy": dmarc_policy,
        "dmarc_policy_source": dmarc_policy_source,
        "dns_evidence_source": dns_evidence_source,
        "spf_status": dns.spf,
        "dkim_status": dns.dkim,
        "dns_pending": dns_pending,
        "dns_lookup_status": dns_lookup_status,
        "dns_lookup_failed": dns_lookup_status == "failed",
        "dns_lookup_error": dns.lookup_error,
        "dmarc_warnings": dns.dmarc_warnings,
        "dmarc_suggestions": dns.dmarc_suggestions,
        "source_reputation": asdict(reputation_result),
    }
    return score_domain_health(domain_row)


def _build_posture_dashboard(
    domain_id: str,
    health: DNSHealthResponse,
    domain_health: Dict[str, Any],
    changes: List[Dict[str, Any]],
) -> PostureDashboardResponse:
    score = _posture_score(health.checks)
    coverage = [
        PostureCoverageItem(
            key=check.key,
            label=check.label,
            status=check.status,
            message=check.message,
            evidence_count=len(check.evidence),
            href=_coverage_href(check),
        )
        for check in health.checks
    ]
    return PostureDashboardResponse(
        domain=domain_id,
        status=health.status,
        score=score,
        health=domain_health,
        summary=_posture_summary(health),
        coverage=coverage,
        recommendations=health.recommendations,
        changes=_change_summaries(changes),
        playbooks=_operator_playbooks(health.recommendations),
    )


def _posture_score(checks: List[DNSHealthCheck]) -> int:
    """Score posture with DMARC/SPF/DKIM as core controls and optional controls as light weight."""
    if not checks:
        return 0
    weights = {
        "dmarc": 35,
        "spf": 25,
        "dkim": 25,
        "mta_sts": 10,
        "bimi": 5,
    }
    total_weight = sum(weights.get(check.key, 0) for check in checks)
    if total_weight <= 0:
        return 0
    passing_weight = sum(weights.get(check.key, 0) for check in checks if check.status == "pass")
    return round((passing_weight / total_weight) * 100)


def _history_response_from_points(
    domain_id: str,
    points: List[Dict[str, Any]],
) -> HealthScoreHistoryResponse:
    """Build a health history response from serialized points."""
    current = points[-1] if points else None
    previous = points[-2] if len(points) > 1 else None
    return HealthScoreHistoryResponse(
        domain=domain_id,
        points=points,
        current_score=current["score"] if current else None,
        previous_score=previous["score"] if previous else None,
        score_delta=current["score"] - previous["score"] if current and previous else None,
        current_grade=current["grade"] if current else None,
        previous_grade=previous["grade"] if previous else None,
        top_drivers=current.get("top_actions", []) if current else [],
    )


def _demo_history_points(
    domain_id: str,
    *,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    limit: int = 120,
) -> List[Dict[str, Any]]:
    points = build_demo_health_score_history(domain_id, days=min(max(limit, 1), DEMO_DAYS))
    if start_date:
        points = [point for point in points if date.fromisoformat(point["date"]) >= start_date]
    if end_date:
        points = [point for point in points if date.fromisoformat(point["date"]) <= end_date]
    return points[-limit:]


def _workspace_history_response_from_points(
    points: List[Dict[str, Any]],
) -> WorkspaceHealthScoreHistoryResponse:
    """Build a workspace health history response from serialized points."""
    current = points[-1] if points else None
    previous = points[-2] if len(points) > 1 else None
    return WorkspaceHealthScoreHistoryResponse(
        scope="workspace",
        points=points,
        current_score=current["score"] if current else None,
        previous_score=previous["score"] if previous else None,
        score_delta=current["score"] - previous["score"] if current and previous else None,
        current_grade=current["grade"] if current else None,
        previous_grade=previous["grade"] if previous else None,
        top_drivers=current.get("top_actions", []) if current else [],
    )


def _demo_workspace_history_points(
    domain_names: List[str],
    *,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    limit: int = 120,
) -> List[Dict[str, Any]]:
    """Return aggregated rolling demo history for the active workspace."""
    demo_domains = domain_names or ["dmarq.org", "dmarq.com"]
    points_by_domain = {
        domain_name: _demo_history_points(
            domain_name,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
        for domain_name in demo_domains
    }
    return aggregate_workspace_health_points(points_by_domain)[-limit:]


def _write_health_evidence_csv(rows: List[Dict[str, Any]], *, domain_id: str) -> Response:
    output = io.StringIO()
    fields = [
        "domain",
        "snapshot_date",
        "score",
        "grade",
        "status",
        "policy",
        "compliance_rate",
        "total_emails",
        "failed_emails",
        "report_count",
        "dns_posture_score",
        "policy_strength_score",
        "report_confidence_score",
        "top_actions",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    filename = f"{domain_id.replace('/', '_')}-health-evidence.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _write_health_evidence_json(
    rows: List[Dict[str, Any]],
    *,
    export_id: str,
    scope: str,
) -> JSONResponse:
    filename = f"{export_id.replace('/', '_')}-health-evidence.json"
    return JSONResponse(
        content={
            "scope": scope,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rows": rows,
        },
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _write_health_evidence_export(
    rows: List[Dict[str, Any]],
    *,
    export_id: str,
    scope: str,
    export_format: str,
) -> Response:
    if export_format == "json":
        return _write_health_evidence_json(rows, export_id=export_id, scope=scope)
    return _write_health_evidence_csv(rows, domain_id=export_id)


def write_health_evidence_export(
    rows: List[Dict[str, Any]],
    *,
    export_id: str,
    scope: str,
    export_format: str,
) -> Response:
    """Write sanitized health evidence rows as a stable API response."""
    return _write_health_evidence_export(
        rows,
        export_id=export_id,
        scope=scope,
        export_format=export_format,
    )


async def build_domain_health_evidence_export_rows(
    *,
    domain_id: str,
    start_date: Optional[date],
    end_date: Optional[date],
    limit: int,
    capture_current: bool,
    db: Session,
    auth_context: Dict[str, Any],
    selected_workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Build sanitized health evidence rows for one authorized workspace domain."""
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_date must be on or before end_date",
        )
    workspace = _authorized_domain_read_workspace(auth_context, db, selected_workspace_id)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    if capture_current and not get_settings().DEMO_MODE:
        health = await _build_domain_dns_health(db, store, domain_id)
        domain_health = await _build_domain_health_grade(db, domain_id, store)
        summary = store.get_domain_summary(domain_id)
        _record_health_snapshot_from_posture(
            db,
            workspace_id=workspace.id,
            domain_id=domain_id,
            dns_health=health,
            domain_health=domain_health,
            report_count=int(summary.get("reports_processed", 0) or 0),
        )

    snapshots = list_health_score_snapshots(
        db,
        workspace_id=workspace.id,
        domain_name=domain_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
    )
    if not snapshots and get_settings().DEMO_MODE:
        points = _demo_history_points(
            domain_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
        return _demo_evidence_export_rows(domain_id, points)
    return build_health_evidence_export_rows(snapshots)


def _demo_evidence_export_rows(
    domain_id: str, points: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    rows = []
    for point in points:
        rows.append(
            {
                "domain": domain_id,
                "snapshot_date": point["date"],
                "score": point["score"],
                "grade": point["grade"],
                "status": point["status"],
                "policy": point.get("policy") or "",
                "compliance_rate": point["compliance_rate"],
                "total_emails": point["total_emails"],
                "failed_emails": point["failed_emails"],
                "report_count": point["report_count"],
                "dns_posture_score": point["dns_posture_score"],
                "policy_strength_score": point["policy_strength_score"],
                "report_confidence_score": point["report_confidence_score"],
                "top_actions": "; ".join(
                    f"{action.get('severity')}:{action.get('title')}"
                    for action in point.get("top_actions", [])
                    if action.get("title")
                ),
            }
        )
    return rows


def _workspace_evidence_export_rows(points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for point in points:
        rows.append(
            {
                "domain": "workspace",
                "snapshot_date": point["date"],
                "score": point["score"],
                "grade": point["grade"],
                "status": point["status"],
                "policy": point.get("policy") or "",
                "compliance_rate": point["compliance_rate"],
                "total_emails": point["total_emails"],
                "failed_emails": point["failed_emails"],
                "report_count": point["report_count"],
                "dns_posture_score": point["dns_posture_score"],
                "policy_strength_score": point["policy_strength_score"],
                "report_confidence_score": point["report_confidence_score"],
                "top_actions": "; ".join(
                    ":".join(
                        value
                        for value in [
                            str(action.get("domain") or ""),
                            str(action.get("severity") or ""),
                            str(action.get("title") or ""),
                        ]
                        if value
                    )
                    for action in point.get("top_actions", [])
                    if action.get("title")
                ),
            }
        )
    return rows


def _record_health_snapshot_from_posture(
    db: Session,
    *,
    workspace_id: int,
    domain_id: str,
    dns_health: DNSHealthResponse,
    domain_health: Dict[str, Any],
    report_count: int,
) -> None:
    upsert_health_score_snapshot(
        db,
        workspace_id=workspace_id,
        domain_name=domain_id,
        health=domain_health,
        policy=dns_health.policy,
        compliance_rate=dns_health.compliance_rate,
        total_emails=dns_health.total_emails,
        failed_emails=dns_health.failed_emails,
        report_count=report_count,
    )


def _with_dns_summary_metadata(
    result: DomainDNSResult,
    *,
    cached: bool,
    checked_at: Optional[datetime],
    pending: bool,
) -> DomainDNSResult:
    result.cached = cached  # type: ignore[attr-defined]
    result.checked_at = checked_at  # type: ignore[attr-defined]
    result.pending = pending  # type: ignore[attr-defined]
    return result


def _pending_dns_summary_result() -> DomainDNSResult:
    return _with_dns_summary_metadata(
        DomainDNSResult(lookup_status="pending"),
        cached=False,
        checked_at=None,
        pending=True,
    )


_NON_LIVE_DNS_POLICY_STATUSES = {"pending", "failed", "stale_cache", "fallback"}


def _dns_lookup_status(dns: DomainDNSResult) -> str:
    return str(getattr(dns, "lookup_status", "ok") or "ok")


def _dns_has_evidence(dns: DomainDNSResult) -> bool:
    return any(
        (
            dns.dmarc,
            dns.dmarc_record,
            dns.spf,
            dns.spf_record,
            dns.dkim,
            dns.dkim_record,
            dns.dkim_selectors,
            dns.nameservers,
            dns.dmarc_policy_domain,
        )
    )


def _dmarc_policy_with_source(
    dns: DomainDNSResult,
    *,
    live_policy: Optional[str],
    reported_policy: Optional[str],
) -> Tuple[str, str]:
    status = _dns_lookup_status(dns)
    if status in _NON_LIVE_DNS_POLICY_STATUSES and reported_policy:
        return reported_policy, "report"
    if live_policy:
        return live_policy, "dns"
    if reported_policy:
        return reported_policy, "report"
    return "none", "default"


def _dns_evidence_source(dns: DomainDNSResult) -> str:
    status = _dns_lookup_status(dns)
    if status == "pending":
        return "pending"
    if status == "failed":
        return "lookup_failed"
    if status == "stale_cache":
        return "stale_cache"
    if status == "fallback":
        return "fallback_dns"
    if status == "partial":
        return "partial_dns"
    if _dns_has_evidence(dns):
        return "cached_dns" if getattr(dns, "cached", False) else "live_dns"
    return "empty_lookup"


def _failed_dns_summary_result(error: str) -> DomainDNSResult:
    return _with_dns_summary_metadata(
        DomainDNSResult(lookup_status="failed", lookup_error=error),
        cached=False,
        checked_at=None,
        pending=False,
    )


async def _resolve_summary_dns_result(
    db: Session,
    provider: Any,
    domain_name: str,
    selectors: List[str],
    *,
    refresh: bool,
) -> DomainDNSResult:
    if not refresh:
        cached_result, cached, checked_at = get_cached_domain_dns_result(
            db,
            provider,
            domain_name,
            selectors=selectors,
        )
        if cached_result is not None:
            return _with_dns_summary_metadata(
                cached_result,
                cached=cached,
                checked_at=checked_at,
                pending=False,
            )
        fallback_result, fallback_cached, fallback_checked_at = (
            get_latest_cached_domain_dns_evidence(
                db,
                provider,
                domain_name,
            )
        )
        if fallback_result is not None:
            return _with_dns_summary_metadata(
                fallback_result,
                cached=fallback_cached,
                checked_at=fallback_checked_at,
                pending=False,
            )
        return _pending_dns_summary_result()

    try:
        result, cached, checked_at = await asyncio.wait_for(
            resolve_domain_dns_cached(
                db,
                provider,
                domain_name,
                selectors=selectors,
                refresh=refresh,
            ),
            timeout=10.0,
        )
        return _with_dns_summary_metadata(
            result,
            cached=cached,
            checked_at=checked_at,
            pending=False,
        )
    except (asyncio.TimeoutError, LookupError, OSError) as exc:
        logger.warning("DNS check failed for %s: %s", domain_name, exc)
        return _failed_dns_summary_result(f"DNS lookup failed: {exc}")


@router.get("/summary", response_model=DomainSummaryResponse)
async def get_domains_summary(
    refresh: bool = Query(False, title="Refresh cached DNS results"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get summary statistics for all domains, formatted for the dashboard.

    Returns report and domain statistics quickly. By default DNS status is read
    from cache only so the domain list is not blocked by live resolver calls.
    Use refresh=true from the UI reload action to force live DNS recomputation.
    """
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    demo_mode = get_settings().DEMO_MODE
    store: Optional[ReportStore] = None
    report_selectors_by_domain: Dict[str, List[str]] = {}
    if demo_mode:
        store = ReportStore()
        hydrate_report_store_from_db(
            db,
            store,
            workspace_id=workspace.id,
        )
        domains = _domain_names_for_summary(
            db,
            store,
            workspace,
            include_unscoped_report_domains=True,
        )
        summaries = store.get_all_domain_summaries()
    else:
        summaries = domain_summaries_from_db(db, workspace_id=workspace.id)
        domains = list(summaries)
        report_selectors_by_domain = _get_report_selectors_map_from_db(
            db,
            domains,
            workspace_id=workspace.id,
        )

    # Perform DNS checks for all domains, reusing fresh cached results.
    provider = get_default_provider(db)
    manual_selectors_by_domain = _get_domain_selectors_map_from_db(db, domains)
    stored_domains_by_name = {
        domain.name: domain
        for domain in workspace_domain_query(db, workspace).filter(Domain.name.in_(domains)).all()
    }
    remediation_activity = summarize_remediation_activity(
        db,
        workspace=workspace,
        domains=domains,
    )
    remediation_by_domain = remediation_activity["domains"]

    async def _dns_for_domain(domain_name: str) -> DomainDNSResult:
        manual_selectors = manual_selectors_by_domain.get(domain_name, [])
        if demo_mode and store is not None:
            report_selectors = _get_selectors_from_reports(store, domain_name)
        else:
            report_selectors = report_selectors_by_domain.get(domain_name, [])
        combined = list(dict.fromkeys(manual_selectors + report_selectors))
        return await _resolve_summary_dns_result(
            db,
            provider,
            domain_name,
            combined,
            refresh=refresh,
        )

    dns_results = []
    for domain_name in domains:
        dns_results.append(await _dns_for_domain(domain_name))

    # Calculate overall statistics
    total_domains = len(domains)
    total_emails = 0
    total_passed = 0
    total_reports = 0

    domains_list = []

    for domain_name, dns in zip(domains, dns_results):
        summary = summaries.get(domain_name, {})
        stored_domain = stored_domains_by_name.get(domain_name)
        total_emails += summary.get("total_count", 0)
        total_passed += summary.get("passed_count", 0)
        total_reports += summary.get("reports_processed", 0)

        live_policy = extract_dmarc_policy(dns.dmarc_record)
        reported_policy = _normalize_reported_policy(summary.get("policy", {}))
        dmarc_policy, dmarc_policy_source = _dmarc_policy_with_source(
            dns,
            live_policy=live_policy,
            reported_policy=reported_policy,
        )
        dns_pending = bool(getattr(dns, "pending", False))
        dns_lookup_status = _dns_lookup_status(dns)
        dns_lookup_failed = dns_lookup_status == "failed"
        dns_evidence_source = _dns_evidence_source(dns)

        # Format domain data for frontend
        domain_row = {
            "id": domain_name,
            "domain_name": domain_name,
            "description": stored_domain.description if stored_domain else None,
            "dkim_selectors": manual_selectors_by_domain.get(domain_name, []),
            "total_emails": summary.get("total_count", 0),
            "passed_count": summary.get("passed_count", 0),
            "failed_count": summary.get("failed_count", 0),
            "pass_rate": summary.get("compliance_rate", 0),
            "report_count": summary.get("reports_processed", 0),
            # Real DNS status
            "dmarc_status": dns.dmarc,
            "dmarc_policy": dmarc_policy,
            "dmarc_policy_source": dmarc_policy_source,
            "dns_evidence_source": dns_evidence_source,
            "spf_status": dns.spf,
            "dkim_status": dns.dkim,
            "dns_pending": dns_pending,
            "dns_lookup_status": dns_lookup_status,
            "dns_lookup_failed": dns_lookup_failed,
            "dns_lookup_error": getattr(dns, "lookup_error", None),
            "dns_cached": getattr(dns, "cached", False),
            "dns_checked_at": (
                getattr(dns, "checked_at", None).isoformat()
                if getattr(dns, "checked_at", None)
                else None
            ),
            "dmarc_warnings": dns.dmarc_warnings,
            "dmarc_suggestions": dns.dmarc_suggestions,
            "remediation": remediation_by_domain.get(domain_name, {}),
        }
        domain_row["health"] = score_domain_health(domain_row)
        domain_row["remediation_workload"] = _domain_remediation_workload(domain_row)
        domains_list.append(domain_row)

    domain_health = [domain["health"] for domain in domains_list]

    # Calculate overall pass rate
    overall_pass_rate = 0
    if total_emails > 0:
        overall_pass_rate = round((total_passed / total_emails) * 100, 1)

    health_summary = build_health_summary(domains_list, domain_health)
    health_summary["remediation"] = remediation_activity["summary"]
    health_summary["remediation_loop"] = _build_dashboard_remediation_loop(
        domains_list,
        remediation_activity,
    )

    return DomainSummaryResponse(
        total_domains=total_domains,
        total_emails=total_emails,
        overall_pass_rate=overall_pass_rate,
        reports_processed=total_reports,
        domains=domains_list,
        health_summary=health_summary,
    )


@router.get("/summary/health/history", response_model=WorkspaceHealthScoreHistoryResponse)
async def get_workspace_health_score_history(
    start_date: Optional[date] = Query(None, title="Start date for score history"),
    end_date: Optional[date] = Query(None, title="End date for score history"),
    limit: int = Query(120, ge=1, le=400, title="Maximum history points"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return selected-workspace health score history aggregated across domains."""
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_date must be on or before end_date",
        )
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    snapshots = list_workspace_health_score_snapshots(
        db,
        workspace_id=workspace.id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
    )
    if not snapshots and get_settings().DEMO_MODE:
        store = ReportStore()
        hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
        domains = _domain_names_for_summary(
            db,
            store,
            workspace,
            include_unscoped_report_domains=True,
        )
        return _workspace_history_response_from_points(
            _demo_workspace_history_points(
                domains,
                start_date=start_date,
                end_date=end_date,
                limit=limit,
            )
        )
    return WorkspaceHealthScoreHistoryResponse(**build_workspace_health_score_history(snapshots))


@router.get("/summary/health/evidence/export")
async def export_workspace_health_evidence(
    start_date: Optional[date] = Query(None, title="Start date for evidence export"),
    end_date: Optional[date] = Query(None, title="End date for evidence export"),
    limit: int = Query(400, ge=1, le=1000, title="Maximum exported snapshots"),
    export_format: str = Query(
        "csv",
        alias="format",
        pattern="^(csv|json)$",
        title="Evidence export format",
    ),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Export sanitized selected-workspace health score evidence as CSV or JSON."""
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_date must be on or before end_date",
        )
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    snapshots = list_workspace_health_score_snapshots(
        db,
        workspace_id=workspace.id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
    )
    if not snapshots and get_settings().DEMO_MODE:
        store = ReportStore()
        hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
        domains = _domain_names_for_summary(
            db,
            store,
            workspace,
            include_unscoped_report_domains=True,
        )
        points = _demo_workspace_history_points(
            domains,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
        return _write_health_evidence_export(
            _workspace_evidence_export_rows(points),
            export_id="workspace",
            scope="workspace",
            export_format=export_format,
        )

    return _write_health_evidence_export(
        _workspace_evidence_export_rows(build_workspace_health_score_history(snapshots)["points"]),
        export_id="workspace",
        scope="workspace",
        export_format=export_format,
    )


@router.get("/domains", response_model=List[DomainResponse])
async def read_domains(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Retrieve domains with their statistics.
    """
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    if get_settings().DEMO_MODE:
        store = ReportStore()
        hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
        domains = _domain_names_for_summary(
            db,
            store,
            workspace,
            include_unscoped_report_domains=False,
        )
        summaries = store.get_all_domain_summaries()
    else:
        summaries = domain_summaries_from_db(db, workspace_id=workspace.id)
        domains = list(summaries)
    stored = {
        domain.name: domain
        for domain in workspace_domain_query(db, workspace).filter(Domain.name.in_(domains)).all()
    }

    result = []
    for domain_name in domains:
        summary = summaries.get(domain_name, {})
        stored_domain = stored.get(domain_name)
        domain_response = DomainResponse(
            name=domain_name,
            description=stored_domain.description if stored_domain else None,
            policy=(
                _normalize_reported_policy(summary.get("policy"))
                or (stored_domain.dmarc_policy if stored_domain else None)
                or "unknown"
            ),
            reports_count=summary.get("reports_processed", 0),
            emails_count=summary.get("total_count", 0),
            compliance_rate=summary.get("compliance_rate", 0.0),
            dkim_selectors=_normalize_domain_selectors(
                (stored_domain.dkim_selectors or "").split(",") if stored_domain else []
            ),
            dmarc_report_mailbox=stored_domain.dmarc_report_mailbox if stored_domain else None,
            mail_service_context=mail_service_context_from_domain(stored_domain),
        )
        result.append(domain_response)

    return result


@router.post("/domains", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    payload: DomainCreate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Create a monitored domain before any DMARC reports have arrived."""
    workspace = _authorized_domain_workspace(_auth, db)
    name = normalize_domain_name(payload.name)
    validation = validate_domain_config({"name": name, "description": payload.description or ""})
    if not validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=validation["errors"],
        )
    existing = workspace_domain_query(db, workspace).filter(Domain.name == name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain is already monitored",
        )
    if workspace.organization:
        try:
            require_organization_plan_limit(
                db,
                workspace.organization,
                "monitored_domains",
            )
        except OrganizationPlanLimitError as exc:
            _raise_plan_limit_error(exc)

    selectors = ",".join(_normalize_domain_selectors(payload.dkim_selectors))
    report_mailbox = _normalize_optional_mailbox(payload.dmarc_report_mailbox)
    domain = Domain(
        workspace_id=workspace.id,
        name=name,
        description=payload.description,
        dkim_selectors=selectors or None,
        dmarc_report_mailbox=report_mailbox,
        active=True,
        verified=False,
    )
    db.add(domain)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain is already monitored",
        ) from exc
    db.refresh(domain)
    return DomainResponse(
        name=domain.name,
        description=domain.description,
        policy=domain.dmarc_policy or "unknown",
        dkim_selectors=_normalize_domain_selectors((domain.dkim_selectors or "").split(",")),
        dmarc_report_mailbox=domain.dmarc_report_mailbox,
        mail_service_context=mail_service_context_from_domain(domain),
    )


@router.get("/domains/{domain_name}", response_model=DomainResponse)
async def read_domain(
    domain_name: str,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Get statistics for a specific domain.
    """
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    domains = _domain_names_for_summary(db, store, workspace)
    stored_domain = workspace_domain_query(db, workspace).filter(Domain.name == domain_name).first()

    if domain_name not in domains and stored_domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    summary = store.get_domain_summary(domain_name)
    policy = _normalize_reported_policy(summary.get("policy"))

    return DomainResponse(
        name=domain_name,
        description=stored_domain.description if stored_domain else None,
        policy=policy or (stored_domain.dmarc_policy if stored_domain else None) or "unknown",
        reports_count=summary.get("reports_processed", 0),
        emails_count=summary.get("total_count", 0),
        compliance_rate=summary.get("compliance_rate", 0.0),
        dkim_selectors=_normalize_domain_selectors(
            (stored_domain.dkim_selectors or "").split(",") if stored_domain else []
        ),
        dmarc_report_mailbox=stored_domain.dmarc_report_mailbox if stored_domain else None,
        mail_service_context=mail_service_context_from_domain(stored_domain),
    )


@router.patch("/domains/{domain_name}", response_model=DomainResponse)
async def update_domain(
    payload: DomainUpdate,
    request: Request,
    domain_name: str,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Update editable metadata for a monitored domain."""
    workspace = _authorized_domain_workspace(_auth, db)
    name = normalize_domain_name(domain_name)
    fields = _domain_update_fields(payload)
    if not fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one editable field must be provided",
        )

    validation = validate_domain_config({"name": name, "description": payload.description or ""})
    if "description" in fields and not validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=validation["errors"],
        )

    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    existing_domain_names = _domain_names_for_summary(db, store, workspace)
    domain = workspace_domain_query(db, workspace).filter(Domain.name == name).first()
    if domain is None and name not in existing_domain_names:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    if domain is None:
        domain = Domain(name=name, workspace_id=workspace.id, active=True)
        db.add(domain)

    if "description" in fields:
        domain.description = payload.description
    if "dkim_selectors" in fields:
        selectors = _normalize_domain_selectors(payload.dkim_selectors)
        domain.dkim_selectors = ",".join(selectors) if selectors else None
    if "dmarc_report_mailbox" in fields:
        domain.dmarc_report_mailbox = _normalize_optional_mailbox(payload.dmarc_report_mailbox)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain is already monitored",
        ) from exc
    db.refresh(domain)
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="domain.updated",
        entity_type="domain",
        entity_id=domain.id,
        entity_name=domain.name,
        details={
            "updated_fields": sorted(fields),
            "dkim_selector_count": len(
                _normalize_domain_selectors((domain.dkim_selectors or "").split(","))
            ),
            "has_dmarc_report_mailbox_override": bool(domain.dmarc_report_mailbox),
        },
        auth_context=_auth,
        request=request,
        commit=True,
    )

    summary = store.get_domain_summary(name)
    policy = _normalize_reported_policy(summary.get("policy"))
    return DomainResponse(
        name=domain.name,
        description=domain.description,
        policy=policy or domain.dmarc_policy or "unknown",
        reports_count=summary.get("reports_processed", 0),
        emails_count=summary.get("total_count", 0),
        compliance_rate=summary.get("compliance_rate", 0.0),
        dkim_selectors=_normalize_domain_selectors((domain.dkim_selectors or "").split(",")),
        dmarc_report_mailbox=domain.dmarc_report_mailbox,
        mail_service_context=mail_service_context_from_domain(domain),
    )


@router.get("/dns/lint", response_model=DNSBulkGuidanceResponse)
async def lint_all_domain_dns(
    refresh: bool = Query(False, title="Refresh cached DNS results"),
    limit: int = Query(100, ge=1, le=500, title="Maximum domains to lint"),
    locale: Optional[str] = Query(None, title="Operator guidance locale"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return typed DNS lint findings and target records for monitored domains."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    domains = _domain_names_for_summary(db, store, workspace)[:limit]

    items: List[DNSBulkGuidanceItem] = []
    for domain_name in domains:
        guidance = await _build_domain_dns_guidance(
            db, store, domain_name, refresh=refresh, locale=locale
        )
        findings = guidance["findings"]
        items.append(
            DNSBulkGuidanceItem(
                domain=domain_name,
                status=guidance["status"],
                finding_count=len(findings),
                highest_severity=_highest_severity(findings),
                findings=findings,
                target_records=guidance["target_records"],
            )
        )
    return DNSBulkGuidanceResponse(domains=items)


@router.get("/dns/lint/export")
async def export_all_domain_dns_lint(
    refresh: bool = Query(False, title="Refresh cached DNS results"),
    limit: int = Query(500, ge=1, le=1000, title="Maximum domains to export"),
    locale: Optional[str] = Query(None, title="Operator guidance locale"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Export typed DNS lint findings for monitored domains as CSV."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    domains = _domain_names_for_summary(db, store, workspace)[:limit]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "domain",
            "status",
            "severity",
            "code",
            "record_type",
            "record_name",
            "title",
            "detail",
            "action",
            "target_value",
        ]
    )
    for domain_name in domains:
        guidance = await _build_domain_dns_guidance(
            db, store, domain_name, refresh=refresh, locale=locale
        )
        for finding in guidance["findings"]:
            target = finding.get("target_record") or {}
            writer.writerow(
                [
                    domain_name,
                    guidance["status"],
                    finding.get("severity", ""),
                    finding.get("code", ""),
                    finding.get("record_type", ""),
                    finding.get("record_name", ""),
                    finding.get("title", ""),
                    finding.get("detail", ""),
                    finding.get("action", ""),
                    target.get("value", ""),
                ]
            )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="dmarq-dns-lint.csv"'},
    )


@router.get("/dns/providers", response_model=DNSProviderCapabilitiesResponse)
async def get_dns_provider_capabilities(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return provider-backed DNS write capabilities."""
    capabilities = provider_capabilities()
    import_provider_ids = {provider["id"] for provider in supported_import_providers()}
    connector_metadata = {provider["id"]: provider for provider in provider_connector_registry()}
    provider_rows = []
    seen_provider_ids = set()
    metadata_keys = {
        "tier",
        "auth_models",
        "zone_import_status",
        "record_read_status",
        "record_write_status",
        "dry_run_supported",
        "verification_supported",
        "rollback_supported",
        "minimum_permissions",
        "setup_hint",
        "docs_url",
    }
    for provider in capabilities:
        credentials_configured = _provider_credentials_configured(db, provider["id"])
        import_available = provider["id"] in import_provider_ids
        seen_provider_ids.add(provider["id"])
        provider_rows.append(
            {
                **provider,
                "import_available": import_available,
                "credentials_configured": credentials_configured,
                "connection_status": (
                    "connected"
                    if credentials_configured
                    else ("needs_credentials" if import_available else "planned")
                ),
                "connection_hint": (
                    "Credentials are configured. Discovery can run without exposing token material."
                    if credentials_configured
                    else (
                        "Configure read-only provider credentials before running zone discovery."
                        if import_available
                        else "Provider is tracked for repair planning but is not import-ready yet."
                    )
                ),
                **{
                    key: value
                    for key, value in connector_metadata.get(provider["id"], {}).items()
                    if key in metadata_keys
                },
            }
        )
    for provider_id, metadata in connector_metadata.items():
        if provider_id in seen_provider_ids:
            continue
        credentials_configured = _provider_credentials_configured(db, provider_id)
        import_available = provider_id in import_provider_ids
        provider_rows.append(
            {
                "id": provider_id,
                "name": metadata["name"],
                "mode": "planned",
                "record_types": [],
                "operations": [],
                "credentials": ", ".join(metadata.get("auth_models") or ["provider credentials"]),
                "status": "planned",
                "import_available": import_available,
                "credentials_configured": credentials_configured,
                "connection_status": (
                    "connected"
                    if credentials_configured
                    else ("needs_credentials" if import_available else "planned")
                ),
                "connection_hint": (
                    "Credentials are configured. Discovery can run without exposing token material."
                    if credentials_configured
                    else (
                        "Configure read-only provider credentials before running zone discovery."
                        if import_available
                        else "Provider is tracked for repair planning but is not import-ready yet."
                    )
                ),
                **{key: value for key, value in metadata.items() if key in metadata_keys},
            }
        )
    return DNSProviderCapabilitiesResponse(providers=provider_rows)


@router.get("/dns/import/{provider}/preview", response_model=DNSProviderImportPreviewResponse)
async def preview_dns_provider_domain_import(
    provider: str = Path(..., title="DNS provider ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Preview DNS-provider zones that can be imported as monitored domains."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        return await preview_dns_provider_import(
            db,
            provider=provider,
            workspace_id=workspace.id,
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post("/dns/import/{provider}", response_model=DNSProviderImportResponse)
async def import_dns_provider_domain_zones(
    payload: DNSProviderImportRequest,
    provider: str = Path(..., title="DNS provider ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Import selected, or all new, DNS-provider zones as monitored domains."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        return await import_dns_provider_domains(
            db,
            provider=provider,
            requested_domains=payload.domains,
            workspace_id=workspace.id,
        )
    except OrganizationPlanLimitError as exc:
        _raise_plan_limit_error(exc)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/mail-services/import/providers")
async def get_mail_service_import_providers(
    _auth: dict = Depends(require_admin_auth),
):
    """Return mail service providers that support sender-domain import."""
    return {"providers": supported_mail_service_import_providers()}


@router.get(
    "/mail-services/import/{provider}/preview",
    response_model=MailServiceImportPreviewResponse,
)
async def preview_mail_service_domain_import(
    provider: str = Path(..., title="Mail service provider ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Preview verified sender domains that can be imported as monitored domains."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        return await preview_mail_service_import(
            db,
            provider=provider,
            workspace_id=workspace.id,
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except MailServiceImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc


@router.post(
    "/mail-services/import/{provider}",
    response_model=MailServiceImportResponse,
)
async def import_mail_service_domain_senders(
    payload: MailServiceImportRequest,
    provider: str = Path(..., title="Mail service provider ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Import selected, or all new, mail service sender domains as monitored domains."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        return await import_mail_service_domains(
            db,
            provider=provider,
            requested_domains=payload.domains,
            workspace_id=workspace.id,
        )
    except OrganizationPlanLimitError as exc:
        _raise_plan_limit_error(exc)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except MailServiceImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc


# New endpoints for domain details page


@router.get("/{domain_id}/stats", response_model=DomainStatsResponse)
async def get_domain_stats(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Get detailed statistics for a specific domain
    """
    workspace = _authorized_domain_read_workspace(_auth, db)
    domain_name, store = _single_domain_report_store_for_read(db, domain_id, workspace)
    summary = store.get_domain_summary(domain_name)
    total_count = summary.get("total_count", 0)
    passed_count = summary.get("passed_count", 0)
    failed_count = total_count - passed_count
    compliance_rate = summary.get("compliance_rate", 0.0)
    reports_processed = summary.get("reports_processed", 0)

    return DomainStatsResponse(
        complianceRate=compliance_rate,
        totalEmails=total_count,
        failedEmails=failed_count,
        reportCount=reports_processed,
    )


@router.get("/{domain_id}/ownership", response_model=DomainOwnershipResponse)
async def get_domain_ownership(
    domain_id: str = Path(..., title="The domain ID or name"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return ownership proof instructions for a monitored domain."""
    workspace = _authorized_domain_read_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    domain_name = normalize_domain_name(domain_id)
    domain = workspace_domain_query(db, workspace).filter(Domain.name == domain_name).first()
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    token = _ensure_domain_verification_token(db, domain)
    return _domain_ownership_response(domain, token)


@router.post("/{domain_id}/ownership/verify", response_model=DomainOwnershipVerifyResponse)
async def verify_domain_ownership(
    domain_id: str = Path(..., title="The domain ID or name"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Check live DNS for the domain ownership TXT proof."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    domain_name = normalize_domain_name(domain_id)
    domain = workspace_domain_query(db, workspace).filter(Domain.name == domain_name).first()
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    token = _ensure_domain_verification_token(db, domain)
    expected = _ownership_record_value(token)
    record_name = _ownership_record_name(domain.name)
    try:
        observed = await get_default_provider(db).lookup_txt(record_name)
    except LookupError as exc:
        observed = []
        logger.info("Domain ownership TXT lookup failed for %s: %s", record_name, exc)

    matched = expected in {str(value).strip() for value in observed}
    if matched and not domain.verified:
        domain.verified = True
        db.commit()
        db.refresh(domain)

    response = _domain_ownership_response(domain, token)
    return DomainOwnershipVerifyResponse(
        **response.model_dump(),
        matched=matched,
        observed_values=[str(value) for value in observed],
    )


@router.post(
    "/{domain_id}/ownership/cloudflare",
    response_model=CloudflareOwnershipVerifyResponse,
)
async def verify_domain_ownership_with_cloudflare(
    domain_id: str = Path(..., title="The domain ID or name"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Verify a monitored domain through connected Cloudflare zone access."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        return await verify_cloudflare_domain_ownership(
            db,
            domain_name=normalize_domain_name(domain_id),
            workspace_id=workspace.id,
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": str(exc),
                "next_steps": [
                    "Connect Cloudflare from Settings, or use a scoped Cloudflare API token.",
                    "Make sure the connected Cloudflare account can list this domain's zone.",
                    "If the domain is not on Cloudflare, use the TXT ownership proof instead.",
                ],
            },
        ) from exc


@router.get("/{domain_id}/migration/readiness", response_model=MigrationReadinessResponse)
async def get_domain_migration_readiness(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return safe migration and data-portability readiness for one monitored domain."""
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    domain_name = _resolve_domain_name_for_read(db, store, domain_id, workspace)

    summary = store.get_domain_summary(domain_name)
    reports = store.get_domain_reports(domain_name, limit=10000)
    sources = store.get_domain_sources(domain_name)
    guidance_payload = await _build_domain_dns_guidance(db, store, domain_name, refresh=refresh)
    guidance = DNSGuidanceResponse(**guidance_payload)
    checklist, parallel_days = _build_migration_checklist(
        domain_name,
        summary,
        reports,
        sources,
        guidance,
    )
    migration_status, readiness_score = _migration_readiness_status(checklist)
    report_count = int(summary.get("reports_processed", 0) or len(reports))
    source_count = len(sources)
    summary_text = (
        f"{domain_name} has {parallel_days} distinct report days, "
        f"{report_count} aggregate reports, and {source_count} observed sending sources."
    )

    return MigrationReadinessResponse(
        domain=domain_name,
        status=migration_status,
        readiness_score=readiness_score,
        summary=summary_text,
        parallel_reporting_days=parallel_days,
        report_count=report_count,
        source_count=source_count,
        checklist=checklist,
        export_links=[
            MigrationExportLink(
                label="Aggregate report CSV",
                href=f"/api/v1/domains/{domain_name}/reports/export",
                format="csv",
                detail="Portable aggregate report summary for parity checks.",
            ),
            MigrationExportLink(
                label="Health evidence CSV",
                href=f"/api/v1/domains/{domain_name}/posture/evidence/export?capture_current=false",
                format="csv",
                detail="Score, policy, report, and DNS posture evidence.",
            ),
            MigrationExportLink(
                label="Health evidence JSON",
                href=(
                    f"/api/v1/domains/{domain_name}/posture/evidence/export"
                    "?capture_current=false&format=json"
                ),
                format="json",
                detail="Machine-readable portability packet for automation.",
            ),
            MigrationExportLink(
                label="Workspace health evidence",
                href="/api/v1/domains/summary/health/evidence/export?format=json",
                format="json",
                detail="Workspace-level health evidence for portfolio audit checks.",
            ),
            MigrationExportLink(
                label="DNS lint CSV",
                href="/api/v1/domains/dns/lint/export",
                format="csv",
                detail="Managed-domain DNS lint findings for cutover review.",
            ),
        ],
        supported_sources=[
            "Valimail",
            "EasyDMARC",
            "dmarcian",
            "PowerDMARC",
            "DMARCguard",
            "Manual mailbox exports",
        ],
    )


@router.get("/{domain_id}/migration/parity", response_model=MigrationParityResponse)
async def get_domain_migration_parity(
    domain_id: str = Path(..., title="The domain ID or name"),
    baseline_report_count: Optional[int] = Query(
        None, ge=0, title="Aggregate reports seen by the legacy platform"
    ),
    baseline_total_emails: Optional[int] = Query(
        None, ge=0, title="Messages seen by the legacy platform"
    ),
    baseline_source_count: Optional[int] = Query(
        None, ge=0, title="Sending sources seen by the legacy platform"
    ),
    baseline_compliance_rate: Optional[float] = Query(
        None, ge=0, le=100, title="Legacy DMARC alignment or compliance percentage"
    ),
    baseline_policy: Optional[str] = Query(
        None, title="DMARC p= policy reported by the legacy platform"
    ),
    tolerance_percent: float = Query(
        10.0, ge=0, le=100, title="Allowed percent delta before review is required"
    ),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Compare DMARQ evidence with an optional legacy-platform migration baseline."""
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    domain_name = _resolve_domain_name_for_read(db, store, domain_id, workspace)

    summary = store.get_domain_summary(domain_name)
    reports = store.get_domain_reports(domain_name, limit=10000)
    sources = store.get_domain_sources(domain_name)
    return _build_migration_parity_response(
        domain_name,
        summary,
        reports,
        sources,
        baseline_report_count=baseline_report_count,
        baseline_total_emails=baseline_total_emails,
        baseline_source_count=baseline_source_count,
        baseline_compliance_rate=baseline_compliance_rate,
        baseline_policy=baseline_policy,
        tolerance_percent=tolerance_percent,
    )


@router.post("/{domain_id}/migration/import/preview", response_model=MigrationImportPreviewResponse)
async def preview_domain_migration_import(
    payload: MigrationImportPreviewRequest,
    domain_id: str = Path(..., title="The domain ID or name"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Preview a historical DMARC export without writing reports or domains."""
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    domain_name = _resolve_domain_name_for_read(db, store, domain_id, workspace)
    domain_row = workspace_domain_query(db, workspace).filter(Domain.name == domain_name).first()
    existing_report_ids: List[str] = []
    if domain_row is not None:
        existing_report_ids = [
            row[0]
            for row in db.query(DMARCReport.report_id)
            .filter(DMARCReport.domain_id == domain_row.id)
            .distinct()
            .all()
            if row[0]
        ]

    try:
        content = (
            payload.content if isinstance(payload.content, str) else json.dumps(payload.content)
        )
        preview = preview_migration_import(
            domain=domain_name,
            content=content,
            source_format=payload.format,
            max_rows=payload.max_rows,
            existing_report_ids=existing_report_ids,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    status_text = "ready" if preview["normalized_count"] else "needs_mapping"
    next_steps = [
        "Use the suggested baseline values in Migration Parity for the same date window.",
        "Keep the old DMARC platform active until mismatches are explained.",
    ]
    if preview["warnings"]:
        next_steps.insert(0, "Review warnings before using this export for parity decisions.")

    return MigrationImportPreviewResponse(
        domain=domain_name,
        status=status_text,
        source_platform=payload.source_platform,
        format=preview["format"],
        row_count=preview["row_count"],
        normalized_count=preview["normalized_count"],
        ignored_count=preview["ignored_count"],
        rejected_count=preview["rejected_count"],
        truncated_count=preview["truncated_count"],
        importable_row_count=preview["importable_row_count"],
        planned_report_count=preview["planned_report_count"],
        existing_report_count=preview["existing_report_count"],
        duplicate_row_count=preview["duplicate_row_count"],
        needs_report_id_count=preview["needs_report_id_count"],
        batch_fingerprint=preview["batch_fingerprint"],
        detected_columns=preview["detected_columns"],
        mapped_columns=preview["mapped_columns"],
        warnings=preview["warnings"],
        baseline=MigrationImportBaseline(**preview["baseline"]),
        sample_rows=[MigrationImportPreviewRow(**row) for row in preview["sample_rows"]],
        next_steps=next_steps,
    )


@router.get("/{domain_id}/dns", response_model=DNSRecordResponse)
async def get_domain_dns_records(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Get DNS records for a specific domain using live DNS lookups.

    Manual selectors (stored in the database) are checked first, followed by
    selectors observed in stored DMARC reports, with common well-known
    selectors used as a final fallback.
    """
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)

    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    manual_selectors = _get_domain_selectors_from_db(db, domain_id)
    report_selectors = _get_selectors_from_reports(store, domain_id)
    combined_selectors = list(dict.fromkeys(manual_selectors + report_selectors))

    provider = get_default_provider(db)
    result, cached, checked_at = await resolve_domain_dns_cached(
        db,
        provider,
        domain_id,
        selectors=combined_selectors,
        refresh=refresh,
    )

    return DNSRecordResponse(
        dmarc=result.dmarc,
        dmarcRecord=result.dmarc_record,
        spf=result.spf,
        spfRecord=result.spf_record,
        dkim=result.dkim,
        dkimSelectors=result.dkim_selectors,
        cached=cached,
        checkedAt=checked_at.isoformat(),
        dmarcWarnings=result.dmarc_warnings,
        dmarcSuggestions=result.dmarc_suggestions,
        nameservers=result.nameservers,
        dnsProvider=asdict(result.dns_provider) if result.dns_provider else None,
        providerContext=_dns_provider_repair_context(
            db,
            dns_provider=asdict(result.dns_provider) if result.dns_provider else None,
            nameservers=result.nameservers,
        ),
        lookupStatus=result.lookup_status,
        lookupError=result.lookup_error,
    )


@router.get("/{domain_id}/dns/lint", response_model=DNSGuidanceResponse)
async def get_domain_dns_lint(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result"),
    locale: Optional[str] = Query(None, title="Operator guidance locale"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return typed DNS lint findings and target records for one monitored domain."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)

    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    return await _build_domain_dns_guidance(db, store, domain_id, refresh=refresh, locale=locale)


@router.get("/{domain_id}/dns/change-plan", response_model=DNSChangePlanResponse)
async def get_domain_dns_change_plan(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return read-only DNS change plans for one monitored domain."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)

    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    guidance = await _build_domain_dns_guidance(db, store, domain_id, refresh=refresh)
    available_providers = _ready_dns_write_provider_ids()
    recommended_provider = _recommended_dns_write_provider(
        guidance.get("dns_provider"),
        available_providers,
    )
    plans = []
    for plan in guidance["change_plans"]:
        provider_write_available = _dns_plan_provider_write_available(plan)
        plans.append(
            {
                **plan,
                "provider_write_available": provider_write_available,
                "safety_notes": _dns_plan_safety_notes(
                    plan,
                    provider_write_available=provider_write_available,
                ),
            }
        )
    return DNSChangePlanResponse(
        domain=guidance["domain"],
        status=guidance["status"],
        read_only=False,
        provider_write_available=bool(available_providers),
        dns_provider=guidance.get("dns_provider"),
        recommended_provider=recommended_provider,
        available_write_providers=available_providers,
        safety_notes=_dns_change_plan_safety_notes(
            recommended_provider=recommended_provider,
            available_providers=available_providers,
        ),
        apply_endpoint=f"/api/v1/domains/{domain_id}/dns/change-plan/apply",
        plans=plans,
    )


def _find_dns_change_plan(guidance: Dict[str, Any], plan_id: str) -> Dict[str, Any]:
    """Return one DNS change plan by ID or raise a 404."""
    for plan in guidance.get("change_plans") or []:
        if plan.get("plan_id") == plan_id:
            return plan
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"DNS change plan '{plan_id}' was not found",
    )


def _dns_write_rollback_guidance(plan: Dict[str, Any], result: Any) -> Dict[str, Any]:
    """Return manual rollback guidance for a prepared or applied DNS mutation."""
    mutation = result.mutation
    previous_values = list(mutation.current_values or [])
    summary = str(plan.get("rollback") or "").strip()
    if not summary:
        summary = "Review provider history and restore the previous DNS value if needed."

    if mutation.operation == "create":
        steps = [
            f"Open {mutation.provider} DNS for the zone that contains {mutation.name}.",
            f"Find the {mutation.record_type} record named {mutation.name}.",
            "Delete the created record only after confirming no legitimate sender depends on it.",
            "Refresh DMARQ DNS evidence and confirm the domain returns to the intended state.",
        ]
    elif mutation.operation == "update":
        if previous_values:
            steps = [
                f"Open {mutation.provider} DNS for the zone that contains {mutation.name}.",
                f"Edit the {mutation.record_type} record named {mutation.name}.",
                "Restore the previous value shown in DMARQ's rollback evidence.",
                "Refresh DMARQ DNS evidence and confirm the restored record is visible.",
            ]
        else:
            steps = [
                f"Open {mutation.provider} DNS for the zone that contains {mutation.name}.",
                f"Review provider history for the {mutation.record_type} record named {mutation.name}.",
                "Restore the last known-good value before this DMARQ repair.",
                "Refresh DMARQ DNS evidence and confirm the restored record is visible.",
            ]
    elif mutation.operation == "noop":
        summary = "No provider rollback is needed because no DNS mutation was applied."
        steps = [
            "No DNS record was created or updated by this operation.",
            "Keep the finding under observation and refresh DNS evidence if the provider changes.",
        ]
    else:
        steps = [
            "Review the provider change history before reverting this DNS record.",
            "Refresh DMARQ DNS evidence after any manual rollback.",
        ]

    return {
        "summary": summary,
        "steps": steps,
        "previous_values": previous_values,
        "record_type": mutation.record_type,
        "name": mutation.name,
        "provider": mutation.provider,
        "requires_manual_review": True,
    }


@router.post("/{domain_id}/dns/change-plan/apply", response_model=DNSWriteResultResponse)
async def apply_domain_dns_change_plan(
    request: Request,
    payload: DNSWriteApplyRequest,
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result before planning"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Preview or explicitly apply one provider-backed DNS change plan."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)

    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    guidance = await _build_domain_dns_guidance(db, store, domain_id, refresh=refresh)
    plan = _find_dns_change_plan(guidance, payload.plan_id)
    resolved_domain = guidance["domain"]
    available_providers = _ready_dns_write_provider_ids()
    detected_provider = _detected_dns_provider_id(guidance.get("dns_provider"))
    recommended_provider = _recommended_dns_write_provider(
        guidance.get("dns_provider"),
        available_providers,
    )
    provider_match_target = recommended_provider or detected_provider
    provider_mismatch_details = _dns_provider_mismatch_audit_details(
        requested_provider=payload.provider,
        recommended_provider=recommended_provider,
        detected_provider=detected_provider,
        allow_mismatch=payload.allow_provider_mismatch,
    )
    try:
        _ensure_dns_provider_selection_is_safe(
            requested_provider=payload.provider,
            provider_match_target=provider_match_target,
            allow_mismatch=payload.allow_provider_mismatch,
        )
        if payload.dry_run or not payload.confirm:
            if get_settings().DEMO_MODE:
                result = simulate_demo_dns_preview(
                    domain=resolved_domain,
                    plan=plan,
                    provider_id=payload.provider,
                    value_override=payload.value,
                    ttl=payload.ttl,
                )
            else:
                result = await preview_dns_write(
                    db,
                    domain=resolved_domain,
                    plan=plan,
                    provider_id=payload.provider,
                    value_override=payload.value,
                    ttl=payload.ttl,
                )
            result_payload = result.to_dict()
            result_payload["rollback"] = _dns_write_rollback_guidance(plan, result)
            safety_note = _provider_mismatch_safety_note(
                requested_provider=payload.provider,
                recommended_provider=recommended_provider,
                detected_provider=detected_provider,
                allow_mismatch=payload.allow_provider_mismatch,
            )
            if safety_note:
                result_payload["changes"].append(
                    {
                        "type": "safety_note",
                        "message": safety_note,
                    }
                )
            return result_payload

        if get_settings().DEMO_MODE:
            result = simulate_demo_dns_write(
                domain=resolved_domain,
                plan=plan,
                provider_id=payload.provider,
                value_override=payload.value,
                ttl=payload.ttl,
            )
        else:
            _require_verified_domain_for_dns_write(db, workspace, resolved_domain)
            result = await apply_dns_write(
                db,
                workspace=workspace,
                domain=resolved_domain,
                plan=plan,
                provider_id=payload.provider,
                value_override=payload.value,
                ttl=payload.ttl,
            )
    except DNSProviderWriteError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    rollback = _dns_write_rollback_guidance(plan, result)
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="domain.dns_change_applied",
        entity_type="domain",
        entity_name=domain_id,
        details={
            "provider": payload.provider,
            "plan_id": payload.plan_id,
            "mutation": result.mutation.to_dict(),
            "applied": result.applied,
            "verification": result.verification.to_dict(),
            "rollback": rollback,
            **provider_mismatch_details,
        },
        auth_context=_auth,
        request=request,
        commit=True,
    )
    result_payload = result.to_dict()
    result_payload["rollback"] = rollback
    return result_payload


@router.get("/{domain_id}/dns/health", response_model=DNSHealthResponse)
async def get_domain_dns_health(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return evidence-linked DNS health and enforcement readiness guidance."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    return await _build_domain_dns_health(db, store, domain_id, refresh=refresh)


@router.get("/{domain_id}/posture", response_model=PostureDashboardResponse)
async def get_domain_posture_dashboard(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS posture"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return an evidence-first posture dashboard for a monitored domain."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    health = await _build_domain_dns_health(db, store, domain_id, refresh=refresh)
    domain_health = await _build_domain_health_grade(
        db,
        domain_id,
        store,
        refresh=refresh,
    )
    summary = store.get_domain_summary(domain_id)
    if not get_settings().DEMO_MODE:
        _record_health_snapshot_from_posture(
            db,
            workspace_id=workspace.id,
            domain_id=domain_id,
            dns_health=health,
            domain_health=domain_health,
            report_count=int(summary.get("reports_processed", 0) or 0),
        )
    changes = list_dns_record_changes(db, domain_id, limit=10)
    return _build_posture_dashboard(domain_id, health, domain_health, changes)


async def _build_domain_remediation_queue_for_workspace(
    db: Session,
    *,
    workspace: Workspace,
    domain_id: str,
    refresh: bool = False,
) -> Dict[str, Any]:
    """Build the current remediation queue for an authorized workspace."""
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    try:
        domain_name = _resolve_domain_name_for_read(db, store, domain_id, workspace)
    except HTTPException as exc:
        if (
            exc.status_code != status.HTTP_404_NOT_FOUND
            or _stored_domain_exists(db, domain_id)
            or not _allows_legacy_report_only_fallback(db)
        ):
            raise
        hydrate_report_store_from_db(db, store)
        domain_name = _resolve_domain_name_for_read(db, store, domain_id, workspace)

    domain_health = await _build_domain_health_grade(
        db,
        domain_name,
        store,
        refresh=refresh,
    )
    guidance = await _build_domain_dns_guidance(db, store, domain_name, refresh=refresh)
    available_providers = _ready_dns_write_provider_ids()
    recommended_provider = _recommended_dns_write_provider(
        guidance.get("dns_provider"),
        available_providers,
    )
    return build_remediation_queue(
        domain=domain_name,
        health=domain_health,
        dns_guidance=guidance,
        available_write_providers=available_providers,
        recommended_provider=recommended_provider,
    )


@router.get("/{domain_id}/remediation", response_model=RemediationQueueResponse)
async def get_domain_remediation_queue(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS posture"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return a prioritized, human-reviewed remediation queue for one domain."""
    workspace = _authorized_domain_read_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    queue = await _build_domain_remediation_queue_for_workspace(
        db,
        workspace=workspace,
        domain_id=domain_id,
        refresh=refresh,
    )
    return attach_remediation_dispatch_previews(db, workspace=workspace, queue=queue)


@router.post(
    "/{domain_id}/remediation/notifications/audit",
    response_model=RemediationNotificationAuditResponse,
)
async def audit_domain_remediation_notification(
    request: Request,
    payload: RemediationNotificationAuditRequest,
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS posture"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Record a sanitized operator lifecycle marker without dispatching notifications."""
    lifecycle_state = payload.lifecycle_state.strip().lower()
    if lifecycle_state not in REMEDIATION_NOTIFICATION_LIFECYCLE_STATES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Unsupported lifecycle_state. Use one of: "
                + ", ".join(sorted(REMEDIATION_NOTIFICATION_LIFECYCLE_STATES))
            ),
        )

    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    queue = await _build_domain_remediation_queue_for_workspace(
        db,
        workspace=workspace,
        domain_id=domain_id,
        refresh=refresh,
    )
    queue = attach_remediation_dispatch_previews(db, workspace=workspace, queue=queue)
    item = next(
        (
            candidate
            for candidate in queue.get("items", [])
            if candidate.get("id") == payload.item_id
        ),
        None,
    )
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation item not found",
        )

    notification = item.get("notification") or {}
    event = str(notification.get("event") or "")
    dedupe_key = str(notification.get("dedupe_key") or "")
    if payload.event is not None and payload.event != event:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Notification event does not match the current remediation item",
        )
    if payload.dedupe_key is not None and payload.dedupe_key != dedupe_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Notification dedupe_key does not match the current remediation item",
        )

    automation = item.get("automation") or {}
    audit_row = record_workspace_audit_log(
        db,
        workspace=workspace,
        action="remediation.notification_lifecycle_recorded",
        entity_type="remediation_notification",
        entity_id=item.get("id"),
        entity_name=queue.get("domain"),
        details={
            "item_id": item.get("id"),
            "domain": queue.get("domain"),
            "event": event,
            "dedupe_key": dedupe_key,
            "lifecycle_state": lifecycle_state,
            "notification_state": notification.get("state"),
            "notification_channel": notification.get("channel"),
            "notification_next_transition": notification.get("next_transition"),
            "source": item.get("source"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "automation_eligible": automation.get("eligible"),
            "automation_provider": automation.get("provider"),
            "automation_plan_id": automation.get("plan_id"),
            "payload_preview": notification.get("payload_preview") or {},
            "operator_note": payload.note,
            "sent": False,
            "delivery_enqueued": False,
            "dns_write_attempted": False,
        },
        auth_context=_auth,
        request=request,
        commit=True,
    )
    return {
        "domain": str(queue.get("domain") or domain_id),
        "item_id": str(item.get("id") or payload.item_id),
        "event": event,
        "dedupe_key": dedupe_key,
        "lifecycle_state": lifecycle_state,
        "audit": audit_log_to_dict(audit_row),
    }


def _remediation_dispatch_idempotency_key(event: str, dedupe_key: str) -> str:
    """Return a bounded idempotency key for explicit remediation dispatch."""
    digest = hashlib.sha256(f"{event}:{dedupe_key}".encode("utf-8")).hexdigest()[:32]
    return f"remediation-dispatch:{digest}"


@router.post(
    "/{domain_id}/remediation/notifications/dispatch",
    response_model=RemediationNotificationDispatchResponse,
)
async def dispatch_domain_remediation_notification(
    request: Request,
    payload: RemediationNotificationDispatchRequest,
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS posture"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Enqueue an explicitly approved remediation notification for webhook delivery."""
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Set confirm=true to enqueue remediation notification delivery.",
        )

    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    queue = await _build_domain_remediation_queue_for_workspace(
        db,
        workspace=workspace,
        domain_id=domain_id,
        refresh=refresh,
    )
    queue = attach_remediation_dispatch_previews(db, workspace=workspace, queue=queue)
    item = next(
        (
            candidate
            for candidate in queue.get("items", [])
            if candidate.get("id") == payload.item_id
        ),
        None,
    )
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation item not found",
        )

    notification = item.get("notification") or {}
    event = str(notification.get("event") or "")
    dedupe_key = str(notification.get("dedupe_key") or "")
    if payload.event is not None and payload.event != event:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Notification event does not match the current remediation item",
        )
    if payload.dedupe_key is not None and payload.dedupe_key != dedupe_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Notification dedupe_key does not match the current remediation item",
        )

    dispatch_preview = notification.get("dispatch") or {}
    if not dispatch_preview.get("eligible"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "Remediation notification is not dispatch-ready.",
                "blocked_reasons": dispatch_preview.get("blocked_reasons") or [],
                "next_steps": dispatch_preview.get("next_steps") or [],
            },
        )

    notification_payload = notification.get("payload_preview") or {}
    deliveries = enqueue_webhook_event(
        db,
        event_type=event,
        payload=notification_payload,
        idempotency_key=_remediation_dispatch_idempotency_key(event, dedupe_key),
        workspace_id=workspace.id,
    )
    delivery_rows = [delivery_to_dict(delivery) for delivery in deliveries]
    automation = item.get("automation") or {}
    audit_row = record_workspace_audit_log(
        db,
        workspace=workspace,
        action="remediation.notification_dispatch_enqueued",
        entity_type="remediation_notification",
        entity_id=item.get("id"),
        entity_name=queue.get("domain"),
        details={
            "item_id": item.get("id"),
            "domain": queue.get("domain"),
            "event": event,
            "dedupe_key": dedupe_key,
            "notification_state": notification.get("state"),
            "notification_channel": notification.get("channel"),
            "notification_next_transition": notification.get("next_transition"),
            "source": item.get("source"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "automation_eligible": automation.get("eligible"),
            "automation_provider": automation.get("provider"),
            "automation_plan_id": automation.get("plan_id"),
            "payload_preview": notification_payload,
            "operator_note": payload.note,
            "sent": False,
            "delivery_enqueued": bool(delivery_rows),
            "delivery_count": len(delivery_rows),
            "deliveries": delivery_rows,
            "dns_write_attempted": False,
        },
        auth_context=_auth,
        request=request,
        commit=True,
    )

    dispatch_response = {
        **dispatch_preview,
        "delivery_enqueued": bool(delivery_rows),
        "delivery_count": len(delivery_rows),
    }
    return {
        "domain": str(queue.get("domain") or domain_id),
        "item_id": str(item.get("id") or payload.item_id),
        "event": event,
        "dedupe_key": dedupe_key,
        "delivery_enqueued": bool(delivery_rows),
        "delivery_count": len(delivery_rows),
        "deliveries": delivery_rows,
        "dispatch": dispatch_response,
        "audit": audit_log_to_dict(audit_row),
    }


@router.get("/{domain_id}/posture/history", response_model=HealthScoreHistoryResponse)
async def get_domain_health_score_history(
    domain_id: str = Path(..., title="The domain ID or name"),
    start_date: Optional[date] = Query(None, title="Start date for score history"),
    end_date: Optional[date] = Query(None, title="End date for score history"),
    limit: int = Query(120, ge=1, le=400, title="Maximum history points"),
    capture_current: bool = Query(True, title="Capture today's current posture first"),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return persisted score history for one domain."""
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_date must be on or before end_date",
        )
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = _authorized_domain_read_workspace(_auth, db, selected_workspace_id)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    if capture_current and not get_settings().DEMO_MODE:
        health = await _build_domain_dns_health(db, store, domain_id)
        domain_health = await _build_domain_health_grade(db, domain_id, store)
        summary = store.get_domain_summary(domain_id)
        _record_health_snapshot_from_posture(
            db,
            workspace_id=workspace.id,
            domain_id=domain_id,
            dns_health=health,
            domain_health=domain_health,
            report_count=int(summary.get("reports_processed", 0) or 0),
        )

    snapshots = list_health_score_snapshots(
        db,
        workspace_id=workspace.id,
        domain_name=domain_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
    )
    if not snapshots and get_settings().DEMO_MODE:
        return _history_response_from_points(
            domain_id,
            _demo_history_points(
                domain_id,
                start_date=start_date,
                end_date=end_date,
                limit=limit,
            ),
        )
    return HealthScoreHistoryResponse(
        **build_health_score_history(domain_name=domain_id, snapshots=snapshots)
    )


@router.get("/{domain_id}/posture/evidence/export")
async def export_domain_health_evidence(
    domain_id: str = Path(..., title="The domain ID or name"),
    start_date: Optional[date] = Query(None, title="Start date for evidence export"),
    end_date: Optional[date] = Query(None, title="End date for evidence export"),
    limit: int = Query(400, ge=1, le=1000, title="Maximum exported snapshots"),
    capture_current: bool = Query(True, title="Capture today's current posture first"),
    export_format: str = Query(
        "csv",
        alias="format",
        pattern="^(csv|json)$",
        title="Evidence export format",
    ),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Export sanitized health score evidence for one domain as CSV or JSON."""
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    rows = await build_domain_health_evidence_export_rows(
        domain_id=domain_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        capture_current=capture_current,
        db=db,
        auth_context=_auth,
        selected_workspace_id=selected_workspace_id,
    )
    return _write_health_evidence_export(
        rows,
        export_id=domain_id,
        scope="domain",
        export_format=export_format,
    )


@router.get("/{domain_id}/dns/mta-sts", response_model=MTAStsResponse)
async def get_domain_mta_sts(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached MTA-STS result"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return cached MTA-STS DNS and HTTPS policy posture for a domain."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    result, cached, checked_at = await check_mta_sts_cached(
        db,
        get_default_provider(db),
        domain_id,
        refresh=refresh,
    )
    return MTAStsResponse(
        status=result.status,
        dns_record=result.dns_record,
        policy_url=result.policy_url,
        policy_text=result.policy_text,
        mode=result.mode,
        max_age=result.max_age,
        mx=result.mx,
        errors=result.errors,
        warnings=result.warnings,
        cached=cached,
        checked_at=checked_at.isoformat(),
    )


@router.get("/{domain_id}/dns/bimi", response_model=BIMIResponse)
async def get_domain_bimi(
    domain_id: str = Path(..., title="The domain ID or name"),
    selector: str = Query("default", title="BIMI selector"),
    refresh: bool = Query(False, title="Refresh cached BIMI result"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return cached BIMI DNS posture for a domain."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    result, cached, checked_at = await check_bimi_cached(
        db,
        get_default_provider(db),
        domain_id,
        selector=selector,
        refresh=refresh,
    )
    return BIMIResponse(
        status=result.status,
        selector=result.selector,
        query_name=result.query_name,
        dns_record=result.dns_record,
        logo_url=result.logo_url,
        certificate_url=result.certificate_url,
        evidence_url=result.evidence_url,
        errors=result.errors,
        warnings=result.warnings,
        cached=cached,
        checked_at=checked_at.isoformat(),
    )


@router.get("/{domain_id}/dns/dane", response_model=DANEResponse)
async def get_domain_dane(
    domain_id: str = Path(..., title="The domain ID or name"),
    port: int = Query(25, ge=1, le=65535, title="SMTP service port for TLSA lookup"),
    refresh: bool = Query(False, title="Refresh cached DANE result"),
    derive_suggestions: bool = Query(
        False,
        title="Derive live SMTP STARTTLS TLSA suggestions",
    ),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return cached DANE/TLSA posture for a domain's MX hosts."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    result, cached, checked_at = await check_dane_cached(
        db,
        get_default_provider(db),
        domain_id,
        port=port,
        refresh=refresh,
        derive_suggestions=derive_suggestions,
    )
    return DANEResponse(
        status=result.status,
        port=result.port,
        mx_hosts=result.mx_hosts,
        records=[TLSARecordResponse(**asdict(record)) for record in result.records],
        suggested_records=[
            TLSASuggestionResponse(**asdict(suggestion)) for suggestion in result.suggested_records
        ],
        errors=result.errors,
        warnings=result.warnings,
        cached=cached,
        checked_at=checked_at.isoformat(),
    )


@router.get("/cloudflare/discover", response_model=List[CloudflareZoneResponse])
async def discover_cloudflare_domains(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Discover active Cloudflare zones visible to the configured API token."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        return await discover_cloudflare_zones(db, workspace_id=workspace.id)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/cloudflare/oauth/status", response_model=CloudflareOAuthStatusResponse)
async def get_cloudflare_oauth_status(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return Cloudflare connector status without exposing token material."""
    auth_mode = _setting_value(db, "cloudflare.auth_mode")
    token_row = db.query(Setting).filter(Setting.key == "cloudflare.api_token").first()
    return CloudflareOAuthStatusResponse(
        oauth_configured=cloudflare_oauth_configured(),
        connected=bool(token_row and token_row.value),
        auth_mode=auth_mode,
        scopes=_setting_value(db, "cloudflare.oauth_scopes"),
        scope_profile=normalize_cloudflare_scope_profile(
            _setting_value(db, "cloudflare.oauth_scope_profile")
        ),
        scope_profiles=cloudflare_scope_profile_metadata(),
        connected_at=_setting_value(db, "cloudflare.oauth_connected_at"),
    )


@router.get("/cloudflare/oauth/authorize-url", response_model=CloudflareOAuthAuthorizeResponse)
async def get_cloudflare_oauth_authorize_url(
    request: Request,
    return_to: str = Query("/settings", title="Path to return to after OAuth"),
    scope_profile: str = Query(
        "read_only",
        title="Cloudflare OAuth rights profile",
        description="read_only, read_only_radar, or full_dns_repair",
    ),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return the Cloudflare OAuth authorization URL for DNS provider access."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    redirect_uri = f"{_public_base_url(request, db)}/api/v1/domains/cloudflare/oauth/callback"
    normalized_profile = normalize_cloudflare_scope_profile(scope_profile)
    try:
        payload = build_cloudflare_authorization_url(
            redirect_uri=redirect_uri,
            state=build_cloudflare_oauth_state(
                workspace_id=workspace.id,
                return_to=return_to,
                scope_profile=normalized_profile,
            ),
            scope_profile=normalized_profile,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return CloudflareOAuthAuthorizeResponse(**payload)


@router.get("/cloudflare/oauth/callback")
async def cloudflare_oauth_callback(
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Handle the Cloudflare OAuth redirect and store the scoped access token."""
    from fastapi.responses import HTMLResponse, RedirectResponse

    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")
    code = request.query_params.get("code")
    state_value = request.query_params.get("state")
    if error or not code or not state_value:
        details = ""
        if error:
            safe_error = html.escape(error)
            safe_description = html.escape(error_description or "")
            details = f"<p><strong>Cloudflare error:</strong> {safe_error}</p>"
            if safe_description:
                details += f"<p>{safe_description}</p>"
            if error == "invalid_scope":
                profile_id = "read_only"
                try:
                    profile_id = decode_cloudflare_oauth_state(state_value or "").get(
                        "scope_profile", "read_only"
                    )
                except LookupError:
                    profile_id = "read_only"
                profile = next(
                    (
                        item
                        for item in cloudflare_scope_profile_metadata()
                        if item.get("id") == profile_id
                    ),
                    {},
                )
                permission_items = "".join(
                    f"<li>{html.escape(str(permission))}</li>"
                    for permission in profile.get("required_permissions", [])
                )
                requested_scopes = html.escape(cloudflare_scopes_for_profile(profile_id))
                retry_href = "/settings?cloudflare_scope_profile=read_only&cloudflare_retry=1"
                details += (
                    "<p>The selected rights profile requests a scope that this Cloudflare "
                    "OAuth client is not allowed to request. Choose a lower rights profile "
                    "or update the allowed scopes on the Cloudflare OAuth client.</p>"
                    f"<p><strong>Selected profile:</strong> {html.escape(profile_id)}</p>"
                    f"<p><strong>Requested scopes:</strong> <code>{requested_scopes}</code></p>"
                    '<p><a href="'
                    f"{html.escape(retry_href)}"
                    '">Retry with read-only Cloudflare access</a></p>'
                )
                if permission_items:
                    details += (
                        "<p>Allow these permissions on the Cloudflare OAuth client, then retry:</p>"
                        f"<ul>{permission_items}</ul>"
                    )
        return HTMLResponse(
            content=(
                "<html><body><p>Cloudflare connection failed. "
                "Please close this window or tab and try again from DMARQ settings.</p>"
                f"{details}</body></html>"
            ),
            status_code=400,
        )

    try:
        state_payload = decode_cloudflare_oauth_state(state_value)
        _authorized_domain_workspace(_auth, db, selected_workspace_id=state_payload["workspace_id"])
        redirect_uri = f"{_public_base_url(request, db)}/api/v1/domains/cloudflare/oauth/callback"
        token_data = await exchange_cloudflare_oauth_code(
            code=code,
            redirect_uri=redirect_uri,
        )
        persist_cloudflare_oauth_tokens(
            db,
            token_data,
            scope_profile=state_payload.get("scope_profile"),
        )
    except LookupError as exc:
        logger.info("Cloudflare OAuth callback failed: %s", exc)
        return HTMLResponse(
            content=(
                "<html><body><p>Cloudflare connection failed. "
                "Please close this window or tab and retry after checking the connector settings."
                "</p></body></html>"
            ),
            status_code=400,
        )

    return RedirectResponse(url=state_payload.get("return_to") or "/settings", status_code=303)


@router.post("/cloudflare/import", response_model=CloudflareImportResponse)
async def import_cloudflare_domain_zones(
    payload: CloudflareImportRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Import selected, or all, Cloudflare zones as monitored domains."""
    workspace = _authorized_domain_workspace(
        _auth,
        db,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        return await import_cloudflare_domains(
            db,
            requested_domains=payload.domains,
            workspace_id=workspace.id,
        )
    except OrganizationPlanLimitError as exc:
        _raise_plan_limit_error(exc)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/{domain_id}/dns/cloudflare", response_model=CloudflareDNSAnalysisResponse)
async def get_cloudflare_domain_dns_analysis(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Analyze Cloudflare-managed DNS records and persist detected changes."""
    _authorized_domain_workspace(_auth, db)
    try:
        zone_data = await get_zone_for_domain(db, domain_id)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    records = zone_data["records"]
    changes = sync_dns_record_changes(
        db,
        domain=domain_id,
        zone_id=zone_data["id"],
        records=records,
    )
    analysis = analyze_dns_records(domain_id, records)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    analysis["suggestions"].extend(
        _policy_enforcement_suggestions(
            analysis["checks"].get("dmarc_policy"),
            store.get_domain_summary(domain_id),
        )
    )
    history = list_dns_record_changes(db, domain_id)
    return CloudflareDNSAnalysisResponse(
        zone={"id": zone_data["id"], "name": zone_data["name"]},
        records=analysis["records"],
        checks=analysis["checks"],
        suggestions=analysis["suggestions"],
        changes=changes,
        history=history,
    )


@router.get("/{domain_id}/dns/history", response_model=DNSChangeHistoryResponse)
async def get_domain_dns_change_history(
    domain_id: str = Path(..., title="The domain ID or name"),
    limit: int = Query(50, title="Maximum number of change events to return"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return recent provider-backed DNS record changes for a domain."""
    _authorized_domain_workspace(_auth, db)
    return DNSChangeHistoryResponse(history=list_dns_record_changes(db, domain_id, limit=limit))


@router.get("/{domain_id}/reports", response_model=DomainReportsResponse)
async def get_domain_reports(
    domain_id: str = Path(..., title="The domain ID or name"),
    limit: int = Query(10, title="Maximum number of reports to return"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Get recent DMARC reports for a specific domain, along with compliance timeline
    """
    workspace = _authorized_domain_read_workspace(_auth, db)
    domain_name, store = _single_domain_report_store_for_read(db, domain_id, workspace)

    # Get reports for this domain
    reports = store.get_domain_reports(domain_name, limit=limit)

    # Generate report entries
    report_entries = []
    for report in reports:
        summary = report.get("summary") or {}
        policy_val = report.get("policy", "none")
        if isinstance(policy_val, dict):
            policy_val = policy_val.get("p", "none")
        report_entries.append(
            ReportEntry(
                id=report.get("report_id", "unknown"),
                org_name=report.get("org_name", "Unknown Organization"),
                begin_date=report.get("begin_timestamp", 0),
                end_date=report.get("end_timestamp", 0),
                total_emails=summary.get("total_count", report.get("total_count", 0)),
                pass_rate=summary.get("pass_rate", report.get("pass_rate", 0.0)),
                policy=policy_val,
            )
        )

    # Build compliance timeline from actual report data
    timeline = _build_compliance_timeline(store, domain_name)

    return DomainReportsResponse(reports=report_entries, compliance_timeline=timeline)


@router.get("/{domain_id}/reports/export")
async def export_domain_reports(
    domain_id: str = Path(..., title="The domain ID or name"),
    start_date: Optional[date] = Query(None, title="Start date for exported reports"),
    end_date: Optional[date] = Query(None, title="End date for exported reports"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Export DMARC report summaries for a specific domain as CSV.
    """
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_date must be on or before end_date",
        )

    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)

    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    reports = [
        report
        for report in store.get_domain_reports(domain_id, limit=10000)
        if _report_in_export_range(report, start_date, end_date)
    ]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "domain",
            "report_id",
            "org_name",
            "begin_date",
            "end_date",
            "total_emails",
            "passed",
            "failed",
            "pass_rate",
            "policy",
            "subdomain_policy",
            "non_subdomain_policy",
            "adkim",
            "aspf",
            "failure_options",
            "testing",
            "discovery_method",
            "schema_version",
            "report_variant",
            "generator",
        ]
    )

    for report in reports:
        summary = report.get("summary", {})
        total = int(summary.get("total_count", report.get("total_count", 0)) or 0)
        passed = int(summary.get("passed_count", report.get("passed_count", 0)) or 0)
        failed = int(summary.get("failed_count", report.get("failed_count", 0)) or 0)
        policy = report.get("policy", "none")
        policy_parts = policy if isinstance(policy, dict) else {}
        if isinstance(policy, dict):
            policy = policy.get("p", "none")
        writer.writerow(
            [
                domain_id,
                report.get("report_id", "unknown"),
                report.get("org_name", "Unknown Organization"),
                _format_report_date(report.get("begin_timestamp") or report.get("begin_date")),
                _format_report_date(report.get("end_timestamp") or report.get("end_date")),
                total,
                passed,
                failed,
                report.get("pass_rate", 0.0),
                policy,
                policy_parts.get("sp", ""),
                policy_parts.get("np", ""),
                policy_parts.get("adkim", ""),
                policy_parts.get("aspf", ""),
                policy_parts.get("fo", ""),
                policy_parts.get("testing", ""),
                policy_parts.get("discovery_method", ""),
                report.get("schema_version", ""),
                report.get("variant", ""),
                report.get("generator", ""),
            ]
        )

    filename = f"{domain_id.replace('/', '_')}-dmarc-reports.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _build_compliance_timeline(store: ReportStore, domain: str) -> List[TimelinePoint]:
    """
    Build a compliance timeline from actual report data stored in ReportStore.

    Groups reports by date and calculates the pass rate per day to provide
    real historical trend data for the compliance chart.
    """
    all_reports = store.get_domain_reports(domain)

    # Aggregate report data by date
    daily_data: Dict[str, Dict[str, int]] = {}
    for report in all_reports:
        # Use begin_date to determine the day of this report
        begin = report.get("begin_date", 0)
        if isinstance(begin, (int, float)) and begin > 0:
            date_str = datetime.fromtimestamp(begin, tz=timezone.utc).strftime("%Y-%m-%d")
        elif isinstance(begin, str):
            # Handle ISO-format strings
            try:
                date_str = datetime.fromisoformat(begin).strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                continue
        else:
            continue

        if date_str not in daily_data:
            daily_data[date_str] = {"total": 0, "passed": 0, "failed": 0}

        summary = report.get("summary", {})
        total = summary.get("total_count", 0)
        passed = summary.get("passed_count", 0)
        failed = summary.get("failed_count", max(0, total - passed))
        daily_data[date_str]["total"] += total
        daily_data[date_str]["passed"] += passed
        daily_data[date_str]["failed"] += failed

    # Convert to timeline points sorted by date
    timeline = []
    for date_str in sorted(daily_data.keys()):
        data = daily_data[date_str]
        total = data["total"]
        compliance_rate = round((data["passed"] / total) * 100, 1) if total > 0 else 0.0
        failure_rate = round((data["failed"] / total) * 100, 1) if total > 0 else 0.0
        timeline.append(
            TimelinePoint(
                date=date_str,
                total=total,
                volume=total,
                passed=data["passed"],
                failed=data["failed"],
                compliance_rate=compliance_rate,
                failure_rate=failure_rate,
            )
        )

    return timeline


def _report_in_export_range(
    report: Dict[str, Any], start_date: Optional[date], end_date: Optional[date]
) -> bool:
    report_date = _report_date(report.get("begin_timestamp") or report.get("begin_date"))
    if report_date is None:
        return False
    if start_date and report_date < start_date:
        return False
    if end_date and report_date > end_date:
        return False
    return True


def _report_date(value: Any) -> Optional[date]:
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value, tz=timezone.utc).date()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).date()
        except (ValueError, TypeError):
            return None
    return None


def _format_report_date(value: Any) -> str:
    report_date = _report_date(value)
    return report_date.isoformat() if report_date else ""


def _migration_item(
    key: str,
    status_value: str,
    title: str,
    detail: str,
    action: str,
    evidence: Optional[List[str]] = None,
    href: Optional[str] = None,
) -> MigrationReadinessItem:
    return MigrationReadinessItem(
        key=key,
        status=status_value,
        title=title,
        detail=detail,
        action=action,
        evidence=evidence or [],
        href=href,
    )


def _migration_readiness_status(items: List[MigrationReadinessItem]) -> tuple[str, int]:
    if not items:
        return "blocked", 0
    complete = sum(1 for item in items if item.status == "complete")
    score = round((complete / len(items)) * 100)
    if complete == len(items):
        return "ready", score
    if any(item.status == "complete" for item in items):
        return "in_progress", score
    return "blocked", score


def _parallel_reporting_days(reports: List[Dict[str, Any]]) -> int:
    dates = {
        report_date
        for report in reports
        if (report_date := _report_date(report.get("begin_timestamp") or report.get("begin_date")))
    }
    return len(dates)


def _build_migration_checklist(
    domain_id: str,
    summary: Dict[str, Any],
    reports: List[Dict[str, Any]],
    sources: List[Dict[str, Any]],
    guidance: DNSGuidanceResponse,
) -> tuple[List[MigrationReadinessItem], int]:
    report_count = int(summary.get("reports_processed", 0) or len(reports))
    total_emails = int(summary.get("total_count", 0) or 0)
    source_count = len(sources)
    parallel_days = _parallel_reporting_days(reports)
    dns_finding_count = len(guidance.findings)

    reporting_status = "complete" if report_count > 0 else "blocked"
    volume_status = (
        "complete" if parallel_days >= 14 else ("in_progress" if report_count else "blocked")
    )
    source_status = (
        "complete" if source_count > 0 else ("in_progress" if report_count else "blocked")
    )
    dns_status = (
        "complete" if dns_finding_count == 0 else ("in_progress" if report_count else "blocked")
    )
    export_status = "complete" if report_count > 0 else "blocked"

    return [
        _migration_item(
            "parallel-reporting",
            reporting_status,
            "Run DMARQ alongside the current platform",
            "Keep the existing DMARC tool in place and add DMARQ as an additional rua target.",
            "Publish a DMARC record that sends aggregate reports to both systems.",
            [f"{report_count} reports received", f"{total_emails} messages observed"],
            "#dns-guidance",
        ),
        _migration_item(
            "volume-parity",
            volume_status,
            "Build 14-30 days of report evidence",
            "Use the overlap window to observe report volume, sender inventory, and policy results.",
            "Wait for at least 14 distinct report days before removing the old tool.",
            [f"{parallel_days} distinct report days", f"{report_count} reports processed"],
            "#compliance-chart-section",
        ),
        _migration_item(
            "sender-parity",
            source_status,
            "Review observed sending sources",
            "Observed senders should be reviewed against the current platform before cutover.",
            "Investigate unknown or failing sources before tightening policy or removing old routing.",
            [f"{source_count} sending sources observed"],
            "#sending-sources",
        ),
        _migration_item(
            "dns-readiness",
            dns_status,
            "Clear DNS posture blockers",
            "DMARC, SPF, DKIM, and reporting authorization findings should be understood before cutover.",
            "Resolve critical DNS lint findings or document why they are intentionally deferred.",
            [f"{dns_finding_count} DNS lint findings", f"DNS status: {guidance.status}"],
            "#dns-guidance",
        ),
        _migration_item(
            "portability-export",
            export_status,
            "Confirm export and rollback path",
            "DMARQ keeps aggregate report and score evidence exportable for audit or offboarding.",
            "Download report CSV and health evidence before decommissioning the previous platform.",
            ["CSV reports export", "CSV or JSON health evidence export"],
            "#recent-reports",
        ),
    ], parallel_days


def _format_parity_value(value: Any, unit: str) -> str:
    if value is None:
        return "Not provided"
    if unit == "percent":
        return f"{float(value):.1f}%"
    if unit == "policy":
        return str(value)
    return f"{int(value):,}"


def _numeric_parity_metric(
    key: str,
    label: str,
    dmarq_value: int | float,
    baseline_value: Optional[int | float],
    unit: str,
    tolerance_percent: float,
) -> MigrationParityMetric:
    if baseline_value is None:
        return MigrationParityMetric(
            key=key,
            label=label,
            status="baseline_needed",
            unit=unit,
            dmarq_value=dmarq_value,
            dmarq_display=_format_parity_value(dmarq_value, unit),
            detail="Add the legacy-platform value to compare this migration signal.",
        )

    if unit == "percent":
        delta = round(float(dmarq_value) - float(baseline_value), 2)
        matched = abs(delta) <= tolerance_percent
    elif baseline_value == 0:
        delta = 0.0 if dmarq_value == 0 else 100.0
        matched = dmarq_value == 0
    else:
        delta = round(
            ((float(dmarq_value) - float(baseline_value)) / float(baseline_value)) * 100, 2
        )
        matched = abs(delta) <= tolerance_percent

    return MigrationParityMetric(
        key=key,
        label=label,
        status="matched" if matched else "attention",
        unit=unit,
        dmarq_value=dmarq_value,
        dmarq_display=_format_parity_value(dmarq_value, unit),
        baseline_value=baseline_value,
        baseline_display=_format_parity_value(baseline_value, unit),
        delta=delta,
        detail=(
            "Within the migration tolerance."
            if matched
            else "Review the legacy export and DMARQ ingestion before cutover."
        ),
    )


def _policy_parity_metric(
    dmarq_policy: Optional[str],
    baseline_policy: Optional[str],
) -> MigrationParityMetric:
    normalized_dmarq = (dmarq_policy or "unknown").lower()
    normalized_baseline = baseline_policy.lower() if baseline_policy else None
    if normalized_baseline is None:
        status_value = "baseline_needed"
        detail = "Add the legacy-platform DMARC policy to compare policy posture."
    elif normalized_dmarq == normalized_baseline:
        status_value = "matched"
        detail = "DMARQ and the legacy platform report the same DMARC policy."
    else:
        status_value = "attention"
        detail = "Policy differs from the legacy baseline; review DNS and report timing."

    return MigrationParityMetric(
        key="policy",
        label="DMARC policy",
        status=status_value,
        unit="policy",
        dmarq_value=normalized_dmarq,
        dmarq_display=_format_parity_value(normalized_dmarq, "policy"),
        baseline_value=normalized_baseline,
        baseline_display=_format_parity_value(normalized_baseline, "policy"),
        detail=detail,
    )


def _build_migration_parity_response(
    domain_id: str,
    summary: Dict[str, Any],
    reports: List[Dict[str, Any]],
    sources: List[Dict[str, Any]],
    *,
    baseline_report_count: Optional[int],
    baseline_total_emails: Optional[int],
    baseline_source_count: Optional[int],
    baseline_compliance_rate: Optional[float],
    baseline_policy: Optional[str],
    tolerance_percent: float,
) -> MigrationParityResponse:
    report_count = int(summary.get("reports_processed", 0) or len(reports))
    total_emails = int(summary.get("total_count", 0) or 0)
    source_count = len(sources)
    compliance_rate = float(summary.get("compliance_rate", 0.0) or 0.0)
    dmarq_policy = _normalize_reported_policy(summary.get("policy"))
    metrics = [
        _numeric_parity_metric(
            "reports",
            "Aggregate reports",
            report_count,
            baseline_report_count,
            "count",
            tolerance_percent,
        ),
        _numeric_parity_metric(
            "messages",
            "Message volume",
            total_emails,
            baseline_total_emails,
            "count",
            tolerance_percent,
        ),
        _numeric_parity_metric(
            "sources",
            "Sending sources",
            source_count,
            baseline_source_count,
            "count",
            tolerance_percent,
        ),
        _numeric_parity_metric(
            "alignment",
            "Alignment rate",
            compliance_rate,
            baseline_compliance_rate,
            "percent",
            tolerance_percent,
        ),
        _policy_parity_metric(dmarq_policy, baseline_policy),
    ]
    baseline_required = any(metric.status == "baseline_needed" for metric in metrics)
    attention_required = any(metric.status == "attention" for metric in metrics)
    if baseline_required:
        status_value = "baseline_needed"
        summary_text = (
            "Add baseline values from the current DMARC platform to compare cutover parity."
        )
    elif attention_required:
        status_value = "attention"
        summary_text = "Some migration parity signals differ from the legacy-platform baseline."
    else:
        status_value = "matched"
        summary_text = "DMARQ evidence is within tolerance of the legacy-platform baseline."

    next_steps = [
        "Export the same date window from the current DMARC platform.",
        "Compare aggregate reports, message volume, sending sources, alignment, and policy.",
        "Keep dual rua reporting active until differences are resolved or documented.",
    ]
    if attention_required:
        next_steps.insert(0, "Review attention metrics before removing legacy reporting routes.")

    return MigrationParityResponse(
        domain=domain_id,
        status=status_value,
        summary=summary_text,
        baseline_required=baseline_required,
        tolerance_percent=tolerance_percent,
        metrics=metrics,
        next_steps=next_steps,
    )


def _spf_fix_hint(ip: str, spf_result: str, failed_count: int = 0) -> Optional[str]:
    """Return a copy-paste SPF mechanism (e.g. ``ip4:1.2.3.4``) for a failing IP.

    Returns ``None`` when SPF did not fail or when *ip* is not a valid address.
    """
    if spf_result != "fail" and failed_count <= 0:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        prefix = "ip6" if isinstance(addr, ipaddress.IPv6Address) else "ip4"
        return f"{prefix}:{ip}"
    except ValueError:
        return None


def _allow_direct_spf_ip_hint(sender: Optional[Dict[str, Any]]) -> bool:
    """Return whether a raw ip4/ip6 SPF mechanism is safe to suggest.

    Commercial senders and forwarders often use shared, rotating, or receiver-side
    infrastructure. Suggesting a raw IP for those sources is misleading. Keep
    copy-paste IP SPF hints for monitored-domain infrastructure where the PTR is
    under the domain and the operator can reasonably own the host.
    """
    return bool(
        sender and sender.get("status") == "known" and sender.get("id") == "owned-infrastructure"
    )


def _source_recommendations(
    ip: str,
    source: Dict[str, Any],
    hostname: Optional[str],
    spf_fix_hint: Optional[str],
    sender: Optional[Dict[str, Any]] = None,
) -> List[SourceRecommendation]:
    """Build clear next steps for common DMARC source patterns."""
    if not _allow_direct_spf_ip_hint(sender):
        spf_fix_hint = None

    spf_result = source.get("spf_result", "unknown")
    dkim_result = source.get("dkim_result", "unknown")
    dmarc_result = source.get("dmarc_result") or (
        "pass" if spf_result == "pass" or dkim_result == "pass" else "fail"
    )
    disposition = source.get("disposition", "none")
    disposition_counts = source.get("disposition_counts", {}) or {}
    dmarc_failed = source.get("dmarc_fail_count", 0) > 0 or dmarc_result == "fail"
    dmarc_passed = source.get("dmarc_pass_count", 0) > 0 or dmarc_result == "pass"

    recommendations: List[SourceRecommendation] = []
    recommendations.extend(_sender_identity_recommendations(sender, dmarc_failed, hostname))
    provider_recommendation = _provider_remediation_recommendation(sender, dmarc_failed)
    if provider_recommendation:
        recommendations.append(provider_recommendation)
    spf_recommendation = _spf_only_recommendation(spf_result, dkim_result, dmarc_passed)
    if spf_recommendation:
        recommendations.append(spf_recommendation)
    dkim_recommendation = _dkim_only_recommendation(
        spf_result, dkim_result, dmarc_passed, spf_fix_hint
    )
    if dkim_recommendation:
        recommendations.append(dkim_recommendation)
    full_fail_recommendation = _full_fail_recommendation(
        spf_result, dkim_result, dmarc_failed, spf_fix_hint
    )
    if full_fail_recommendation:
        recommendations.append(full_fail_recommendation)
    if dmarc_failed and (disposition == "none" or disposition_counts.get("none", 0) > 0):
        recommendations.append(_policy_not_enforced_recommendation())

    return recommendations


def _anomaly_recommendations(anomalies: List[Dict[str, Any]]) -> List[SourceRecommendation]:
    """Expose source intelligence anomalies as source-level next steps."""
    recommendations = []
    for anomaly in anomalies[:3]:
        recommendations.append(
            SourceRecommendation(
                type=f"anomaly_{anomaly['type']}",
                severity=anomaly["severity"],
                title=anomaly["title"],
                detail=anomaly["detail"],
                action=anomaly["action"],
            )
        )
    return recommendations


def _sender_identity_recommendations(
    sender: Optional[Dict[str, Any]],
    dmarc_failed: bool,
    hostname: Optional[str],
) -> List[SourceRecommendation]:
    recommendations: List[SourceRecommendation] = []
    if sender and sender.get("status") == "ambiguous":
        recommendations.append(
            SourceRecommendation(
                type="ambiguous_sender",
                severity="warning",
                title="Confirm sender ownership",
                detail=sender["reason"],
                action=sender["remediation_hint"],
            )
        )
    if sender and sender.get("status") in {"unknown", "suspicious"} and dmarc_failed:
        recommendations.append(
            SourceRecommendation(
                type="unknown_sender",
                severity="error" if sender.get("status") == "suspicious" else "warning",
                title="Identify unknown sender",
                detail=sender["reason"],
                action=sender["remediation_hint"],
            )
        )
    if not sender and not hostname and dmarc_failed:
        recommendations.append(
            SourceRecommendation(
                type="unknown_source",
                severity="warning",
                title="Unknown sending source",
                detail=(
                    "No reverse DNS name was found for this IP, so treat it as unrecognized "
                    "until you confirm who owns it."
                ),
                action=(
                    "Confirm whether this server should send mail for this domain before "
                    "authorizing it in SPF or DKIM."
                ),
            )
        )
    return recommendations


def _provider_remediation_recommendation(
    sender: Optional[Dict[str, Any]],
    dmarc_failed: bool,
) -> Optional[SourceRecommendation]:
    if not sender or sender.get("status") != "known" or not dmarc_failed:
        return None
    return SourceRecommendation(
        type="provider_remediation",
        severity="warning",
        title=f"Fix {sender['name']} authentication",
        detail=(
            f"{sender['name']} is recognized, but some mail from this source is "
            "not passing DMARC."
        ),
        action=sender["remediation_hint"],
    )


def _spf_only_recommendation(
    spf_result: str,
    dkim_result: str,
    dmarc_passed: bool,
) -> Optional[SourceRecommendation]:
    if not (
        spf_result == "pass"
        and dkim_result in {"fail", "mixed", "unknown", "none"}
        and dmarc_passed
    ):
        return None
    return SourceRecommendation(
        type="spf_only_pass",
        severity="info",
        title="SPF-only DMARC pass",
        detail="DMARC is passing through SPF, but DKIM is not reliably passing for this source.",
        action=(
            "Enable DKIM signing for this sending service so messages keep passing "
            "if SPF alignment changes."
        ),
    )


def _dkim_only_recommendation(
    spf_result: str,
    dkim_result: str,
    dmarc_passed: bool,
    spf_fix_hint: Optional[str],
) -> Optional[SourceRecommendation]:
    if not (
        dkim_result == "pass"
        and spf_result in {"fail", "mixed", "unknown", "none"}
        and dmarc_passed
    ):
        return None
    action = "Authorize this service in SPF, or confirm SPF is intentionally handled elsewhere."
    if spf_fix_hint:
        action = f"Add {spf_fix_hint} to your SPF record if this service is legitimate."
    return SourceRecommendation(
        type="dkim_only_pass",
        severity="info",
        title="DKIM-only DMARC pass",
        detail="DMARC is passing through DKIM, but SPF is not reliably passing for this source.",
        action=action,
    )


def _full_fail_recommendation(
    spf_result: str,
    dkim_result: str,
    dmarc_failed: bool,
    spf_fix_hint: Optional[str],
) -> Optional[SourceRecommendation]:
    if not (spf_result == "fail" and dkim_result == "fail" and dmarc_failed):
        return None
    action = (
        "Do not authorize this source until you confirm it is legitimate; then configure "
        "both SPF authorization and DKIM signing."
    )
    if spf_fix_hint:
        action = (
            f"If legitimate, add {spf_fix_hint} to SPF and enable DKIM signing for this service."
        )
    return SourceRecommendation(
        type="full_fail",
        severity="error",
        title="Full DMARC failure",
        detail="Neither SPF nor DKIM is passing, so this mail fails DMARC.",
        action=action,
    )


def _policy_not_enforced_recommendation() -> SourceRecommendation:
    return SourceRecommendation(
        type="policy_not_enforced",
        severity="warning",
        title="Policy not enforced",
        detail="Some failed mail was accepted because the applied DMARC disposition was none.",
        action=(
            "After legitimate sources are passing consistently, move the domain policy "
            "toward quarantine or reject."
        ),
    )


def _source_reputation_response(item: SourceReputation) -> SourceReputationResponse:
    presentation = reputation_presentation(item)
    return SourceReputationResponse(
        ip=item.ip,
        status=item.status,
        status_label=presentation.status_label,
        status_detail=presentation.status_detail,
        risk_score=item.risk_score,
        summary=item.summary,
        evidence_summary=presentation.evidence_summary,
        feed_status=presentation.feed_status,
        feed_summary=presentation.feed_summary,
        listings=item.listings,
        evidence=[
            SourceReputationEvidence(
                label=evidence.label,
                value=evidence.value,
                source=evidence.source,
            )
            for evidence in item.evidence
        ],
        recommendations=item.recommendations,
        first_seen=item.first_seen,
        last_seen=item.last_seen,
        checked_at=item.checked_at,
    )


def _reputation_recommendations(item: Optional[SourceReputation]) -> List[SourceRecommendation]:
    if item is None or item.status in {"clean", "unknown"}:
        return []
    severity = "error" if item.status in {"listed", "critical"} else "warning"
    return [
        SourceRecommendation(
            type="source_reputation",
            severity=severity,
            title="Review sender IP reputation",
            detail=item.summary,
            action=(
                item.recommendations[0]
                if item.recommendations
                else "Confirm this source before authorizing it or tightening DMARC policy."
            ),
        )
    ]


def _ptr_lookup_providers(provider: Any) -> List[Any]:
    """Return resolver candidates for reverse-DNS sender enrichment."""
    providers = [provider]
    provider_class = provider.__class__
    provider_name = provider_class.__name__
    if provider_name == "DemoDNSProvider":
        return providers
    if provider_class is not PublicRecursiveDNSProvider:
        providers.append(PublicRecursiveDNSProvider())
    if provider_class is not CloudflareDNSProvider:
        providers.append(CloudflareDNSProvider())
    return providers


async def _safe_ptr_lookup(provider: Any, ip: str, timeout: float = 3.0) -> Optional[str]:
    """Perform a PTR lookup for *ip*, returning ``None`` on any error or timeout."""
    try:
        parsed_ip = ipaddress.ip_address(ip)  # validate before making a DNS query
    except ValueError:
        return None
    if not parsed_ip.is_global:
        return None
    for candidate in _ptr_lookup_providers(provider):
        try:
            hostname = await asyncio.wait_for(candidate.lookup_ptr(ip), timeout=timeout)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug(
                "PTR lookup provider failed during sender enrichment",
                extra={
                    "provider": candidate.__class__.__name__,
                    "ip": ip,
                    "error": str(exc),
                },
            )
            continue
        if hostname:
            return str(hostname).rstrip(".")
    return None


async def _source_networks_by_ip(
    db: Session,
    provider: Any,
    ips: List[str],
    settings: Any,
) -> Dict[str, SourceNetworkIntelligence]:
    if not settings.SOURCE_NETWORK_ENRICHMENT_ENABLED:
        return {}
    try:
        return await asyncio.wait_for(
            lookup_sources_network_cached(
                db,
                provider,
                ips,
                ttl_seconds=settings.SOURCE_NETWORK_ENRICHMENT_CACHE_SECONDS,
                max_ips=settings.SOURCE_NETWORK_ENRICHMENT_MAX_IPS,
            ),
            timeout=max(
                0.5,
                float(settings.SOURCE_NETWORK_ENRICHMENT_DETAIL_TIMEOUT_SECONDS),
            ),
        )
    except asyncio.TimeoutError:
        logger.info("Source network enrichment timed out for domain sources")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.info(
            "Source network enrichment failed for domain sources: %s",
            type(exc).__name__,
        )
    return {}


async def _source_reputations_by_ip(
    db: Session,
    domain_name: str,
    reports: List[Dict[str, Any]],
    sources: List[Dict[str, Any]],
    sender_by_ip: Dict[str, Dict[str, Any]],
    anomalies_by_ip: Dict[str, List[Dict[str, Any]]],
    days: int,
    refresh: bool,
    settings: Any,
) -> Dict[str, SourceReputation]:
    try:
        reputation_result, _, _ = await asyncio.wait_for(
            build_source_reputation_cached(
                db,
                domain_name,
                reports,
                sources,
                senders_by_ip=sender_by_ip,
                anomalies_by_ip=anomalies_by_ip,
                days=days,
                refresh=refresh,
            ),
            timeout=max(
                0.5,
                float(settings.SOURCE_REPUTATION_DETAIL_TIMEOUT_SECONDS) * (2 if refresh else 1),
            ),
        )
        return source_reputation_by_ip(reputation_result)
    except asyncio.TimeoutError:
        logger.info("Source reputation enrichment timed out for domain sources")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.info(
            "Source reputation enrichment failed for domain sources: %s",
            type(exc).__name__,
        )
    return {}


@router.get("/{domain_id}/sources", response_model=DomainSourcesResponse)
async def get_domain_sources(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, title="Number of days to look back"),
    refresh: bool = Query(False, title="Refresh cached source reputation evidence"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Get sending sources for a specific domain, including reverse-DNS hostnames
    and SPF fix hints for sources that fail authentication.
    """
    workspace = _authorized_domain_read_workspace(_auth, db)
    domain_name, store = _single_domain_report_store_for_read(db, domain_id, workspace)

    sources = store.get_domain_sources(domain_name, days=days)
    reports = store.get_domain_reports(domain_name)
    provider = get_default_provider(db)
    settings = get_settings()

    ips = [s.get("source_ip", "unknown") for s in sources]
    ptr_task = asyncio.gather(*[_safe_ptr_lookup(provider, ip) for ip in ips])
    network_task = asyncio.create_task(_source_networks_by_ip(db, provider, ips, settings))
    hostnames, networks_by_ip = await asyncio.gather(ptr_task, network_task)
    geo_by_ip = {
        str(source.get("source_ip") or "unknown"): merge_network_into_geo(
            source_geo_for(str(source.get("source_ip") or "unknown"), source),
            networks_by_ip.get(str(source.get("source_ip") or "unknown")),
        )
        for source in sources
    }
    intelligence = build_source_intelligence(
        domain_name,
        reports,
        sources,
        period_days=days,
        geo_by_ip=geo_by_ip,
    )
    anomalies_by_ip = intelligence.get("anomalies_by_ip", {})

    source_entries = []
    sender_by_ip: Dict[str, Dict[str, Any]] = {}
    source_context = []
    for source, hostname in zip(sources, hostnames):
        ip = source.get("source_ip", "unknown")
        sender_by_ip[ip] = identify_sender(ip, source, hostname=hostname, domain=domain_name)
        source_context.append((source, hostname, sender_by_ip[ip]))

    reputations_by_ip = await _source_reputations_by_ip(
        db,
        domain_name,
        reports,
        sources,
        sender_by_ip,
        anomalies_by_ip,
        days,
        refresh,
        settings,
    )

    for source, hostname, sender in source_context:
        ip = source.get("source_ip", "unknown")
        spf_result = source.get("spf_result", "unknown")
        dkim_result = source.get("dkim_result", "unknown")
        spf_fix_hint = _spf_fix_hint(ip, spf_result, source.get("spf_fail_count", 0))
        if not _allow_direct_spf_ip_hint(sender):
            spf_fix_hint = None
        source_anomalies = anomalies_by_ip.get(ip, [])
        reputation = reputations_by_ip.get(ip)
        recommendations = _source_recommendations(ip, source, hostname, spf_fix_hint, sender)
        recommendations.extend(_anomaly_recommendations(source_anomalies))
        recommendations.extend(_reputation_recommendations(reputation))
        source_entries.append(
            SourceEntry(
                ip=ip,
                count=source.get("count", 0),
                first_seen=source.get("first_seen"),
                last_seen=source.get("last_seen"),
                active_days=source.get("active_days", 0),
                report_count=source.get("report_count", 0),
                volume_history=source.get("volume_history", []),
                spf=spf_result,
                dkim=dkim_result,
                dmarc=source.get("dmarc_result")
                or ("pass" if spf_result == "pass" or dkim_result == "pass" else "fail"),
                disposition=source.get("disposition", "none"),
                spf_pass_count=source.get("spf_pass_count", 0),
                spf_fail_count=source.get("spf_fail_count", 0),
                dkim_pass_count=source.get("dkim_pass_count", 0),
                dkim_fail_count=source.get("dkim_fail_count", 0),
                dmarc_pass_count=source.get("dmarc_pass_count", 0),
                dmarc_fail_count=source.get("dmarc_fail_count", 0),
                disposition_counts=source.get("disposition_counts", {}),
                hostname=hostname,
                sender=SenderIdentity(**sender),
                geo=SourceGeo(
                    **(
                        geo_by_ip.get(ip)
                        or merge_network_into_geo(
                            source_geo_for(ip, source),
                            networks_by_ip.get(ip),
                        )
                    )
                ),
                anomalies=[SourceAnomaly(**anomaly) for anomaly in source_anomalies],
                reputation=(
                    _source_reputation_response(reputation) if reputation is not None else None
                ),
                spf_fix_hint=spf_fix_hint,
                recommendations=recommendations,
            )
        )

    return DomainSourcesResponse(sources=source_entries)


@router.get("/{domain_id}/source-reputation", response_model=DomainSourceReputationResponse)
async def get_domain_source_reputation(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, ge=1, le=365, title="Number of days to analyze"),
    refresh: bool = Query(False, title="Refresh cached reputation evidence"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return passive reputation evidence for observed sender IPs."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    domain_name, store = _single_domain_report_store_for_read(db, domain_id, workspace)

    reports = store.get_domain_reports(domain_name)
    sources = store.get_domain_sources(domain_name, days=days)
    intelligence = build_source_intelligence(
        domain_name,
        reports,
        sources,
        period_days=days,
    )
    sender_by_ip = {
        str(source.get("source_ip") or "unknown"): identify_sender(
            str(source.get("source_ip") or "unknown"),
            source,
            hostname=None,
            domain=domain_id,
        )
        for source in sources
    }
    result, cached, _ = await build_source_reputation_cached(
        db,
        domain_name,
        reports,
        sources,
        senders_by_ip=sender_by_ip,
        anomalies_by_ip=intelligence.get("anomalies_by_ip", {}),
        days=days,
        refresh=refresh,
    )
    return DomainSourceReputationResponse(
        domain=result.domain,
        status=result.status,
        checked_at=result.checked_at,
        sources=[_source_reputation_response(item) for item in result.sources],
        summary=result.summary,
        feeds=feed_registry(),
        cached=cached,
    )


@router.get("/{domain_id}/source-intelligence", response_model=SourceIntelligenceResponse)
async def get_domain_source_intelligence(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, ge=1, le=365, title="Number of days to analyze"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return region summaries and source anomaly hints for a domain."""
    workspace = _authorized_domain_read_workspace(_auth, db)
    domain_name, store = _single_domain_report_store_for_read(db, domain_id, workspace)

    sources = store.get_domain_sources(domain_name, days=days)
    provider = get_default_provider(db)
    settings = get_settings()
    ips = [str(source.get("source_ip") or "unknown") for source in sources]
    networks_by_ip = await _source_networks_by_ip(db, provider, ips, settings)
    geo_by_ip = {
        str(source.get("source_ip") or "unknown"): merge_network_into_geo(
            source_geo_for(str(source.get("source_ip") or "unknown"), source),
            networks_by_ip.get(str(source.get("source_ip") or "unknown")),
        )
        for source in sources
    }
    intelligence = build_source_intelligence(
        domain_name,
        store.get_domain_reports(domain_name),
        sources,
        period_days=days,
        geo_by_ip=geo_by_ip,
    )
    return SourceIntelligenceResponse(
        domain=intelligence["domain"],
        period_days=intelligence["period_days"],
        recent_days=intelligence.get("recent_days", 0),
        regions=[SourceRegionSummary(**region) for region in intelligence["regions"]],
        anomalies=[SourceAnomaly(**anomaly) for anomaly in intelligence["anomalies"]],
        summary=intelligence["summary"],
    )


@router.get("/{domain_id}/selectors")
async def get_domain_selectors(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return the manually configured DKIM selectors for a domain.

    The response includes both ``selectors`` (manually configured, can be
    deleted) and ``report_selectors`` (automatically discovered from received
    DMARC reports, read-only).
    """
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    manual = _get_domain_selectors_from_db(db, domain_id)
    report = _get_selectors_from_reports(store, domain_id)
    # Only include in report_selectors those not already in the manual list
    auto = [s for s in report if s not in manual]
    return {"selectors": manual, "report_selectors": auto}


@router.post("/{domain_id}/selectors", status_code=status.HTTP_201_CREATED)
async def add_domain_selector(
    selector_data: SelectorRequest,
    request: Request,
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Add a DKIM selector to the manual list for a domain.

    The selector is persisted in the ``Domain`` database row so that it will
    be used in all subsequent DNS checks, even if it has not yet appeared in
    any received DMARC report.
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    workspace = _authorized_domain_workspace(_auth, db)
    if not _domain_exists(db, store, domain_id, workspace):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    selector = selector_data.selector.strip()
    if not selector:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Selector must not be empty",
        )

    domain_db = workspace_domain_query(db, workspace).filter(Domain.name == domain_id).first()
    if not domain_db:
        domain_db = Domain(name=domain_id, workspace_id=workspace.id)
        db.add(domain_db)

    existing = [s.strip() for s in (domain_db.dkim_selectors or "").split(",") if s.strip()]
    if selector not in existing:
        existing.append(selector)
        domain_db.dkim_selectors = ",".join(existing)
        db.commit()
        record_workspace_audit_log(
            db,
            workspace=workspace,
            action="domain.selector_added",
            entity_type="domain",
            entity_id=domain_db.id,
            entity_name=domain_db.name,
            details={"selector": selector},
            auth_context=_auth,
            request=request,
            commit=True,
        )

    return {"selectors": existing}


@router.delete("/{domain_id}/selectors/{selector}", status_code=status.HTTP_200_OK)
async def delete_domain_selector(
    request: Request,
    domain_id: str = Path(..., title="The domain ID or name"),
    selector: str = Path(..., title="The DKIM selector to remove"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Remove a manually configured DKIM selector from a domain."""
    workspace = _authorized_domain_workspace(_auth, db)
    domain_db = workspace_domain_query(db, workspace).filter(Domain.name == domain_id).first()
    if not domain_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    existing = [s.strip() for s in (domain_db.dkim_selectors or "").split(",") if s.strip()]
    if selector not in existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Selector '{selector}' not found",
        )

    existing.remove(selector)
    domain_db.dkim_selectors = ",".join(existing)
    db.commit()
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="domain.selector_removed",
        entity_type="domain",
        entity_id=domain_db.id,
        entity_name=domain_db.name,
        details={"selector": selector},
        auth_context=_auth,
        request=request,
        commit=True,
    )

    return {"selectors": existing}


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Delete a domain and all associated data.
    This performs a full cleanup of all reports and records related to this domain.
    """
    workspace = _authorized_domain_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    domains = _domain_names_for_summary(db, store, workspace)

    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    # Perform deletion with cleanup
    domain_row = workspace_domain_query(db, workspace).filter(Domain.name == domain_id).first()
    deleted_from_db = False
    if domain_row is not None:
        db.delete(domain_row)
        deleted_from_db = True
    if deleted_from_db:
        db.commit()
    deleted = store.delete_domain_with_cleanup(domain_id) or deleted_from_db

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete domain",
        )

    # Return 204 No Content on success
    return None


@router.get("/search", response_model=List[DomainResponse])
async def search_domains(
    q: Optional[str] = Query(None, title="Search query for domain name or description"),
    policy: Optional[str] = Query(None, title="Filter by DMARC policy"),
    page: int = Query(1, title="Page number", ge=1),
    limit: int = Query(10, title="Number of domains per page", ge=1, le=100),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """
    Search domains with filtering and pagination.
    This supports searching by domain name/description and filtering by DMARC policy.

    Args:
        q: Optional search query for domain name or description
        policy: Optional filter by DMARC policy (none, quarantine, reject)
        page: Page number (1-based)
        limit: Number of domains per page (max 100)
    """
    workspace = _authorized_domain_read_workspace(_auth, db)
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    domains = _domain_names_for_summary(db, store, workspace)
    summaries = store.get_all_domain_summaries()

    # Apply search filter if provided
    filtered_domains = []
    for domain_name in domains:
        summary = summaries.get(domain_name, {})

        # Skip domain if it doesn't match the search query
        if q and q.lower() not in domain_name.lower():
            continue

        reported_policy = _normalize_reported_policy(summary.get("policy")) or "unknown"

        # Skip domain if it doesn't match the policy filter
        if policy and reported_policy != policy:
            continue

        # Domain passed all filters
        filtered_domains.append(
            {
                "name": domain_name,
                "description": "",  # No description in in-memory store
                "policy": reported_policy,
                "reports_count": summary.get("reports_processed", 0),
                "emails_count": summary.get("total_count", 0),
                "compliance_rate": summary.get("compliance_rate", 0.0),
            }
        )

    # Apply pagination
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_domains = filtered_domains[start_idx:end_idx]

    return [DomainResponse(**domain) for domain in paginated_domains]
