"""Current-user workspace context endpoints."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import case, distinct, func, or_
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.core.localization import resolve_request_locale
from app.core.security import require_admin_auth
from app.models.dns_posture_snapshot import DomainDNSPostureCurrent, DomainDNSPostureSnapshot
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.report import DMARCReport, ForensicReport, ReportRecord, TLSReport
from app.models.setting import Setting
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.cloudflare_dns import get_cloudflare_credentials
from app.services.diagnostic_plan import DiagnosticEvidence, build_diagnostic_plan
from app.services.dns_provider_writes import lexicon_provider_environment_configured
from app.services.guidance_profile import (
    EXPLANATION_DEPTHS,
    INSTALLATION_GOALS,
    LEGACY_GOAL_MAP,
    PRIMARY_GOAL_LEGACY_MAP,
    PROFILE_VERSION,
    REPORT_INTAKE_PREFERENCES,
    SOVEREIGNTY_PREFERENCES,
    WORK_CONTEXTS,
    encode_json,
    resolve_guidance_profile,
)
from app.services.hetzner_dns import get_hetzner_dns_credentials
from app.services.mail_health import build_workspace_mail_health_assessment
from app.services.mail_health_incidents import (
    NOTIFICATION_POSTURES,
    list_mail_health_incidents,
    record_mail_health_assessment,
    update_incident_operator_state,
)
from app.services.report_intake_recommendation import (
    ReportIntakeEvidence,
    build_report_intake_recommendation,
)
from app.services.route53_dns import get_route53_dns_credentials
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    PERMISSION_REPORTS_WRITE,
    ROLE_ANALYST,
    ROLE_WORKSPACE_OWNER,
    _auth_user,
    is_platform_admin_auth,
    parse_selected_workspace_id,
    permissions_for_role,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import record_workspace_audit_log
from app.utils.domain_validator import normalize_domain_name, validate_domain

router = APIRouter()


class WorkspaceContextResponse(BaseModel):
    """Visible workspace context for client-side scope selection."""

    workspaces: List[Dict[str, Any]]
    default_workspace_id: Optional[int] = None


class GuidancePreferenceUpdate(BaseModel):
    """Workspace opt-in with a user's optional presentation preference."""

    enabled: bool
    depth: str = "guided"
    context: str = "watch"
    teaching_hints_enabled: Optional[bool] = None


class GuidanceProfileUpdate(BaseModel):
    """Problem-first setup answers that do not change the legacy dashboard."""

    goal: str
    depth: str = "guided"


class PersonalGuidancePreferenceUpdate(BaseModel):
    """Presentation only; never changes evidence access or workspace policy."""

    depth: str
    context: str
    teaching_hints_enabled: bool = True


class WorkspaceGuidanceProfileUpdate(BaseModel):
    """Versioned, non-secret operational context for guided decisions."""

    installation_goals: List[str] = Field(max_length=len(INSTALLATION_GOALS))
    sovereignty_preference: str = "not_sure"
    notification_posture: str = "actionable_only"
    mail_context: Dict[str, Any] = Field(default_factory=dict)
    interview_version: int = PROFILE_VERSION
    interview_completed: bool = True


class NotificationPostureUpdate(BaseModel):
    """How much Calm Watch may interrupt an operator."""

    posture: str


class IncidentActionUpdate(BaseModel):
    """An auditable acknowledgement or bounded snooze."""

    action: str
    note: Optional[str] = None
    snoozed_until: Optional[datetime] = None


def _guidance_payload(workspace: Workspace, user: Optional[User] = None) -> Dict[str, Any]:
    settings = get_settings()
    return resolve_guidance_profile(
        workspace,
        user,
        available=bool(settings.GUIDED_MAIL_HEALTH_UI_ENABLED),
    )


def _validated_provider_names(value: object) -> List[str]:
    if not isinstance(value, list) or len(value) > 20:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="known_mail_providers must be a list with at most 20 entries",
        )
    normalized_providers = []
    for provider in value:
        normalized = str(provider or "").strip()
        if not normalized or len(normalized) > 80:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Mail provider names must contain 1 to 80 characters",
            )
        if normalized not in normalized_providers:
            normalized_providers.append(normalized)
    return normalized_providers


def _validated_optional_bool(value: Dict[str, Any], key: str) -> Optional[bool]:
    if key not in value:
        return None
    if not isinstance(value[key], bool):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{key} must be true or false",
        )
    return value[key]


def _validated_domains(value: Any) -> List[str]:
    if not isinstance(value, list) or len(value) > 20:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="domains must be a list with at most 20 entries",
        )
    normalized_domains: List[str] = []
    for raw_domain in value:
        domain = normalize_domain_name(str(raw_domain or ""))
        valid, _, _ = validate_domain(domain, check_dns=False)
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid domain in mail context",
            )
        if domain not in normalized_domains:
            normalized_domains.append(domain)
    return normalized_domains


def _validated_optional_text(value: Dict[str, Any], key: str) -> Optional[str]:
    if value.get(key) is None:
        return None
    normalized = str(value[key] or "").strip()
    if len(normalized) > 80:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{key} must not exceed 80 characters",
        )
    return normalized or None


def _validated_choice(
    value: Dict[str, Any], key: str, choices: set[str], detail: str
) -> Optional[str]:
    selected = value.get(key)
    if selected is not None and selected not in choices:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
        )
    return selected


def _validated_interview_step(value: Dict[str, Any]) -> Optional[int]:
    interview_step = value.get("interview_step")
    if interview_step is None:
        return None
    if (
        isinstance(interview_step, bool)
        or not isinstance(interview_step, int)
        or not 1 <= interview_step <= 4
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="interview_step must be between 1 and 4",
        )
    return interview_step


def _validated_mail_context_bools(value: Dict[str, Any]) -> Dict[str, bool]:
    result: Dict[str, bool] = {}
    for key in (
        "self_hosted_sender",
        "domain_sends_mail",
        "controls_dns",
        "bounce_available",
        "low_volume",
        "continuous_monitoring",
        "local_bridge_available",
    ):
        validated = _validated_optional_bool(value, key)
        if validated is not None:
            result[key] = validated
    return result


def _validated_mail_context(value: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "domains",
        "known_mail_providers",
        "self_hosted_sender",
        "domain_sends_mail",
        "dns_provider",
        "report_intake_preference",
        "controls_dns",
        "setup_effort",
        "bounce_available",
        "low_volume",
        "symptom_recipient_provider",
        "symptom_first_observed",
        "interview_step",
        "continuous_monitoring",
        "local_bridge_available",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported mail context field: {unknown[0]}",
        )
    result: Dict[str, Any] = {
        "known_mail_providers": _validated_provider_names(value.get("known_mail_providers", []))
    }
    normalized_domains = _validated_domains(value.get("domains", []))
    if normalized_domains:
        result["domains"] = normalized_domains
    result.update(_validated_mail_context_bools(value))
    dns_provider = _validated_optional_text(value, "dns_provider")
    if value.get("dns_provider") is not None:
        result["dns_provider"] = dns_provider
    intake = _validated_choice(
        value,
        "report_intake_preference",
        REPORT_INTAKE_PREFERENCES,
        "Invalid report intake preference",
    )
    if intake is not None:
        result["report_intake_preference"] = intake
    effort = _validated_choice(
        value,
        "setup_effort",
        {"simplest", "balanced", "maximum_control"},
        "Invalid setup effort",
    )
    if effort is not None:
        result["setup_effort"] = effort
    for key in ("symptom_recipient_provider", "symptom_first_observed"):
        normalized = _validated_optional_text(value, key)
        if normalized:
            result[key] = normalized
    interview_step = _validated_interview_step(value)
    if interview_step is not None:
        result["interview_step"] = interview_step
    return result


def _selected_diagnostic_domain(domains: List[Domain], profile: Dict[str, Any]) -> Optional[Domain]:
    requested = profile.get("mail_context", {}).get("domains", [])
    domains_by_name = {domain.name: domain for domain in domains}
    if requested:
        # Never combine a requested but unmonitored domain with another domain's evidence.
        return next((domains_by_name[name] for name in requested if name in domains_by_name), None)
    return domains[0] if domains else None


def _destination_count(value: object) -> int:
    return len([item for item in str(value or "").split(",") if item.strip()])


def _stored_dns_evidence(db: Session, selected: Optional[Domain]) -> Dict[str, Any]:
    has_dmarc = bool(selected and selected.dmarc_policy)
    has_spf = bool(selected and selected.spf_record)
    evidence = {
        "has_dmarc": has_dmarc,
        "has_spf": has_spf,
        "has_dkim": False,
        "dkim_selector_count": 0,
        "dmarc_rua_count": 0,
        "dmarc_ruf_count": 0,
        "available": False,
    }
    if selected is None:
        return evidence
    current = (
        db.query(DomainDNSPostureCurrent)
        .filter(DomainDNSPostureCurrent.domain_id == selected.id)
        .one_or_none()
    )
    snapshot = (
        db.get(DomainDNSPostureSnapshot, current.accepted_snapshot_id)
        if current and current.accepted_snapshot_id
        else None
    )
    if snapshot is None:
        evidence["available"] = has_dmarc or has_spf
        return evidence
    try:
        dns_result = json.loads(snapshot.result_json)
    except (TypeError, ValueError, json.JSONDecodeError):
        dns_result = {}
    if not isinstance(dns_result, dict):
        return evidence
    dmarc_tags = dns_result.get("dmarc_tags")
    tags = dmarc_tags if isinstance(dmarc_tags, dict) else {}
    selectors = dns_result.get("dkim_selectors")
    selector_count = len(selectors) if isinstance(selectors, list) else 0
    evidence.update(
        {
            "has_dmarc": bool(dns_result.get("dmarc")),
            "has_spf": bool(dns_result.get("spf")),
            "has_dkim": bool(dns_result.get("dkim")),
            "dkim_selector_count": selector_count,
            "dmarc_rua_count": _destination_count(tags.get("rua")),
            "dmarc_ruf_count": _destination_count(tags.get("ruf")),
            "available": True,
        }
    )
    return evidence


def _stored_report_evidence(
    db: Session, selected: Optional[Domain]
) -> tuple[int, int, int, Optional[int]]:
    if selected is None:
        return 0, 0, 0, None
    latest = (
        db.query(DMARCReport.id, DMARCReport.end_date)
        .filter(DMARCReport.domain_id == selected.id)
        .order_by(DMARCReport.end_date.desc(), DMARCReport.id.desc())
        .first()
    )
    if latest is None:
        return 0, 0, 0, None
    total_messages = func.coalesce(func.sum(ReportRecord.count), 0)
    # These are receiver policy-evaluated aligned DKIM/SPF outcomes. Passing
    # either mechanism is the persisted DMARC authentication result.
    passed_messages = func.coalesce(
        func.sum(
            case(
                (
                    or_(ReportRecord.dkim == "pass", ReportRecord.spf == "pass"),
                    ReportRecord.count,
                ),
                else_=0,
            )
        ),
        0,
    )
    aggregate = (
        db.query(func.count(distinct(DMARCReport.id)), total_messages, passed_messages)
        .select_from(DMARCReport)
        .outerjoin(ReportRecord, ReportRecord.report_id == DMARCReport.id)
        .filter(DMARCReport.domain_id == selected.id)
        .one()
    )
    latest_messages, latest_passed = (
        db.query(total_messages, passed_messages)
        .select_from(DMARCReport)
        .outerjoin(ReportRecord, ReportRecord.report_id == DMARCReport.id)
        .filter(DMARCReport.id == latest.id)
        .one()
    )
    failed_message_count = max(0, int(latest_messages or 0) - int(latest_passed or 0))
    return (
        int(aggregate[0] or 0),
        int(aggregate[1] or 0),
        failed_message_count,
        int(latest.id),
    )


def _dns_provider_connected(db: Session, profile: Dict[str, Any]) -> bool:
    provider_name = str(profile.get("mail_context", {}).get("dns_provider") or "").strip().lower()
    provider_id = {
        "cloudflare": "cloudflare",
        "route 53": "route53",
        "route53": "route53",
        "aws": "route53",
        "aws route 53": "route53",
        "hetzner": "hetzner",
        "hetzner dns": "hetzner",
        "ovh": "ovh",
        "ovhcloud": "ovh",
    }.get(provider_name, provider_name.replace(" ", "-"))
    try:
        if provider_id == "cloudflare":
            return get_cloudflare_credentials(db).configured
        if provider_id == "route53":
            return (
                get_route53_dns_credentials().configured
                or lexicon_provider_environment_configured(provider_id)
            )
        if provider_id == "hetzner":
            return (
                get_hetzner_dns_credentials().configured
                or lexicon_provider_environment_configured(provider_id)
            )
        return bool(provider_id and lexicon_provider_environment_configured(provider_id))
    except Exception:  # pragma: no cover - readiness checks expose no secret material.
        return False


def _diagnostic_evidence(
    db: Session,
    *,
    workspace: Workspace,
    profile: Dict[str, Any],
) -> DiagnosticEvidence:
    """Build a bounded diagnostic read model from persisted database rows."""
    domains = (
        db.query(Domain)
        .filter(Domain.workspace_id == workspace.id, Domain.active.is_(True))
        .order_by(Domain.name.asc())
        .all()
    )
    selected = _selected_diagnostic_domain(domains, profile)
    dns_evidence = _stored_dns_evidence(db, selected)
    report_count, message_count, failed_message_count, latest_report_id = _stored_report_evidence(
        db, selected
    )
    sources = db.query(MailSource).filter(MailSource.workspace_id == workspace.id).all()
    enabled_sources = [source for source in sources if source.enabled]
    forensic_report_count = (
        db.query(func.count(ForensicReport.id))
        .filter(ForensicReport.domain_id == selected.id)
        .scalar()
        if selected
        else 0
    )
    tls_report_count = (
        db.query(func.count(TLSReport.id)).filter(TLSReport.domain_id == selected.id).scalar()
        if selected
        else 0
    )
    return DiagnosticEvidence(
        domain_names=tuple(domain.name for domain in domains),
        selected_domain=selected.name if selected else None,
        has_dmarc=dns_evidence["has_dmarc"],
        has_spf=dns_evidence["has_spf"],
        has_dkim=dns_evidence["has_dkim"],
        dkim_selector_count=dns_evidence["dkim_selector_count"],
        dmarc_rua_count=dns_evidence["dmarc_rua_count"],
        dmarc_ruf_count=dns_evidence["dmarc_ruf_count"],
        dmarc_policy=selected.dmarc_policy if selected else None,
        dns_evidence_available=dns_evidence["available"],
        report_count=report_count,
        forensic_report_count=int(forensic_report_count or 0),
        tls_report_count=int(tls_report_count or 0),
        message_count=message_count,
        failed_message_count=failed_message_count,
        enabled_source_count=len(enabled_sources),
        checked_source_count=sum(
            1 for source in enabled_sources if source.last_checked is not None
        ),
        dns_provider_connected=_dns_provider_connected(db, profile),
        latest_report_id=latest_report_id,
    )


def _report_intake_evidence(
    db: Session,
    *,
    workspace: Workspace,
    profile: Dict[str, Any],
) -> ReportIntakeEvidence:
    """Build a secret-free intake read model from stored workspace state."""
    sources = (
        db.query(MailSource)
        .filter(MailSource.workspace_id == workspace.id)
        .order_by(MailSource.id.asc())
        .all()
    )
    source_ids = [source.id for source in sources]
    latest_import = None
    if source_ids:
        latest_import = (
            db.query(MailSourceImport)
            .filter(MailSourceImport.mail_source_id.in_(source_ids))
            .filter(MailSourceImport.finished_at.isnot(None))
            .order_by(
                MailSourceImport.finished_at.desc(),
                MailSourceImport.id.desc(),
            )
            .first()
        )
    domains = (
        db.query(Domain).filter(Domain.workspace_id == workspace.id).order_by(Domain.id.asc()).all()
    )
    selected_domain = _selected_diagnostic_domain(domains, profile)
    settings = get_settings()
    report_query = (
        db.query(DMARCReport)
        .join(Domain, Domain.id == DMARCReport.domain_id)
        .filter(Domain.workspace_id == workspace.id)
    )
    if selected_domain:
        report_query = report_query.filter(DMARCReport.domain_id == selected_domain.id)
    report_count = report_query.count()
    latest_report = report_query.order_by(DMARCReport.id.desc()).first()
    dns_evidence = _stored_dns_evidence(db, selected_domain)
    return ReportIntakeEvidence(
        source_methods=tuple(str(source.method or "").upper() for source in sources),
        source_labels=tuple(
            " ".join(
                part
                for part in (
                    str(source.name or ""),
                    str(source.server or ""),
                    str(source.gmail_email or ""),
                    str(source.m365_email or ""),
                )
                if part
            )
            for source in sources
        ),
        enabled_source_count=sum(1 for source in sources if source.enabled),
        checked_source_count=sum(
            1 for source in sources if source.enabled and source.last_checked is not None
        ),
        total_report_count=int(report_count or 0),
        latest_report_id=(latest_report.id if latest_report else None),
        domain_name=(selected_domain.name if selected_domain else None),
        report_destination_configured=bool(
            selected_domain and selected_domain.dmarc_report_mailbox
        ),
        dmarc_reporting_configured=bool(dns_evidence.get("dmarc_rua_count")),
        latest_import_status=(str(latest_import.status) if latest_import else None),
        latest_import_reports_found=int(latest_import.reports_found or 0) if latest_import else 0,
        latest_import_duplicates=(
            int(latest_import.duplicate_reports or 0) if latest_import else 0
        ),
        latest_import_errors=int(latest_import.error_count or 0) if latest_import else 0,
        public_base_url=(
            getattr(settings, "PUBLIC_BASE_URL", None)
            or (
                db.query(Setting.value)
                .filter(Setting.key == "general.base_url")
                .scalar()
            )
        ),
        webhook_configured=bool(getattr(settings, "WEBHOOK_SECRET", None)),
    )


def _workspace_context_row(
    workspace: Workspace,
    role: str,
) -> Optional[Dict[str, Any]]:
    if not role:
        return None
    organization = workspace.organization
    return {
        "id": workspace.id,
        "slug": workspace.slug,
        "name": workspace.name,
        "active": bool(workspace.active),
        "organization": (
            {
                "id": organization.id,
                "slug": organization.slug,
                "name": organization.name,
                "active": bool(organization.active),
            }
            if organization is not None
            else None
        ),
        "effective_role": role,
        "permissions": sorted(permissions_for_role(role)),
    }


def _visible_workspace_roles(db: Session, auth_context: dict) -> Dict[int, str]:
    if is_platform_admin_auth(auth_context):
        return {
            workspace_id: ROLE_WORKSPACE_OWNER for (workspace_id,) in db.query(Workspace.id).all()
        }

    if (auth_context or {}).get("auth_type") == "api_token":
        try:
            workspace_id = int((auth_context or {}).get("workspace_id") or 0)
        except (TypeError, ValueError):
            workspace_id = 0
        return {workspace_id: ROLE_ANALYST} if workspace_id else {}

    user = _auth_user(db, auth_context)
    if user is None:
        return {}

    rows = (
        db.query(WorkspaceMembership.workspace_id, WorkspaceMembership.role)
        .filter(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.active.is_(True),
        )
        .all()
    )
    roles = {workspace_id: role for workspace_id, role in rows}
    if user.is_superuser and user.workspace_id:
        roles.setdefault(user.workspace_id, ROLE_WORKSPACE_OWNER)
    return roles


@router.get("", response_model=WorkspaceContextResponse)
async def list_visible_workspaces(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> WorkspaceContextResponse:
    """Return workspaces visible to the current admin/session context."""
    roles_by_workspace = _visible_workspace_roles(db, _auth)
    if not roles_by_workspace:
        return {"workspaces": [], "default_workspace_id": None}
    workspaces = (
        db.query(Workspace)
        .options(selectinload(Workspace.organization))
        .filter(Workspace.id.in_(list(roles_by_workspace)))
        .order_by(Workspace.active.desc(), Workspace.slug.asc())
        .all()
    )
    visible = []
    for workspace in workspaces:
        row = _workspace_context_row(workspace, roles_by_workspace.get(workspace.id, ""))
        if row is not None:
            visible.append(row)
    default_workspace_id = visible[0]["id"] if visible else None
    return {"workspaces": visible, "default_workspace_id": default_workspace_id}


@router.get("/guidance")
async def get_guidance_preference(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return whether this workspace may use the optional guided dashboard."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    return _guidance_payload(workspace, _auth_user(db, _auth))


@router.put("/guidance")
async def update_guidance_preference(
    payload: GuidancePreferenceUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Persist an opt-in without changing legacy dashboards automatically."""
    if payload.depth not in EXPLANATION_DEPTHS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid guidance depth"
        )
    if payload.context not in WORK_CONTEXTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid guidance context"
        )
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    workspace.guided_mail_health_enabled = bool(payload.enabled)
    user = _auth_user(db, _auth)
    if user is not None:
        user.guidance_depth = payload.depth
        user.guidance_context = payload.context
        if payload.teaching_hints_enabled is not None:
            user.guidance_teaching_hints_enabled = payload.teaching_hints_enabled
        user.guidance_profile_version = PROFILE_VERSION
    else:
        workspace.guidance_depth = payload.depth
        workspace.guidance_context = payload.context
        if payload.teaching_hints_enabled is not None:
            workspace.guidance_teaching_hints_enabled = payload.teaching_hints_enabled
    db.commit()
    db.refresh(workspace)
    return _guidance_payload(workspace, user)


@router.put("/guidance/profile")
async def update_guidance_profile(
    payload: GuidanceProfileUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Record the user's installation goal without opting them into a new view."""
    valid_goals = {
        "delivery_problem",
        "spam_or_inconsistent",
        "reports_confusing",
        "suspected_abuse",
        "preventive_monitoring",
        "curious",
    }
    if payload.goal not in valid_goals:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid mail health goal"
        )
    if payload.depth not in EXPLANATION_DEPTHS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid guidance depth"
        )
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    workspace.mail_health_goal = payload.goal
    normalized_goal = LEGACY_GOAL_MAP.get(payload.goal, payload.goal)
    if normalized_goal in INSTALLATION_GOALS:
        workspace.guidance_installation_goals = encode_json([normalized_goal])
    user = _auth_user(db, _auth)
    if user is not None:
        user.guidance_depth = payload.depth
        user.guidance_profile_version = PROFILE_VERSION
    else:
        workspace.guidance_depth = payload.depth
    workspace.guidance_profile_version = PROFILE_VERSION
    workspace.guidance_interview_version = PROFILE_VERSION
    workspace.guidance_interview_completed_at = datetime.utcnow()
    db.commit()
    db.refresh(workspace)
    return _guidance_payload(workspace, user)


@router.get("/guidance/preferences")
async def get_personal_guidance_preference(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return the caller's presentation preference or durable workspace fallback."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    profile = _guidance_payload(workspace, _auth_user(db, _auth))
    return {
        key: profile[key]
        for key in (
            "depth",
            "context",
            "teaching_hints_enabled",
            "preference_scope",
            "profile_version",
        )
    }


@router.put("/guidance/preferences")
async def update_personal_guidance_preference(
    payload: PersonalGuidancePreferenceUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Update only the caller's presentation, or the single-user fallback."""
    if payload.depth not in EXPLANATION_DEPTHS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid guidance depth",
        )
    if payload.context not in WORK_CONTEXTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid guidance context",
        )
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    user = _auth_user(db, _auth)
    if user is not None:
        user.guidance_depth = payload.depth
        user.guidance_context = payload.context
        user.guidance_teaching_hints_enabled = payload.teaching_hints_enabled
        user.guidance_profile_version = PROFILE_VERSION
    else:
        workspace = resolve_authorized_workspace(
            db,
            _auth,
            PERMISSION_REPORTS_WRITE,
            selected_workspace_id=parse_selected_workspace_id(selected_workspace),
        )
        workspace.guidance_depth = payload.depth
        workspace.guidance_context = payload.context
        workspace.guidance_teaching_hints_enabled = payload.teaching_hints_enabled
        workspace.guidance_profile_version = PROFILE_VERSION
    db.commit()
    profile = _guidance_payload(workspace, user)
    return {
        key: profile[key]
        for key in (
            "depth",
            "context",
            "teaching_hints_enabled",
            "preference_scope",
            "profile_version",
        )
    }


@router.get("/guidance/workspace-profile")
async def get_workspace_guidance_profile(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return the non-secret workspace context used by guided decisions."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    profile = _guidance_payload(workspace, _auth_user(db, _auth))
    return {
        key: profile[key]
        for key in (
            "installation_goals",
            "sovereignty_preference",
            "notification_posture",
            "mail_context",
            "interview_version",
            "interview_completed",
            "profile_version",
        )
    }


@router.put("/guidance/workspace-profile")
async def update_workspace_guidance_profile(
    payload: WorkspaceGuidanceProfileUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Replace the versioned workspace profile and record one sanitized audit event."""
    goals = []
    for goal in payload.installation_goals:
        if goal not in INSTALLATION_GOALS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid installation goal",
            )
        if goal not in goals:
            goals.append(goal)
    if payload.sovereignty_preference not in SOVEREIGNTY_PREFERENCES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid sovereignty preference",
        )
    if payload.notification_posture not in NOTIFICATION_POSTURES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid notification posture",
        )
    if payload.interview_version < 1 or payload.interview_version > PROFILE_VERSION:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unsupported interview version",
        )
    context = _validated_mail_context(payload.mail_context)
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    previous = _guidance_payload(workspace, _auth_user(db, _auth))
    workspace.guidance_installation_goals = encode_json(goals)
    workspace.mail_health_goal = PRIMARY_GOAL_LEGACY_MAP.get(goals[0], goals[0]) if goals else None
    workspace.sovereignty_preference = payload.sovereignty_preference
    workspace.notification_posture = payload.notification_posture
    workspace.guidance_mail_context = encode_json(context)
    workspace.guidance_profile_version = PROFILE_VERSION
    workspace.guidance_interview_version = payload.interview_version
    workspace.guidance_interview_completed_at = (
        datetime.utcnow() if payload.interview_completed else None
    )
    if payload.interview_completed:
        record_workspace_audit_log(
            db,
            workspace=workspace,
            action="workspace.guidance_profile_updated",
            entity_type="workspace_guidance_profile",
            entity_id=workspace.id,
            entity_name=workspace.name,
            auth_context=_auth,
            request=request,
            details={
                "previous": {
                    "installation_goals": previous["installation_goals"],
                    "sovereignty_preference": previous["sovereignty_preference"],
                    "notification_posture": previous["notification_posture"],
                    "mail_context": previous["mail_context"],
                },
                "current": {
                    "installation_goals": goals,
                    "sovereignty_preference": payload.sovereignty_preference,
                    "notification_posture": payload.notification_posture,
                    "mail_context": context,
                },
                "profile_version": PROFILE_VERSION,
                "interview_version": payload.interview_version,
            },
        )
    db.commit()
    profile = _guidance_payload(workspace, _auth_user(db, _auth))
    return {
        key: profile[key]
        for key in (
            "installation_goals",
            "sovereignty_preference",
            "notification_posture",
            "mail_context",
            "interview_version",
            "interview_completed",
            "profile_version",
        )
    }


@router.get("/guidance/effective")
async def get_effective_guidance_profile(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return the single effective profile consumed by guided pages and APIs."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    return _guidance_payload(workspace, _auth_user(db, _auth))


@router.get("/guidance/diagnostic-plan")
async def get_guidance_diagnostic_plan(
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return one next-step plan derived only from persisted workspace evidence."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    profile = _guidance_payload(workspace, _auth_user(db, _auth))
    evidence = _diagnostic_evidence(db, workspace=workspace, profile=profile)
    locale = resolve_request_locale(
        request, default=getattr(get_settings(), "default_locale", "en")
    )
    plan = build_diagnostic_plan(profile, evidence, locale=locale)
    plan["interview_completed"] = profile["interview_completed"]
    plan["interview_step"] = int(profile["mail_context"].get("interview_step") or 1)
    return plan


@router.get("/guidance/report-intake-recommendation")
async def get_report_intake_recommendation(
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return a deterministic intake choice from stored state and safe preferences."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    profile = _guidance_payload(workspace, _auth_user(db, _auth))
    locale = resolve_request_locale(
        request, default=getattr(get_settings(), "default_locale", "en")
    )
    return build_report_intake_recommendation(
        profile,
        _report_intake_evidence(db, workspace=workspace, profile=profile),
        locale=locale,
    )


@router.put("/guidance/notification-posture")
async def update_notification_posture(
    payload: NotificationPostureUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Choose whether Calm Watch only interrupts for actionable incidents."""
    if payload.posture not in NOTIFICATION_POSTURES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid notification posture"
        )
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    workspace.notification_posture = payload.posture
    db.commit()
    return _guidance_payload(workspace, _auth_user(db, _auth))


@router.get("/mail-health/incidents")
async def get_mail_health_incidents(
    limit: int = 50,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """List only incidents in the caller's authorized workspace."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    return {"incidents": list_mail_health_incidents(db, workspace=workspace, limit=limit)}


@router.post("/mail-health/incidents/evaluate")
async def evaluate_mail_health_incident(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Evaluate one report-backed Calm Watch assessment without sending a notification."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    end = datetime.utcnow()
    assessment = build_workspace_mail_health_assessment(
        db,
        workspace=workspace,
        start_ts=int((end.timestamp() - 30 * 24 * 60 * 60)),
        end_ts=int(end.timestamp()),
    )
    return record_mail_health_assessment(db, workspace=workspace, assessment=assessment)


@router.put("/mail-health/incidents/{incident_id}")
async def update_mail_health_incident(
    incident_id: int,
    payload: IncidentActionUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Acknowledge or snooze an incident without treating it as resolved."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    try:
        snoozed_until = payload.snoozed_until
        if snoozed_until is not None and snoozed_until.tzinfo is not None:
            snoozed_until = snoozed_until.astimezone(timezone.utc).replace(tzinfo=None)
        return update_incident_operator_state(
            db,
            workspace=workspace,
            incident_id=incident_id,
            action=payload.action,
            note=payload.note,
            snoozed_until=snoozed_until,
            auth_context=_auth,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
