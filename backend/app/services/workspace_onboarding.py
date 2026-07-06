"""Workspace onboarding templates and apply helpers."""

from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.organization import Organization, OrganizationMembership
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.organizations import (
    BILLING_MODE_MANUAL_CONTRACT,
    STARTER_PLAN_ENTITLEMENTS,
    ensure_billing_account,
    ensure_entitlements,
    ensure_subscription,
    get_or_create_starter_plan,
    require_organization_plan_limit,
)
from app.services.workspace_access import ROLE_WORKSPACE_OWNER, user_for_auth_context
from app.services.workspace_audit import record_workspace_audit_log, sanitize_audit_details
from app.services.workspaces import normalize_workspace_slug, workspace_domain_query
from app.utils.domain_validator import validate_domain_config

ONBOARDING_SCHEMA_VERSION = "dmarq.workspace_onboarding.v1"

SAFE_NOTIFICATION_DEFAULTS = {
    "notifications.apprise_enabled",
    "notifications.min_send_interval_minutes",
    "notifications.redact_pii_enabled",
    "notifications.alert_new_sources_enabled",
    "notifications.alert_compliance_drop_enabled",
    "notifications.alert_compliance_drop_points",
    "notifications.alert_failure_threshold_enabled",
    "notifications.alert_failure_threshold_count",
    "notifications.alert_missing_reports_enabled",
    "notifications.alert_missing_reports_days",
    "notifications.summary_daily_enabled",
    "notifications.summary_weekly_enabled",
    "notifications.summary_send_hour_utc",
    "notifications.summary_weekday_utc",
    "notifications.remediation_dispatch_enabled",
    "notifications.remediation_dispatch_channel",
    "notifications.remediation_dispatch_require_acknowledgement",
    "notifications.remediation_dispatch_events",
}

NOTIFICATION_SETTING_META = {
    "notifications.apprise_enabled": ("Send notifications through Apprise", "boolean"),
    "notifications.min_send_interval_minutes": ("Minimum minutes between notifications", "integer"),
    "notifications.redact_pii_enabled": ("Redact PII in outbound notifications", "boolean"),
    "notifications.alert_new_sources_enabled": ("Alert when new senders appear", "boolean"),
    "notifications.alert_compliance_drop_enabled": ("Alert on compliance drops", "boolean"),
    "notifications.alert_compliance_drop_points": ("Compliance drop threshold", "integer"),
    "notifications.alert_failure_threshold_enabled": ("Alert on high failure volume", "boolean"),
    "notifications.alert_failure_threshold_count": ("Daily failure-count threshold", "integer"),
    "notifications.alert_missing_reports_enabled": ("Alert when reports stop arriving", "boolean"),
    "notifications.alert_missing_reports_days": ("Days without reports before alerting", "integer"),
    "notifications.summary_daily_enabled": ("Send daily DMARC summaries", "boolean"),
    "notifications.summary_weekly_enabled": ("Send weekly DMARC summaries", "boolean"),
    "notifications.summary_send_hour_utc": ("UTC hour for scheduled summaries", "integer"),
    "notifications.summary_weekday_utc": ("UTC weekday for weekly summaries", "integer"),
    "notifications.remediation_dispatch_enabled": ("Enable remediation dispatch", "boolean"),
    "notifications.remediation_dispatch_channel": ("Remediation dispatch channel", "string"),
    "notifications.remediation_dispatch_require_acknowledgement": (
        "Require remediation lifecycle acknowledgement",
        "boolean",
    ),
    "notifications.remediation_dispatch_events": ("Eligible remediation events", "string"),
}

WORKSPACE_ONBOARDING_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "standard_monitoring",
        "name": "Standard DMARC Monitoring",
        "description": (
            "Create one monitored domain, one disabled IMAP mail source, "
            "and safe notification defaults."
        ),
        "variables": [
            {"name": "domain", "required": True, "example": "example.com"},
            {"name": "workspace_name", "required": False, "example": "Example Client"},
            {"name": "dns_provider", "required": False, "example": "Cloudflare"},
            {"name": "report_mailbox", "required": False, "example": "dmarc@example.com"},
            {"name": "imap_server", "required": False, "example": "imap.example.com"},
            {"name": "imap_username", "required": False, "example": "dmarc@example.com"},
            {"name": "imap_password", "required": False, "secret": True},
        ],
        "domains": [
            {
                "name": "{domain}",
                "description": "Primary DMARC domain for {workspace_name}",
                "dkim_selectors": ["google", "selector1"],
            }
        ],
        "mail_sources": [
            {
                "name": "{workspace_name} DMARC inbox",
                "method": "IMAP",
                "server": "{imap_server}",
                "port": 993,
                "username": "{imap_username}",
                "password": "{imap_password}",
                "folder": "INBOX",
                "use_ssl": True,
                "polling_interval": 60,
                "enabled": False,
            }
        ],
        "notification_defaults": {
            "notifications.apprise_enabled": "false",
            "notifications.redact_pii_enabled": "true",
            "notifications.alert_new_sources_enabled": "true",
            "notifications.alert_compliance_drop_enabled": "true",
            "notifications.alert_compliance_drop_points": "10",
            "notifications.alert_failure_threshold_enabled": "true",
            "notifications.alert_failure_threshold_count": "100",
            "notifications.alert_missing_reports_enabled": "true",
            "notifications.alert_missing_reports_days": "2",
            "notifications.summary_weekly_enabled": "true",
            "notifications.summary_send_hour_utc": "8",
            "notifications.summary_weekday_utc": "0",
        },
        "checklist": [
            {
                "id": "verify-domain-dns",
                "category": "domains",
                "title": "Verify DMARC, SPF, and DKIM DNS posture",
                "description": (
                    "Open the domain DNS view and confirm DMARC, SPF, and each "
                    "configured DKIM selector resolve."
                ),
            },
            {
                "id": "connect-mail-source",
                "category": "mail_sources",
                "title": "Connect the DMARC report inbox",
                "description": (
                    "Add credentials or complete OAuth, run a connection test, "
                    "then enable polling."
                ),
            },
            {
                "id": "run-initial-import",
                "category": "mail_sources",
                "title": "Run an initial DMARC import",
                "description": (
                    "Trigger a manual import for the mail source and confirm " "reports are parsed."
                ),
            },
            {
                "id": "configure-notification-target",
                "category": "notifications",
                "title": "Configure and test notification delivery",
                "description": (
                    "Add Apprise targets, send a test notification, and confirm "
                    "alert thresholds match the client."
                ),
            },
        ],
    },
    {
        "id": "dns_only_assessment",
        "name": "DNS Posture Assessment",
        "description": (
            "Create monitored domains and a validation checklist without " "mailbox ingestion."
        ),
        "variables": [
            {"name": "domain", "required": True, "example": "example.com"},
            {"name": "workspace_name", "required": False, "example": "Example Client"},
            {"name": "dns_provider", "required": False, "example": "Cloudflare"},
        ],
        "domains": [
            {
                "name": "{domain}",
                "description": "DNS posture assessment for {workspace_name}",
                "dkim_selectors": [],
            }
        ],
        "mail_sources": [],
        "notification_defaults": {
            "notifications.apprise_enabled": "false",
            "notifications.alert_missing_reports_enabled": "false",
            "notifications.summary_weekly_enabled": "false",
        },
        "checklist": [
            {
                "id": "verify-domain-dns",
                "category": "domains",
                "title": "Verify published authentication records",
                "description": (
                    "Review DMARC, SPF, DKIM, MTA-STS, and BIMI posture before "
                    "recommending changes."
                ),
            },
            {
                "id": "document-report-inbox",
                "category": "mail_sources",
                "title": "Document the future DMARC report inbox",
                "description": (
                    "Confirm where aggregate reports are delivered before " "enabling ingestion."
                ),
            },
        ],
    },
]


class _SafeFormatDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _render_value(value: Any, variables: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        return value.format_map(
            _SafeFormatDict({k: "" if v is None else v for k, v in variables.items()})
        )
    if isinstance(value, list):
        return [_render_value(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _render_value(item, variables) for key, item in value.items()}
    return value


def _clean_optional_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clean_optional_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean_optional_strings(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return value


def _template_by_id(template_id: str) -> Dict[str, Any]:
    for template in WORKSPACE_ONBOARDING_TEMPLATES:
        if template["id"] == template_id:
            return copy.deepcopy(template)
    raise ValueError(f"Unknown onboarding template: {template_id}")


def list_onboarding_templates() -> List[Dict[str, Any]]:
    """Return static workspace onboarding templates."""
    return copy.deepcopy(WORKSPACE_ONBOARDING_TEMPLATES)


def public_onboarding_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Return an API-safe plan with secret-like values redacted."""
    return sanitize_audit_details(plan)


def _workspace_context(
    workspace: Dict[str, Any],
    variables: Optional[Dict[str, Any]],
) -> Tuple[str, str, Dict[str, Any]]:
    context = {str(key): value for key, value in (variables or {}).items()}
    workspace_name = str(workspace.get("name") or context.get("workspace_name") or "").strip()
    slug = normalize_workspace_slug(str(workspace.get("slug") or workspace_name))
    context.setdefault("workspace_name", workspace_name or slug)
    context.setdefault("domain", "")
    context.setdefault("dns_provider", "")
    context.setdefault("report_mailbox", "")
    context.setdefault("imap_server", "")
    context.setdefault("imap_username", context.get("report_mailbox", ""))
    context.setdefault("imap_password", "")
    return slug, workspace_name, context


def _organization_context(
    organization: Optional[Dict[str, Any]],
    workspace_plan: Dict[str, Any],
) -> Dict[str, Any]:
    organization = organization or {}
    name = str(organization.get("name") or workspace_plan["name"]).strip()
    slug_source = organization.get("slug") or name or workspace_plan["slug"]
    return {
        "slug": normalize_workspace_slug(str(slug_source)),
        "name": name or workspace_plan["name"],
        "description": organization.get("description"),
    }


def _required_variable_errors(template: Dict[str, Any], variables: Dict[str, Any]) -> List[str]:
    errors = []
    for variable in template.get("variables", []):
        name = variable["name"]
        if variable.get("required") and not str(variables.get(name) or "").strip():
            errors.append(f"template variable is required: {name}")
    return errors


def _render_sections(
    template: Dict[str, Any],
    variables: Dict[str, Any],
    *,
    domains: Optional[List[Dict[str, Any]]],
    mail_sources: Optional[List[Dict[str, Any]]],
    notification_defaults: Optional[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    rendered_domains = _clean_optional_strings(
        _render_value(domains if domains is not None else template.get("domains", []), variables)
    )
    rendered_sources = _clean_optional_strings(
        _render_value(
            mail_sources if mail_sources is not None else template.get("mail_sources", []),
            variables,
        )
    )
    rendered_notifications = _clean_optional_strings(
        _render_value(
            (
                notification_defaults
                if notification_defaults is not None
                else template.get("notification_defaults", {})
            ),
            variables,
        )
    )
    return rendered_domains, rendered_sources, rendered_notifications


def _validated_domains(
    rendered_domains: Iterable[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors = []
    validated = []
    for item in rendered_domains:
        name = str(item.get("name") or "").strip().strip(".").lower()
        validation = validate_domain_config(
            {"name": name, "description": item.get("description") or ""}
        )
        if not validation["valid"]:
            errors.append(f"invalid domain {name or '<empty>'}: {validation['errors']}")
            continue
        selectors = [
            str(selector).strip()
            for selector in item.get("dkim_selectors") or []
            if str(selector).strip()
        ]
        validated.append(
            {
                "name": name,
                "description": item.get("description"),
                "dkim_selectors": selectors,
            }
        )
    return validated, errors


def _validated_mail_sources(
    rendered_sources: Iterable[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors = []
    validated = []
    for item in rendered_sources:
        name = str(item.get("name") or "").strip()
        method = str(item.get("method") or "IMAP").strip().upper()
        if not name:
            errors.append("mail source name is required")
            continue
        if method not in {"IMAP", "POP3", "GMAIL_API", "M365_GRAPH"}:
            errors.append(f"unsupported mail source method: {method}")
            continue
        validated.append(
            {
                "name": name,
                "method": method,
                "server": item.get("server"),
                "port": int(item.get("port") or 993),
                "username": item.get("username"),
                "password": item.get("password"),
                "use_ssl": bool(item.get("use_ssl", True)),
                "folder": item.get("folder") or "INBOX",
                "polling_interval": int(item.get("polling_interval") or 60),
                "enabled": bool(item.get("enabled", False)),
                "gmail_client_id": item.get("gmail_client_id"),
                "gmail_client_secret": item.get("gmail_client_secret"),
                "m365_tenant_id": item.get("m365_tenant_id") or "common",
                "m365_client_id": item.get("m365_client_id"),
                "m365_client_secret": item.get("m365_client_secret"),
                "m365_mailbox": item.get("m365_mailbox"),
                "m365_folder_id": item.get("m365_folder_id"),
            }
        )
    return validated, errors


def _validated_notification_defaults(
    rendered_notifications: Dict[str, Any],
) -> Tuple[Dict[str, str], List[str]]:
    errors = []
    safe_notifications = {}
    for key, value in (rendered_notifications or {}).items():
        if key not in SAFE_NOTIFICATION_DEFAULTS:
            errors.append(f"unsupported notification default: {key}")
            continue
        safe_notifications[key] = "" if value is None else str(value)
    return safe_notifications, errors


def _validated_sections(
    rendered_domains: Iterable[Dict[str, Any]],
    rendered_sources: Iterable[Dict[str, Any]],
    rendered_notifications: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str], List[str]]:
    domains, domain_errors = _validated_domains(rendered_domains)
    sources, source_errors = _validated_mail_sources(rendered_sources)
    notifications, notification_errors = _validated_notification_defaults(rendered_notifications)
    return domains, sources, notifications, domain_errors + source_errors + notification_errors


def _actionable_tasks(
    plan: Dict[str, Any],
    *,
    domain_results: Optional[Iterable[Dict[str, Any]]] = None,
    source_results: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    domain_by_name = {item["name"]: item for item in domain_results or []}
    source_by_name = {item["name"]: item for item in source_results or []}
    domains = plan.get("domains") or []
    sources = plan.get("mail_sources") or []
    dns_provider = (plan.get("variables") or {}).get("dns_provider") or "your DNS provider"
    tasks: List[Dict[str, Any]] = []

    for domain in domains:
        name = domain["name"]
        result = domain_by_name.get(name, {})
        tasks.append(
            {
                "id": f"verify-domain-dns:{name}",
                "category": "domains",
                "status": "pending",
                "title": f"Verify DNS records for {name}",
                "description": (
                    f"Review DMARC, SPF, and DKIM in {dns_provider}; keep production "
                    "monitoring pending until ownership is verified."
                ),
                "href": f"/domains/{name}",
                "api_hint": f"/api/v1/domains/{result.get('id', ':domain_id')}/dns",
                "target": {
                    "type": "domain",
                    "name": name,
                    "id": result.get("id"),
                    "requires_verification": True,
                },
            }
        )

    for source in sources:
        name = source["name"]
        result = source_by_name.get(name, {})
        tasks.append(
            {
                "id": f"connect-mail-source:{name}",
                "category": "mail_sources",
                "status": "pending",
                "title": f"Connect {name}",
                "description": (
                    "Add the report inbox credentials, run a connection test, and enable "
                    "polling after the first successful import."
                ),
                "href": "/mail-sources",
                "api_hint": f"/api/v1/mail-sources/{result.get('id', ':source_id')}/test",
                "target": {
                    "type": "mail_source",
                    "name": name,
                    "id": result.get("id"),
                },
            }
        )
        tasks.append(
            {
                "id": f"run-initial-import:{name}",
                "category": "mail_sources",
                "status": "pending",
                "title": f"Run the first import for {name}",
                "description": "Import the latest aggregate reports and confirm DMARQ parsed them.",
                "href": "/reports",
                "api_hint": f"/api/v1/mail-sources/{result.get('id', ':source_id')}/import",
                "target": {
                    "type": "mail_source",
                    "name": name,
                    "id": result.get("id"),
                },
            }
        )

    if plan.get("notification_defaults"):
        tasks.append(
            {
                "id": "configure-notification-target",
                "category": "notifications",
                "status": "pending",
                "title": "Configure alert delivery",
                "description": (
                    "Add Apprise targets and send a test notification before relying on alerts."
                ),
                "href": "/settings/notifications",
                "api_hint": "/api/v1/settings/notifications/test",
                "target": {"type": "notification_settings"},
            }
        )

    if not sources:
        tasks.append(
            {
                "id": "document-report-inbox",
                "category": "mail_sources",
                "status": "pending",
                "title": "Document the future report inbox",
                "description": (
                    "Capture the RUA/RUF destination before enabling automated report ingestion."
                ),
                "href": "/mail-sources",
                "api_hint": "/api/v1/mail-sources",
                "target": {"type": "mail_source"},
            }
        )

    return tasks


def build_onboarding_plan(  # pylint: disable=too-many-locals
    *,
    template_id: str,
    organization: Optional[Dict[str, Any]] = None,
    workspace: Dict[str, Any],
    variables: Optional[Dict[str, Any]] = None,
    domains: Optional[List[Dict[str, Any]]] = None,
    mail_sources: Optional[List[Dict[str, Any]]] = None,
    notification_defaults: Optional[Dict[str, Any]] = None,
    overwrite_existing: bool = False,
) -> Dict[str, Any]:
    """Render and validate a workspace onboarding plan."""
    template = _template_by_id(template_id)
    slug, workspace_name, variables = _workspace_context(workspace, variables)
    errors: List[str] = []
    if not slug:
        errors.append("workspace.slug or workspace.name is required")
    if not workspace_name:
        errors.append("workspace.name is required")
    workspace_plan = {
        "slug": slug,
        "name": workspace_name,
        "description": workspace.get("description"),
    }
    organization_plan = _organization_context(organization, workspace_plan)
    if not organization_plan["slug"]:
        errors.append("organization.slug or organization.name is required")
    errors.extend(_required_variable_errors(template, variables))
    rendered_domains, rendered_sources, rendered_notifications = _render_sections(
        template,
        variables,
        domains=domains,
        mail_sources=mail_sources,
        notification_defaults=notification_defaults,
    )
    validated_domains, validated_sources, safe_notifications, section_errors = _validated_sections(
        rendered_domains, rendered_sources, rendered_notifications
    )
    errors.extend(section_errors)

    plan = {
        "schema_version": ONBOARDING_SCHEMA_VERSION,
        "template_id": template_id,
        "template_name": template["name"],
        "organization": organization_plan,
        "workspace": workspace_plan,
        "variables": variables,
        "domains": validated_domains,
        "mail_sources": validated_sources,
        "notification_defaults": safe_notifications,
        "checklist": copy.deepcopy(template.get("checklist", [])),
        "tasks": [],
        "overwrite_existing": overwrite_existing,
        "errors": errors,
    }
    plan["tasks"] = _actionable_tasks(plan)
    return plan


def _ensure_organization(
    db: Session, organization_plan: Dict[str, Any]
) -> Tuple[Organization, str]:
    organization = (
        db.query(Organization).filter(Organization.slug == organization_plan["slug"]).first()
    )
    if organization:
        return organization, "existing"
    organization = Organization(
        slug=organization_plan["slug"],
        name=organization_plan["name"],
        description=organization_plan.get("description"),
        active=True,
    )
    db.add(organization)
    db.flush()
    return organization, "created"


def _ensure_workspace(
    db: Session,
    workspace_plan: Dict[str, Any],
    organization: Organization,
) -> Tuple[Workspace, str]:
    workspace = db.query(Workspace).filter(Workspace.slug == workspace_plan["slug"]).first()
    if workspace:
        if workspace.organization_id is None:
            workspace.organization_id = organization.id
            db.flush()
            return workspace, "linked_existing"
        if workspace.organization_id != organization.id:
            raise ValueError("Workspace is already attached to another organization")
        return workspace, "existing"
    workspace = Workspace(
        organization_id=organization.id,
        slug=workspace_plan["slug"],
        name=workspace_plan["name"],
        description=workspace_plan.get("description"),
        active=True,
    )
    db.add(workspace)
    db.flush()
    return workspace, "created"


def _apply_domains(
    db: Session,
    *,
    workspace: Workspace,
    domain_plans: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for item in domain_plans:
        existing = workspace_domain_query(db, workspace).filter(Domain.name == item["name"]).first()
        if existing:
            results.append({"name": item["name"], "status": "existing", "id": existing.id})
            continue
        owned_elsewhere = (
            db.query(Domain)
            .filter(Domain.name == item["name"], Domain.workspace_id != workspace.id)
            .first()
        )
        if owned_elsewhere:
            results.append(
                {
                    "name": item["name"],
                    "status": "conflict",
                    "message": "Domain is already owned by another workspace",
                }
            )
            continue
        if workspace.organization:
            require_organization_plan_limit(
                db,
                workspace.organization,
                "monitored_domains",
            )
        domain = Domain(
            workspace_id=workspace.id,
            name=item["name"],
            description=item.get("description"),
            dkim_selectors=",".join(item.get("dkim_selectors") or []) or None,
            active=True,
            verified=False,
        )
        db.add(domain)
        db.flush()
        results.append({"name": domain.name, "status": "created", "id": domain.id})
    return results


def _apply_mail_sources(
    db: Session,
    *,
    workspace: Workspace,
    source_plans: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    source_plans_list = list(source_plans)
    source_names = [item["name"] for item in source_plans_list]
    existing_sources = (
        db.query(MailSource)
        .filter(
            MailSource.workspace_id == workspace.id,
            MailSource.name.in_(source_names)
        )
        .all()
    ) if source_names else []
    existing_by_name = {source.name: source for source in existing_sources}

    for item in source_plans_list:
        existing = existing_by_name.get(item["name"])
        if existing:
            results.append({"name": item["name"], "status": "existing", "id": existing.id})
            continue
        source = MailSource(
            workspace_id=workspace.id,
            name=item["name"],
            method=item["method"],
            server=item.get("server"),
            port=item.get("port") or 993,
            username=item.get("username"),
            password=item.get("password"),
            use_ssl=item.get("use_ssl", True),
            folder=item.get("folder") or "INBOX",
            polling_interval=item.get("polling_interval") or 60,
            enabled=item.get("enabled", False),
            gmail_client_id=item.get("gmail_client_id"),
            gmail_client_secret=item.get("gmail_client_secret"),
            m365_tenant_id=item.get("m365_tenant_id") or "common",
            m365_client_id=item.get("m365_client_id"),
            m365_client_secret=item.get("m365_client_secret"),
            m365_mailbox=item.get("m365_mailbox"),
            m365_folder_id=item.get("m365_folder_id"),
        )
        db.add(source)
        db.flush()
        results.append({"name": source.name, "status": "created", "id": source.id})
        # Add to existing_by_name in case there are duplicates in the source_plans_list
        existing_by_name[source.name] = source
    return results


def _apply_notification_defaults(
    db: Session,
    *,
    defaults: Dict[str, str],
    overwrite_existing: bool,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for key, value in defaults.items():
        row = db.query(Setting).filter(Setting.key == key).first()
        if row and not overwrite_existing:
            results.append({"key": key, "status": "existing"})
            continue
        if row:
            row.value = value
            results.append({"key": key, "status": "updated"})
            continue
        description, value_type = NOTIFICATION_SETTING_META.get(
            key, ("Workspace onboarding default", "string")
        )
        db.add(
            Setting(
                key=key,
                value=value,
                description=description,
                value_type=value_type,
                category="notifications",
            )
        )
        results.append({"key": key, "status": "created"})
    return results


def _ensure_owner_memberships(
    db: Session,
    *,
    organization: Organization,
    workspace: Workspace,
    auth_context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    owner = user_for_auth_context(db, auth_context or {})
    if owner is None:
        return {"status": "skipped", "reason": "no authenticated local user"}

    organization_membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == owner.id,
        )
        .first()
    )
    organization_status = "existing"
    if organization_membership is None:
        organization_membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role="organization_owner",
            active=True,
        )
        db.add(organization_membership)
        organization_status = "created"
    else:
        if organization_membership.role != "organization_owner":
            organization_membership.role = "organization_owner"
            organization_status = "updated"
        if not organization_membership.active:
            organization_membership.active = True
            organization_status = "reactivated"

    workspace_membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == owner.id,
        )
        .first()
    )
    workspace_status = "existing"
    if workspace_membership is None:
        workspace_membership = WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=owner.id,
            role=ROLE_WORKSPACE_OWNER,
            active=True,
        )
        db.add(workspace_membership)
        workspace_status = "created"
    else:
        if workspace_membership.role != ROLE_WORKSPACE_OWNER:
            workspace_membership.role = ROLE_WORKSPACE_OWNER
            workspace_status = "updated"
        if not workspace_membership.active:
            workspace_membership.active = True
            workspace_status = "reactivated"

    if owner.workspace_id is None:
        owner.workspace_id = workspace.id
    db.flush()
    return {
        "status": "ready",
        "user_id": owner.id,
        "email": owner.email,
        "organization_membership": organization_status,
        "workspace_membership": workspace_status,
    }


def _ensure_starter_subscription(
    db: Session,
    *,
    organization: Organization,
) -> Dict[str, Any]:
    plan = get_or_create_starter_plan(db, commit=False)
    account = ensure_billing_account(
        db,
        organization,
        billing_mode=BILLING_MODE_MANUAL_CONTRACT,
        commit=False,
    )
    subscription = ensure_subscription(
        db,
        organization,
        plan,
        account,
        commit=False,
    )
    entitlements = ensure_entitlements(
        db,
        organization,
        subscription,
        STARTER_PLAN_ENTITLEMENTS,
        commit=False,
    )
    db.flush()
    return {
        "billing_account": {
            "id": account.id,
            "billing_mode": account.billing_mode,
            "status": account.status,
            "invoice_delivery_mode": account.invoice_delivery_mode,
        },
        "subscription": {
            "id": subscription.id,
            "status": subscription.status,
            "plan_code": plan.code,
            "billing_mode": subscription.billing_mode,
        },
        "entitlements": {
            entitlement.key: entitlement.value
            for entitlement in sorted(entitlements, key=lambda item: item.key)
        },
    }


def apply_onboarding_plan(
    db: Session,
    *,
    plan: Dict[str, Any],
    auth_context: Optional[Dict[str, Any]],
    request=None,
) -> Dict[str, Any]:
    """Apply a validated onboarding plan and return an API-safe result."""
    if plan.get("errors"):
        raise ValueError("Cannot apply an invalid onboarding plan")
    try:
        organization, organization_status = _ensure_organization(db, plan["organization"])
        workspace, workspace_status = _ensure_workspace(db, plan["workspace"], organization)
        owner_result = _ensure_owner_memberships(
            db,
            organization=organization,
            workspace=workspace,
            auth_context=auth_context,
        )
        commercial_result = _ensure_starter_subscription(db, organization=organization)
        domain_results = _apply_domains(db, workspace=workspace, domain_plans=plan["domains"])
        source_results = _apply_mail_sources(
            db,
            workspace=workspace,
            source_plans=plan["mail_sources"],
        )
        notification_results = _apply_notification_defaults(
            db,
            defaults=plan["notification_defaults"],
            overwrite_existing=bool(plan.get("overwrite_existing")),
        )
        conflicts = [item for item in domain_results if item["status"] == "conflict"]
        if conflicts:
            db.rollback()
            return {
                "applied": False,
                "workspace": plan["workspace"],
                "organization": plan["organization"],
                "errors": [item["message"] for item in conflicts],
                "results": {"domains": domain_results},
            }
        tasks = _actionable_tasks(
            plan,
            domain_results=domain_results,
            source_results=source_results,
        )
        record_workspace_audit_log(
            db,
            workspace=workspace,
            action="workspace.onboarding_applied",
            entity_type="workspace",
            entity_id=workspace.id,
            entity_name=workspace.slug,
            details={
                "template_id": plan["template_id"],
                "organization_status": organization_status,
                "workspace_status": workspace_status,
                "owner": owner_result,
                "subscription": commercial_result["subscription"],
                "domains": domain_results,
                "mail_sources": source_results,
                "notification_defaults": notification_results,
                "checklist_ids": [item["id"] for item in plan.get("checklist", [])],
                "task_ids": [item["id"] for item in tasks],
            },
            auth_context=auth_context,
            request=request,
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise

    db.refresh(workspace)
    return public_onboarding_plan(
        {
            "applied": True,
            "schema_version": plan["schema_version"],
            "template_id": plan["template_id"],
            "organization": {
                "id": organization.id,
                "slug": organization.slug,
                "name": organization.name,
                "status": organization_status,
            },
            "workspace": {
                "id": workspace.id,
                "slug": workspace.slug,
                "name": workspace.name,
                "status": workspace_status,
            },
            "owner": owner_result,
            "billing_account": commercial_result["billing_account"],
            "subscription": commercial_result["subscription"],
            "entitlements": commercial_result["entitlements"],
            "results": {
                "domains": domain_results,
                "mail_sources": source_results,
                "notification_defaults": notification_results,
            },
            "checklist": plan.get("checklist", []),
            "tasks": tasks,
        }
    )
