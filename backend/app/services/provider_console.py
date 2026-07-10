"""Provider site-manager console assembled from the normal tenant data model."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.models.domain import Domain
from app.models.organization import (
    BillingAccount,
    Organization,
    OrganizationMembership,
    Plan,
    ProviderIntegration,
    Subscription,
)
from app.models.report import DMARCReport
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _report_messages(report: DMARCReport) -> int:
    return sum(max(0, int(record.count or 0)) for record in report.records)


def _report_passed_messages(report: DMARCReport) -> int:
    return sum(
        max(0, int(record.count or 0))
        for record in report.records
        if record.dkim == "pass" or record.spf == "pass"
    )


def _plan_payload(plan: Plan) -> Dict[str, Any]:
    return {
        "code": plan.code,
        "label": plan.name,
        "monthly_charge_cents": int(plan.monthly_price_cents or 0),
        "domains": int(plan.included_sending_domains or 0),
        "users": int(plan.included_users or 0),
        "messages": int(plan.included_message_volume or 0),
        "retention_days": int(plan.retention_days or 0),
    }


def _billing_status(subscription: Optional[Subscription]) -> str:
    status = (subscription.status if subscription is not None else "").lower()
    return {
        "active": "current",
        "trialing": "trial",
        "past_due": "past_due",
        "past_due_provider_reported": "past_due",
        "unpaid": "past_due",
        "suspended": "past_due",
        "canceled": "canceled",
        "cancelled": "canceled",
    }.get(status, status or "unconfigured")


def _account_status(
    organization: Organization,
    subscription: Optional[Subscription],
    report_count: int,
) -> str:
    if not organization.active:
        return "suspended"
    subscription_status = (subscription.status if subscription is not None else "").lower()
    if subscription_status in {"suspended", "canceled", "cancelled", "unpaid"}:
        return "suspended"
    if report_count == 0:
        return "onboarding"
    return "active"


def _health(compliance_rate: float, domains: List[Domain], report_count: int) -> str:
    if report_count == 0:
        return "monitoring"
    if compliance_rate < 80:
        return "critical"
    if compliance_rate < 95 or any(not domain.verified for domain in domains):
        return "attention"
    return "healthy"


def _recommended_action(
    health: str,
    domains: List[Domain],
    report_count: int,
) -> str:
    if not domains:
        return "Erste Versanddomain anlegen und den DNS-Besitz bestätigen."
    if report_count == 0:
        return "Report-Mailbox verbinden und den ersten DMARC-Report importieren."
    if health == "critical":
        return (
            "Fehlgeschlagene Sender priorisieren und DKIM/SPF vor einer Policy-Änderung reparieren."
        )
    if any((domain.dmarc_policy or "none") == "none" for domain in domains):
        return "Unbekannte Sender klären und anschließend die DMARC-Policy verschärfen."
    if any((domain.dmarc_policy or "none") != "reject" for domain in domains):
        return "Reject-Rollout vorbereiten und nach der Änderung sieben Tage überwachen."
    return "Aktuelle Policy beibehalten und neue Senderabweichungen überwachen."


def _user_rows(
    organization: Organization,
    workspaces: List[Workspace],
    workspace_memberships: Dict[int, List[WorkspaceMembership]],
) -> List[Dict[str, Any]]:
    roles: Dict[int, str] = {}
    users_by_id: Dict[int, User] = {}
    for membership in organization.memberships:
        if not membership.active or membership.user is None:
            continue
        roles[membership.user_id] = membership.role
        users_by_id[membership.user_id] = membership.user
    for workspace in workspaces:
        for membership in workspace_memberships.get(workspace.id, []):
            if not membership.active or membership.user is None:
                continue
            roles.setdefault(membership.user_id, membership.role)
            users_by_id[membership.user_id] = membership.user
    if not roles:
        return []
    users = sorted(
        (users_by_id[user_id] for user_id in roles if user_id in users_by_id),
        key=lambda user: user.email,
    )
    return [
        {
            "id": user.id,
            "name": user.full_name or user.email,
            "email": user.email,
            "role": roles[user.id],
            "status": "active" if user.is_active else "inactive",
            "last_active_at": _iso(user.updated_at or user.created_at),
            "mfa_enabled": bool(user.is_verified),
            "can_impersonate": bool(
                user.is_active and roles[user.id] not in {"auditor", "organization_auditor"}
            ),
        }
        for user in users
    ]


def _domain_rows(
    domains: List[Domain],
    reports_by_domain: Dict[int, List[DMARCReport]],
    *,
    period_start: datetime,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for domain in domains:
        reports = reports_by_domain.get(domain.id, [])
        recent = [
            report for report in reports if (report.processed_at or datetime.min) >= period_start
        ]
        messages = sum(_report_messages(report) for report in recent)
        passed = sum(_report_passed_messages(report) for report in recent)
        compliance_rate = round((passed / messages) * 100, 1) if messages else 0.0
        source_count = len(
            {record.source_ip for report in recent for record in report.records if record.source_ip}
        )
        findings: List[str] = []
        if not domain.verified:
            findings.append("DNS-Besitz ist noch nicht bestätigt.")
        if messages == 0:
            findings.append("Für die letzten 30 Tage liegen keine Reports vor.")
        elif compliance_rate < 95:
            findings.append("Authentifizierungsquote liegt unter 95 %.")
        if (domain.dmarc_policy or "none") == "none":
            findings.append("DMARC befindet sich noch im Monitoring-Modus.")
        if not findings:
            findings.append("Keine akuten Findings; Policy und neue Sender weiter überwachen.")
        last_report = max(
            (report.processed_at for report in reports if report.processed_at), default=None
        )
        domain_health = _health(compliance_rate, [domain], len(recent))
        rows.append(
            {
                "id": domain.id,
                "name": domain.name,
                "health": domain_health,
                "policy": domain.dmarc_policy or "none",
                "compliance_rate": compliance_rate,
                "messages_30d": messages,
                "reports_30d": len(recent),
                "source_count": source_count,
                "spf_alignment": compliance_rate,
                "dkim_alignment": compliance_rate,
                "last_report_at": _iso(last_report),
                "open_findings": findings,
            }
        )
    return rows


def _report_rows(reports: Iterable[DMARCReport]) -> List[Dict[str, Any]]:
    rows = []
    for report in sorted(
        reports,
        key=lambda row: (row.processed_at or datetime.min, row.id),
        reverse=True,
    )[:12]:
        messages = _report_messages(report)
        passed = _report_passed_messages(report)
        rows.append(
            {
                "id": report.report_id,
                "provider": report.org_name,
                "domain": report.domain.name,
                "period_start": datetime.fromtimestamp(report.begin_date, timezone.utc)
                .date()
                .isoformat(),
                "period_end": datetime.fromtimestamp(report.end_date, timezone.utc)
                .date()
                .isoformat(),
                "received_at": _iso(report.processed_at),
                "messages": messages,
                "pass_rate": round((passed / messages) * 100, 1) if messages else 0.0,
                "status": "processed",
            }
        )
    return rows


def _activity_rows(rows: List[WorkspaceAuditLog]) -> List[Dict[str, Any]]:
    activity = []
    for row in rows[:12]:
        details: Dict[str, Any] = {}
        if row.details:
            try:
                details = json.loads(row.details)
            except (TypeError, ValueError):
                details = {}
        activity.append(
            {
                "id": row.id,
                "occurred_at": _iso(row.created_at),
                "actor": row.actor_id or row.actor_type,
                "action": row.action,
                "summary": details.get("summary") or row.entity_name or row.action,
            }
        )
    return activity


def _account_payload(  # pylint: disable=too-many-locals
    organization: Organization,
    *,
    period_start: datetime,
    workspace_memberships: Dict[int, List[WorkspaceMembership]],
    audits: List[WorkspaceAuditLog],
) -> Dict[str, Any]:
    workspaces = sorted(
        organization.workspaces,
        key=lambda workspace: (not workspace.active, workspace.slug),
    )
    domains = sorted(
        (domain for workspace in workspaces for domain in workspace.domains if domain.active),
        key=lambda domain: domain.name,
    )
    reports = sorted(
        (report for domain in domains for report in domain.reports),
        key=lambda report: (report.processed_at or datetime.min, report.id),
        reverse=True,
    )
    reports_by_domain: Dict[int, List[DMARCReport]] = {}
    for report in reports:
        reports_by_domain.setdefault(report.domain_id, []).append(report)
    recent_reports = [
        report for report in reports if (report.processed_at or datetime.min) >= period_start
    ]
    messages = sum(_report_messages(report) for report in recent_reports)
    passed = sum(_report_passed_messages(report) for report in recent_reports)
    compliance_rate = round((passed / messages) * 100, 1) if messages else 0.0
    users = _user_rows(organization, workspaces, workspace_memberships)
    primary_contact = next(
        (user for user in users if user["role"] in {"organization_owner", "workspace_owner"}),
        users[0] if users else None,
    ) or {"name": "Nicht zugewiesen", "email": "Nicht zugewiesen"}
    subscriptions = sorted(
        organization.subscriptions,
        key=lambda subscription: (subscription.created_at or datetime.min, subscription.id),
        reverse=True,
    )
    subscription = subscriptions[0] if subscriptions else None
    plan = subscription.plan if subscription is not None else None
    billing_accounts = sorted(organization.billing_accounts, key=lambda account: account.id)
    billing_account = billing_accounts[0] if billing_accounts else None
    domain_rows = _domain_rows(domains, reports_by_domain, period_start=period_start)
    health = _health(compliance_rate, domains, len(recent_reports))
    completed_steps = sum(
        [
            bool(domains),
            bool(users),
            bool(reports),
            all(domain.verified for domain in domains),
            bool(plan),
        ]
    )
    retention = max((workspace.report_retention_days for workspace in workspaces), default=0)
    account_status = _account_status(organization, subscription, len(reports))
    return {
        "id": organization.id,
        "organization_id": organization.id,
        "workspace_id": workspaces[0].id if workspaces else None,
        "slug": organization.slug,
        "customer_number": (
            billing_account.external_customer_id
            if billing_account and billing_account.external_customer_id
            else f"DM-{organization.id:05d}"
        ),
        "name": organization.name,
        "short_name": organization.name,
        "status": account_status,
        "health": health,
        "plan_code": plan.code if plan is not None else "unconfigured",
        "plan_label": plan.name if plan is not None else "Kein Plan",
        "created_at": _iso(organization.created_at),
        "last_activity_at": _iso(max((report.processed_at for report in reports), default=None)),
        "primary_contact": {
            "name": primary_contact["name"],
            "email": primary_contact["email"],
            "phone": "Im Identity Provider verwaltet",
        },
        "billing": {
            "status": _billing_status(subscription),
            "invoice_owner": "Provider" if billing_account else "DMARQ",
            "collection_model": (
                billing_account.billing_mode if billing_account else "unconfigured"
            ),
            "payment_rail": (
                billing_account.invoice_delivery_mode if billing_account else "unconfigured"
            ),
            "invoice_reference": (
                billing_account.tax_reference
                if billing_account and billing_account.tax_reference
                else (
                    billing_account.external_customer_id
                    if billing_account
                    else "Nicht konfiguriert"
                )
            ),
            "billing_contact": (
                billing_account.billing_contact_email
                if billing_account and billing_account.billing_contact_email
                else primary_contact["email"]
            ),
            "monthly_charge_cents": int(
                subscription.monthly_price_cents
                if subscription and subscription.monthly_price_cents is not None
                else plan.monthly_price_cents if plan else 0
            ),
            "next_invoice_at": _iso(subscription.current_period_end if subscription else None),
            "external_subscription_id": (
                subscription.external_subscription_id if subscription else None
            ),
            "provider_id": billing_account.provider_id if billing_account else None,
        },
        "usage": {
            "messages_30d": messages,
            "reports_30d": len(recent_reports),
            "compliance_rate": compliance_rate,
            "change_percent": 0.0,
        },
        "entitlements": {
            "domains": {
                "used": len(domains),
                "included": int(plan.included_sending_domains or 0) if plan else 0,
            },
            "users": {
                "used": len(users),
                "included": int(plan.included_users or 0) if plan else 0,
            },
            "messages": {
                "used": messages,
                "included": int(plan.included_message_volume or 0) if plan else 0,
            },
            "retention_days": {
                "used": retention,
                "included": int(plan.retention_days or 0) if plan else 0,
            },
        },
        "onboarding": {
            "completed_steps": completed_steps,
            "total_steps": 5,
            "next_step": _recommended_action(health, domains, len(reports)),
        },
        "recommended_action": _recommended_action(health, domains, len(reports)),
        "domains": domain_rows,
        "users": users,
        "reports": _report_rows(reports),
        "activity": _activity_rows(audits),
        "settings": {
            "report_mailbox": next(
                (domain.dmarc_report_mailbox for domain in domains if domain.dmarc_report_mailbox),
                "Nicht konfiguriert",
            ),
            "timezone": "Europe/Berlin",
            "weekly_digest": True,
            "ai_redaction": "strict",
        },
    }


def _workspace_memberships_for_console(
    db: Session,
    workspace_ids: List[int],
) -> Dict[int, List[WorkspaceMembership]]:
    grouped: Dict[int, List[WorkspaceMembership]] = {}
    if not workspace_ids:
        return grouped
    rows = (
        db.query(WorkspaceMembership)
        .options(selectinload(WorkspaceMembership.user))
        .filter(
            WorkspaceMembership.workspace_id.in_(workspace_ids),
            WorkspaceMembership.active.is_(True),
        )
        .all()
    )
    for row in rows:
        grouped.setdefault(row.workspace_id, []).append(row)
    return grouped


def _recent_audits_for_console(
    db: Session,
    organization_ids: List[int],
) -> Dict[int, List[WorkspaceAuditLog]]:
    grouped: Dict[int, List[WorkspaceAuditLog]] = {}
    if not organization_ids:
        return grouped
    ranked = (
        db.query(
            WorkspaceAuditLog.id.label("audit_id"),
            Workspace.organization_id.label("organization_id"),
            func.row_number()
            .over(
                partition_by=Workspace.organization_id,
                order_by=(
                    WorkspaceAuditLog.created_at.desc(),
                    WorkspaceAuditLog.id.desc(),
                ),
            )
            .label("position"),
        )
        .join(Workspace, Workspace.id == WorkspaceAuditLog.workspace_id)
        .filter(Workspace.organization_id.in_(organization_ids))
        .subquery()
    )
    rows = (
        db.query(WorkspaceAuditLog, ranked.c.organization_id)
        .join(ranked, ranked.c.audit_id == WorkspaceAuditLog.id)
        .filter(ranked.c.position <= 12)
        .order_by(
            ranked.c.organization_id.asc(),
            WorkspaceAuditLog.created_at.desc(),
            WorkspaceAuditLog.id.desc(),
        )
        .all()
    )
    for audit, organization_id in rows:
        grouped.setdefault(int(organization_id), []).append(audit)
    return grouped


def build_provider_console(
    db: Session,
    *,
    organization_ids: Optional[Iterable[int]] = None,
    operator: Optional[Dict[str, Any]] = None,
    demo_mode: bool = False,
    today: Optional[date] = None,
) -> Dict[str, Any]:
    """Build the site-manager console from persisted provider account data."""
    anchor = today or date.today()
    period_start = datetime.combine(anchor - timedelta(days=29), datetime.min.time())
    query = (
        db.query(Organization)
        .options(
            selectinload(Organization.workspaces)
            .selectinload(Workspace.domains)
            .selectinload(Domain.reports)
            .selectinload(DMARCReport.records),
            selectinload(Organization.memberships).selectinload(OrganizationMembership.user),
            selectinload(Organization.billing_accounts),
            selectinload(Organization.subscriptions).selectinload(Subscription.plan),
        )
        .join(BillingAccount, BillingAccount.organization_id == Organization.id)
        .filter(BillingAccount.billing_mode.like("provider_%"))
        .distinct()
    )
    if organization_ids is not None:
        ids = [int(value) for value in organization_ids]
        query = query.filter(Organization.id.in_(ids or [-1]))
    organizations = query.order_by(Organization.active.desc(), Organization.name.asc()).all()
    organization_id_list = [organization.id for organization in organizations]
    workspace_ids = [
        workspace.id for organization in organizations for workspace in organization.workspaces
    ]
    workspace_memberships = _workspace_memberships_for_console(db, workspace_ids)
    audits_by_organization = _recent_audits_for_console(db, organization_id_list)
    accounts = [
        _account_payload(
            organization,
            period_start=period_start,
            workspace_memberships=workspace_memberships,
            audits=audits_by_organization.get(organization.id, []),
        )
        for organization in organizations
    ]
    plans = (
        db.query(Plan)
        .filter(Plan.active.is_(True), Plan.billing_mode.like("provider_%"))
        .order_by(Plan.monthly_price_cents.asc())
        .all()
    )
    integration = (
        db.query(ProviderIntegration)
        .filter(ProviderIntegration.organization_id.is_(None))
        .order_by(ProviderIntegration.id.asc())
        .first()
    )
    operator = operator or {
        "id": "site-manager",
        "name": "Site Manager",
        "email": "Aktuelle Sitzung",
        "role": "site_manager",
    }
    monthly_messages = sum(account["usage"]["messages_30d"] for account in accounts)
    monthly_revenue = sum(
        account["billing"]["monthly_charge_cents"]
        for account in accounts
        if account["billing"]["status"] not in {"trial", "canceled"}
    )
    weighted_pass = sum(
        account["usage"]["messages_30d"] * account["usage"]["compliance_rate"]
        for account in accounts
    )
    allowed_targets = [
        {
            "account_slug": account["slug"],
            "organization_id": account["organization_id"],
            "workspace_id": account["workspace_id"],
            "workspace_slug": account["slug"],
            "domain": account["domains"][0]["name"] if account["domains"] else None,
            "target_user_id": user["id"],
            "target_user": user["email"],
            "target_user_name": user["name"],
            "target_role": user["role"],
            "health": account["health"],
        }
        for account in accounts
        for user in account["users"]
        if user["can_impersonate"] and account["workspace_id"] is not None
    ]
    settings = get_settings()
    provider_slug = integration.external_provider_id if integration else settings.PROVIDER_SLUG
    provider_name = integration.name if integration else settings.PROVIDER_DISPLAY_NAME
    return {
        "source": "provider_accounts_db_v1",
        "generated_for": anchor.isoformat(),
        "demo_mode": demo_mode,
        "provider": {
            "id": integration.id if integration else "provider",
            "slug": provider_slug,
            "name": provider_name,
            "operator": operator,
            "support_email": operator.get("email"),
            "billing_reference": provider_slug,
        },
        "summary": {
            "accounts": len(accounts),
            "active_accounts": sum(1 for account in accounts if account["status"] == "active"),
            "at_risk_accounts": sum(
                1 for account in accounts if account["health"] in {"attention", "critical"}
            ),
            "domains": sum(len(account["domains"]) for account in accounts),
            "users": sum(len(account["users"]) for account in accounts),
            "messages_30d": monthly_messages,
            "monthly_revenue_cents": monthly_revenue,
            "compliance_rate": (
                round(weighted_pass / monthly_messages, 1) if monthly_messages else 0.0
            ),
        },
        "health_segments": {
            "healthy": sum(1 for account in accounts if account["health"] == "healthy"),
            "monitoring": sum(1 for account in accounts if account["health"] == "monitoring"),
            "attention": sum(1 for account in accounts if account["health"] == "attention"),
            "critical": sum(1 for account in accounts if account["health"] == "critical"),
        },
        "plans": [_plan_payload(plan) for plan in plans],
        "accounts": accounts,
        "support_access_demo": {
            "mode": "audited_workspace_session",
            "operator": operator,
            "reason": "Kundensupport und Konfigurationsprüfung",
            "allowed_targets": allowed_targets,
            "safeguards": [
                "Zeitlich begrenzte, signierte Sitzung",
                "Operator, Zielbenutzer, Workspace und Grund werden protokolliert",
                "Die API-Berechtigungen entsprechen der Rolle des Zielbenutzers",
                "Die Sitzung ist fest an genau einen Kunden-Workspace gebunden",
            ],
            "audit_events": [],
        },
        "capabilities": {
            "backend_seeded_demo": demo_mode,
            "real_workspace_scope": True,
            "real_membership_management": not demo_mode,
            "real_provider_provisioning": not demo_mode,
            "real_billing_management": not demo_mode,
            "support_session": True,
        },
    }
