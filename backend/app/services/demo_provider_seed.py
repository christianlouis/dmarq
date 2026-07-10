"""Idempotent relational data seed for the dedicated provider demo."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.health_score_snapshot import HealthScoreSnapshot
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.organization import (
    BillingAccount,
    Organization,
    OrganizationMembership,
    Plan,
    ProviderIntegration,
    Subscription,
)
from app.models.report import DMARCReport, ReportRecord
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.demo_provider import build_demo_provider_seed_spec
from app.services.organizations import (
    BILLING_MODE_PROVIDER_RESALE,
    ensure_entitlements,
    plan_entitlements,
    provision_provider_customer,
)

DEMO_PROVIDER_ID = "northstar-demo"


def _naive_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _timestamp(value: str) -> int:
    parsed = datetime.fromisoformat(f"{value}T00:00:00+00:00")
    return int(parsed.timestamp())


def _ensure_plans(db: Session, spec: Dict[str, Any]) -> Dict[str, Plan]:
    plans: Dict[str, Plan] = {}
    for item in spec["plans"]:
        plan = db.query(Plan).filter(Plan.code == item["code"]).first()
        if plan is None:
            plan = Plan(code=item["code"])
            db.add(plan)
        plan.name = item["label"]
        plan.description = "Provider-managed DMARQ plan used by multi-tenant deployments."
        plan.billing_mode = BILLING_MODE_PROVIDER_RESALE
        plan.public = True
        plan.active = True
        plan.monthly_price_cents = item["monthly_charge_cents"]
        plan.currency = "EUR"
        plan.included_sending_domains = item["domains"]
        plan.included_message_volume = item["messages"]
        plan.included_users = item["users"]
        plan.retention_days = item["retention_days"]
        plan.features = "aggregate_reports,dns_linting,alerts,multi_workspace,sso"
        db.flush()
        plans[plan.code] = plan
    return plans


def _ensure_provider_integration(db: Session, spec: Dict[str, Any]) -> None:
    provider = spec["provider"]
    integration = (
        db.query(ProviderIntegration)
        .filter(
            ProviderIntegration.organization_id.is_(None),
            ProviderIntegration.external_provider_id == provider["slug"],
        )
        .first()
    )
    if integration is None:
        integration = ProviderIntegration(
            organization_id=None,
            external_provider_id=provider["slug"],
        )
        db.add(integration)
    integration.name = provider["name"]
    integration.provider_type = "reseller"
    integration.status = "active"
    integration.scopes = "accounts,memberships,billing,support_access"


def _ensure_account_foundation(
    db: Session,
    account: Dict[str, Any],
    plans: Dict[str, Plan],
) -> tuple[Organization, Workspace, Subscription, BillingAccount]:
    provision_provider_customer(
        db,
        provider_id=DEMO_PROVIDER_ID,
        external_customer_id=account["customer_number"],
        external_subscription_id=f"demo-sub-{account['slug']}",
        organization_slug=account["slug"],
        organization_name=account["name"],
        workspace_slug=account["slug"],
        workspace_name=f"{account['short_name']} Mail Security",
        plan_code=account["plan_code"],
        external_product_code=account["plan_code"],
        external_event_id=f"demo-seed-{account['slug']}",
        payload_summary="Deterministic provider demo seed",
        commit=False,
    )
    organization = db.query(Organization).filter(Organization.slug == account["slug"]).one()
    workspace = db.query(Workspace).filter(Workspace.slug == account["slug"]).one()
    subscription = (
        db.query(Subscription)
        .filter(Subscription.external_subscription_id == f"demo-sub-{account['slug']}")
        .one()
    )
    billing_account = (
        db.query(BillingAccount)
        .filter(BillingAccount.organization_id == organization.id)
        .order_by(BillingAccount.id.asc())
        .first()
    )
    plan = plans[account["plan_code"]]
    organization.name = account["name"]
    organization.description = "Synthetic customer account for the provider demonstration."
    organization.active = account["status"] != "suspended"
    organization.created_at = _naive_datetime(account["created_at"])
    workspace.active = organization.active
    workspace.report_retention_days = account["entitlements"]["retention_days"]["used"]
    workspace.forensic_retention_days = min(workspace.report_retention_days, 90)
    workspace.tls_report_retention_days = workspace.report_retention_days
    subscription.plan_id = plan.id
    billing_status = account["billing"]["status"]
    subscription.status = {
        "current": "active",
        "trial": "trialing",
    }.get(billing_status, billing_status)
    subscription.current_period_start = datetime.utcnow()
    subscription.current_period_end = _naive_datetime(
        f"{account['billing']['next_invoice_at']}T00:00:00Z"
    )
    subscription.external_product_code = plan.code
    subscription.monthly_price_cents = account["billing"]["monthly_charge_cents"]
    billing_account.status = "active"
    billing_account.provider_id = DEMO_PROVIDER_ID
    billing_account.external_customer_id = account["customer_number"]
    billing_account.invoice_delivery_mode = "provider_invoice"
    billing_account.billing_contact_email = account["billing"]["billing_contact"]
    billing_account.tax_reference = account["billing"]["invoice_reference"]
    ensure_entitlements(
        db,
        organization,
        subscription,
        plan_entitlements(plan),
        commit=False,
    )
    return organization, workspace, subscription, billing_account


def _workspace_role(role: str) -> str:
    return {
        "organization_owner": "workspace_owner",
        "organization_admin": "workspace_owner",
        "workspace_admin": "workspace_owner",
        "security_analyst": "analyst",
        "billing_admin": "auditor",
    }.get(role, role)


def _ensure_users(
    db: Session,
    account: Dict[str, Any],
    organization: Organization,
    workspace: Workspace,
) -> None:
    for item in account["users"]:
        user = db.query(User).filter(User.email == item["email"]).first()
        if user is None:
            user = User(email=item["email"])
            db.add(user)
        user.workspace_id = workspace.id
        user.full_name = item["name"]
        user.username = item["email"].split("@", maxsplit=1)[0]
        user.organization = organization.name
        user.is_active = item["status"] == "active"
        user.is_superuser = False
        user.is_verified = bool(item["mfa_enabled"])
        last_active_at = item.get("last_active_at") or account["created_at"]
        user.created_at = _naive_datetime(last_active_at)
        user.updated_at = _naive_datetime(last_active_at)
        db.flush()
        workspace_membership = (
            db.query(WorkspaceMembership)
            .filter(
                WorkspaceMembership.workspace_id == workspace.id,
                WorkspaceMembership.user_id == user.id,
            )
            .first()
        )
        if workspace_membership is None:
            workspace_membership = WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=user.id,
            )
            db.add(workspace_membership)
        workspace_membership.role = _workspace_role(item["role"])
        workspace_membership.active = user.is_active
        if item["role"].startswith("organization_") or item["role"] == "billing_admin":
            organization_membership = (
                db.query(OrganizationMembership)
                .filter(
                    OrganizationMembership.organization_id == organization.id,
                    OrganizationMembership.user_id == user.id,
                )
                .first()
            )
            if organization_membership is None:
                organization_membership = OrganizationMembership(
                    organization_id=organization.id,
                    user_id=user.id,
                )
                db.add(organization_membership)
            organization_membership.role = item["role"]
            organization_membership.active = user.is_active


def _ensure_domains_and_reports(
    db: Session,
    account: Dict[str, Any],
    workspace: Workspace,
    *,
    account_index: int,
) -> None:
    domains: Dict[str, Domain] = {}
    for item in account["domains"]:
        domain = db.query(Domain).filter(Domain.name == item["name"]).first()
        if domain is None:
            domain = Domain(name=item["name"])
            db.add(domain)
        domain.workspace_id = workspace.id
        domain.description = f"{account['name']} primary sending domain"
        domain.active = True
        domain.dmarc_policy = item["policy"]
        domain.dmarc_report_mailbox = account["settings"]["report_mailbox"]
        domain.spf_record = "v=spf1 include:_spf.example.net -all"
        domain.dkim_selectors = "google,mail"
        domain.verified = item["health"] != "critical"
        db.flush()
        domains[domain.name] = domain

    for report_index, item in enumerate(account["reports"], start=1):
        domain = domains[item["domain"]]
        report = (
            db.query(DMARCReport)
            .filter(
                DMARCReport.domain_id == domain.id,
                DMARCReport.report_id == item["id"],
            )
            .first()
        )
        if report is None:
            report = DMARCReport(
                domain_id=domain.id,
                report_id=item["id"],
                org_name=item["provider"],
                begin_date=_timestamp(item["period_start"]),
                end_date=_timestamp(item["period_end"]),
            )
            db.add(report)
        report.org_name = item["provider"]
        report.begin_date = _timestamp(item["period_start"])
        report.end_date = _timestamp(item["period_end"])
        report.source_email = f"noreply-dmarc@{item['provider'].lower()}.example"
        report.policy = domain.dmarc_policy
        report.subdomain_policy = domain.dmarc_policy
        report.adkim = "r"
        report.aspf = "r"
        report.percentage = 100
        report.processed_at = _naive_datetime(item["received_at"])
        db.flush()
        db.query(ReportRecord).filter(ReportRecord.report_id == report.id).delete(
            synchronize_session=False
        )
        passed = round(item["messages"] * item["pass_rate"] / 100)
        failed = max(0, item["messages"] - passed)
        if passed:
            db.add(
                ReportRecord(
                    report_id=report.id,
                    source_ip=f"192.0.2.{account_index * 10 + report_index}",
                    count=passed,
                    disposition="none",
                    dkim="pass",
                    spf="pass",
                    header_from=domain.name,
                    envelope_from=domain.name,
                    dkim_auth_details=json.dumps(
                        [{"domain": domain.name, "selector": "mail", "result": "pass"}]
                    ),
                    spf_auth_details=json.dumps(
                        [{"domain": domain.name, "scope": "mfrom", "result": "pass"}]
                    ),
                )
            )
        if failed:
            db.add(
                ReportRecord(
                    report_id=report.id,
                    source_ip=f"198.51.100.{account_index * 10 + report_index}",
                    count=failed,
                    disposition="quarantine",
                    dkim="fail",
                    spf="fail",
                    header_from=domain.name,
                    envelope_from=f"relay.{domain.name}",
                    dkim_auth_details=json.dumps(
                        [{"domain": domain.name, "selector": "legacy", "result": "fail"}]
                    ),
                    spf_auth_details=json.dumps(
                        [{"domain": domain.name, "scope": "mfrom", "result": "fail"}]
                    ),
                )
            )


def _ensure_health_history(
    db: Session,
    account: Dict[str, Any],
    workspace: Workspace,
) -> None:
    """Materialize tenant-specific trend evidence in the normal snapshot table."""
    anchor = date.today()
    base_scores = {
        "healthy": 94,
        "attention": 82,
        "monitoring": 72,
        "critical": 58,
    }
    for domain_index, item in enumerate(account["domains"]):
        current_score = base_scores.get(item["health"], 70)
        current_compliance = float(item["compliance_rate"])
        daily_messages = max(1, round(int(item["messages_30d"]) / 30))
        daily_reports = max(1, round(int(item["reports_30d"]) / 30))
        primary_finding = next(
            iter(item.get("open_findings") or []),
            "Keine akuten Findings; neue Senderabweichungen weiter überwachen.",
        )
        for days_ago in range(13, -1, -1):
            snapshot_date = anchor - timedelta(days=days_ago)
            row = (
                db.query(HealthScoreSnapshot)
                .filter(
                    HealthScoreSnapshot.workspace_id == workspace.id,
                    HealthScoreSnapshot.domain_name == item["name"],
                    HealthScoreSnapshot.snapshot_date == snapshot_date,
                )
                .one_or_none()
            )
            if row is None:
                row = HealthScoreSnapshot(
                    workspace_id=workspace.id,
                    domain_name=item["name"],
                    snapshot_date=snapshot_date,
                )
                db.add(row)
            trend_offset = min(6, days_ago // 3)
            score = max(25, min(99, current_score - trend_offset + (domain_index % 2)))
            compliance = max(0, min(100, round(current_compliance - trend_offset)))
            row.score = score
            row.grade = (
                "A"
                if score >= 90
                else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
            )
            row.status = "healthy" if score >= 90 else "attention" if score >= 70 else "critical"
            row.policy = item["policy"]
            row.compliance_rate = compliance
            row.total_emails = daily_messages
            row.failed_emails = round(daily_messages * (100 - compliance) / 100)
            row.report_count = daily_reports
            row.dns_posture_score = max(0, min(100, score + 3))
            row.policy_strength_score = {"reject": 100, "quarantine": 75, "none": 35}.get(
                item["policy"], 35
            )
            row.report_confidence_score = 90 if item["reports_30d"] else 0
            row.top_actions = json.dumps(
                [
                    {
                        "type": "tenant_finding",
                        "severity": "critical" if item["health"] == "critical" else "info",
                        "title": primary_finding,
                        "score_impact": max(0, 100 - score),
                    }
                ],
                sort_keys=True,
            )
            row.updated_at = datetime.utcnow()


def _ensure_import_source(db: Session, account: Dict[str, Any], workspace: Workspace) -> None:
    source = (
        db.query(MailSource)
        .filter(MailSource.workspace_id == workspace.id, MailSource.name == "Provider report inbox")
        .first()
    )
    if source is None:
        source = MailSource(workspace_id=workspace.id, name="Provider report inbox")
        db.add(source)
    source.method = "IMAP"
    source.server = "imap.provider-demo.invalid"
    source.port = 993
    source.username = account["settings"]["report_mailbox"]
    source.folder = "INBOX/DMARC"
    source.use_ssl = True
    source.enabled = True
    source.last_checked = _naive_datetime(account["last_activity_at"])
    db.flush()
    imported = (
        db.query(MailSourceImport).filter(MailSourceImport.mail_source_id == source.id).first()
    )
    if imported is None:
        imported = MailSourceImport(mail_source_id=source.id)
        db.add(imported)
    imported.trigger = "scheduled"
    imported.status = "success"
    imported.processed = len(account["reports"])
    imported.reports_found = len(account["reports"])
    imported.duplicate_reports = 0
    imported.error_count = 0
    imported.started_at = source.last_checked
    imported.finished_at = source.last_checked
    imported.details = json.dumps({"summary": "Synthetic provider report import completed."})


def _ensure_activity(db: Session, account: Dict[str, Any], workspace: Workspace) -> None:
    for item in account["activity"]:
        entity_id = f"demo-{item['id']}"
        row = (
            db.query(WorkspaceAuditLog)
            .filter(
                WorkspaceAuditLog.workspace_id == workspace.id,
                WorkspaceAuditLog.entity_id == entity_id,
            )
            .first()
        )
        if row is None:
            row = WorkspaceAuditLog(
                workspace_id=workspace.id,
                entity_id=entity_id,
                actor_type="demo_seed",
                entity_type="provider_account",
            )
            db.add(row)
        row.actor_id = item["actor"]
        row.action = item["action"]
        row.entity_name = account["name"]
        row.details = json.dumps({"summary": item["summary"]})
        row.created_at = _naive_datetime(item["occurred_at"])


def seed_demo_provider_database(db: Session) -> Dict[str, int]:
    """Seed the provider demo into real tenant tables and return row counts."""
    spec = build_demo_provider_seed_spec()
    plans = _ensure_plans(db, spec)
    _ensure_provider_integration(db, spec)
    for account_index, account in enumerate(spec["accounts"], start=1):
        organization, workspace, _, _ = _ensure_account_foundation(db, account, plans)
        _ensure_users(db, account, organization, workspace)
        _ensure_domains_and_reports(
            db,
            account,
            workspace,
            account_index=account_index,
        )
        _ensure_health_history(db, account, workspace)
        _ensure_import_source(db, account, workspace)
        _ensure_activity(db, account, workspace)
    db.commit()
    return {
        "accounts": len(spec["accounts"]),
        "plans": len(spec["plans"]),
        "domains": sum(len(account["domains"]) for account in spec["accounts"]),
        "users": sum(len(account["users"]) for account in spec["accounts"]),
        "reports": sum(len(account["reports"]) for account in spec["accounts"]),
    }
