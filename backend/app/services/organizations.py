"""Organization and commercial-account bootstrap helpers."""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from html import escape
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.organization import (
    BillingAccount,
    BillingEvent,
    Entitlement,
    Organization,
    Plan,
    Subscription,
    UsageRecord,
)
from app.models.report import DMARCReport, ForensicReport, ReportRecord
from app.models.user import User
from app.models.workspace import Workspace

DEFAULT_ORGANIZATION_SLUG = "default"
DEFAULT_ORGANIZATION_NAME = "Default Organization"

BILLING_MODE_DIRECT_STRIPE = "direct_stripe"
BILLING_MODE_MANUAL_CONTRACT = "manual_contract"
BILLING_MODE_PROVIDER_RESALE = "provider_resale"
BILLING_MODE_PROVIDER_WHMCS = "provider_whmcs"
BILLING_MODE_PROVIDER_TMF = "provider_tmf"
BILLING_MODE_SELF_HOSTED = "self_hosted_license"

SELF_HOSTED_PLAN_CODE = "self_hosted"
DEFAULT_SELF_HOSTED_ENTITLEMENTS: Dict[str, str] = {
    "aggregate_reports": "true",
    "forensic_reports": "true",
    "dns_linting": "true",
    "alerts": "true",
    "multi_workspace": "true",
    "retention_days": "400",
}

PROVIDER_SUBSCRIPTION_STATUSES = {
    "trialing",
    "active",
    "past_due_provider_reported",
    "suspended",
    "canceled",
    "terminated",
}
MAX_PROVIDER_PAYLOAD_SUMMARY_LENGTH = 500


def _sanitize_payload_summary(payload_summary: Optional[str]) -> Optional[str]:
    """Trim provider summaries to safe, displayable text."""
    if payload_summary is None:
        return None
    normalized = " ".join(str(payload_summary).split())
    if not normalized:
        return None
    escaped = escape(normalized, quote=True)
    return escaped[:MAX_PROVIDER_PAYLOAD_SUMMARY_LENGTH]


def get_or_create_default_organization(db: Session, *, commit: bool = True) -> Organization:
    """Return the default organization used by single-tenant installs."""
    organization = (
        db.query(Organization).filter(Organization.slug == DEFAULT_ORGANIZATION_SLUG).first()
    )
    if organization:
        return organization

    organization = Organization(
        slug=DEFAULT_ORGANIZATION_SLUG,
        name=DEFAULT_ORGANIZATION_NAME,
        description="Automatically created for existing single-tenant installs.",
        active=True,
    )
    db.add(organization)
    if commit:
        db.commit()
        db.refresh(organization)
    else:
        db.flush()
    return organization


def get_or_create_self_hosted_plan(db: Session, *, commit: bool = True) -> Plan:
    """Return the built-in self-hosted plan record."""
    plan = db.query(Plan).filter(Plan.code == SELF_HOSTED_PLAN_CODE).first()
    if plan:
        return plan

    plan = Plan(
        code=SELF_HOSTED_PLAN_CODE,
        name="Self-hosted",
        description="Default local deployment plan with no external billing dependency.",
        billing_mode=BILLING_MODE_SELF_HOSTED,
        public=False,
        active=True,
        currency="EUR",
        retention_days=400,
        features="aggregate_reports,forensic_reports,dns_linting,alerts,multi_workspace",
    )
    db.add(plan)
    if commit:
        db.commit()
        db.refresh(plan)
    else:
        db.flush()
    return plan


def assign_default_organization_to_unscoped_rows(
    db: Session,
    *,
    commit: bool = True,
) -> Organization:
    """Attach workspaces without an account boundary to the default organization."""
    organization = get_or_create_default_organization(db, commit=False)
    db.query(Workspace).filter(Workspace.organization_id.is_(None)).update(
        {Workspace.organization_id: organization.id},
        synchronize_session=False,
    )
    if commit:
        db.commit()
        db.refresh(organization)
    else:
        db.flush()
    return organization


def ensure_billing_account(
    db: Session,
    organization: Organization,
    *,
    billing_mode: str = BILLING_MODE_SELF_HOSTED,
    commit: bool = True,
) -> BillingAccount:
    """Return the billing account for an organization and mode."""
    account = (
        db.query(BillingAccount)
        .filter(
            BillingAccount.organization_id == organization.id,
            BillingAccount.billing_mode == billing_mode,
        )
        .first()
    )
    if account:
        return account

    account = BillingAccount(
        organization_id=organization.id,
        billing_mode=billing_mode,
        status="active",
        invoice_delivery_mode="internal",
    )
    db.add(account)
    if commit:
        db.commit()
        db.refresh(account)
    else:
        db.flush()
    return account


def ensure_subscription(
    db: Session,
    organization: Organization,
    plan: Plan,
    billing_account: BillingAccount,
    *,
    commit: bool = True,
) -> Subscription:
    """Return the active subscription for the organization and plan."""
    subscription = (
        db.query(Subscription)
        .filter(
            Subscription.organization_id == organization.id,
            Subscription.plan_id == plan.id,
            Subscription.status.in_(("active", "trialing")),
        )
        .first()
    )
    if subscription:
        return subscription

    subscription = Subscription(
        organization_id=organization.id,
        plan_id=plan.id,
        billing_account_id=billing_account.id,
        billing_mode=billing_account.billing_mode,
        status="active",
        current_period_start=datetime.utcnow(),
    )
    db.add(subscription)
    if commit:
        db.commit()
        db.refresh(subscription)
    else:
        db.flush()
    return subscription


def ensure_entitlements(
    db: Session,
    organization: Organization,
    subscription: Subscription,
    entitlements: Dict[str, str],
    *,
    commit: bool = True,
) -> Iterable[Entitlement]:
    """Ensure each entitlement key exists for the organization."""
    existing = {
        entitlement.key: entitlement
        for entitlement in db.query(Entitlement)
        .filter(
            Entitlement.organization_id == organization.id,
            Entitlement.active.is_(True),
        )
        .all()
    }
    created_or_existing = []
    for key, value in entitlements.items():
        entitlement = existing.get(key)
        if entitlement:
            created_or_existing.append(entitlement)
            continue
        entitlement = Entitlement(
            organization_id=organization.id,
            subscription_id=subscription.id,
            key=key,
            value=value,
            source="plan",
            active=True,
        )
        db.add(entitlement)
        created_or_existing.append(entitlement)

    if commit:
        db.commit()
        for entitlement in created_or_existing:
            db.refresh(entitlement)
    else:
        db.flush()
    return created_or_existing


def bootstrap_default_commercial_foundation(
    db: Session,
    *,
    commit: bool = True,
) -> Organization:
    """Create the minimum account records needed by self-hosted installs."""
    organization = assign_default_organization_to_unscoped_rows(db, commit=False)
    plan = get_or_create_self_hosted_plan(db, commit=False)
    account = ensure_billing_account(db, organization, commit=False)
    subscription = ensure_subscription(db, organization, plan, account, commit=False)
    ensure_entitlements(
        db,
        organization,
        subscription,
        DEFAULT_SELF_HOSTED_ENTITLEMENTS,
        commit=False,
    )
    if commit:
        db.commit()
        db.refresh(organization)
    else:
        db.flush()
    return organization


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat()


def _workspace_to_dict(workspace: Workspace) -> Dict[str, Any]:
    return {
        "id": workspace.id,
        "slug": workspace.slug,
        "name": workspace.name,
        "active": workspace.active,
        "report_retention_days": workspace.report_retention_days,
        "forensic_retention_days": workspace.forensic_retention_days,
        "tls_report_retention_days": workspace.tls_report_retention_days,
    }


def _billing_account_to_dict(account: BillingAccount) -> Dict[str, Any]:
    return {
        "id": account.id,
        "billing_mode": account.billing_mode,
        "status": account.status,
        "provider_id": account.provider_id,
        "external_customer_id": account.external_customer_id,
        "stripe_customer_id": account.stripe_customer_id,
        "invoice_delivery_mode": account.invoice_delivery_mode,
        "tax_reference": account.tax_reference,
    }


def _plan_to_dict(plan: Plan) -> Dict[str, Any]:
    return {
        "id": plan.id,
        "code": plan.code,
        "name": plan.name,
        "billing_mode": plan.billing_mode,
        "public": plan.public,
        "active": plan.active,
        "monthly_price_cents": plan.monthly_price_cents,
        "annual_price_cents": plan.annual_price_cents,
        "currency": plan.currency,
        "included_sending_domains": plan.included_sending_domains,
        "included_message_volume": plan.included_message_volume,
        "included_users": plan.included_users,
        "retention_days": plan.retention_days,
        "features": [
            feature.strip() for feature in (plan.features or "").split(",") if feature.strip()
        ],
    }


def _subscription_to_dict(subscription: Subscription) -> Dict[str, Any]:
    return {
        "id": subscription.id,
        "billing_mode": subscription.billing_mode,
        "status": subscription.status,
        "current_period_start": _iso(subscription.current_period_start),
        "current_period_end": _iso(subscription.current_period_end),
        "stripe_subscription_id": subscription.stripe_subscription_id,
        "external_subscription_id": subscription.external_subscription_id,
        "external_product_code": subscription.external_product_code,
        "canceled_at": _iso(subscription.canceled_at),
        "plan": _plan_to_dict(subscription.plan),
    }


def organization_summary(db: Session, organization: Organization) -> Dict[str, Any]:
    """Return an API-safe organization/account summary."""
    workspaces = (
        db.query(Workspace)
        .filter(Workspace.organization_id == organization.id)
        .order_by(Workspace.slug.asc())
        .all()
    )
    billing_accounts = (
        db.query(BillingAccount)
        .filter(BillingAccount.organization_id == organization.id)
        .order_by(BillingAccount.id.asc())
        .all()
    )
    subscriptions = (
        db.query(Subscription)
        .filter(Subscription.organization_id == organization.id)
        .order_by(Subscription.created_at.desc())
        .all()
    )
    entitlements = (
        db.query(Entitlement)
        .filter(
            Entitlement.organization_id == organization.id,
            Entitlement.active.is_(True),
        )
        .order_by(Entitlement.key.asc())
        .all()
    )
    return {
        "id": organization.id,
        "slug": organization.slug,
        "name": organization.name,
        "description": organization.description,
        "active": organization.active,
        "created_at": _iso(organization.created_at),
        "updated_at": _iso(organization.updated_at),
        "workspaces": [_workspace_to_dict(workspace) for workspace in workspaces],
        "billing_accounts": [_billing_account_to_dict(account) for account in billing_accounts],
        "subscriptions": [_subscription_to_dict(subscription) for subscription in subscriptions],
        "entitlements": {
            entitlement.key: {
                "value": entitlement.value,
                "source": entitlement.source,
                "expires_at": _iso(entitlement.expires_at),
            }
            for entitlement in entitlements
        },
        "metrics": {
            "workspace_count": len(workspaces),
            "active_workspace_count": sum(1 for workspace in workspaces if workspace.active),
            "user_count": (
                db.query(func.count(User.id))
                .filter(User.workspace_id.in_([workspace.id for workspace in workspaces] or [-1]))
                .scalar()
                or 0
            ),
        },
    }


def list_organization_summaries(db: Session) -> List[Dict[str, Any]]:
    """Return all organizations with local commercial state materialized."""
    bootstrap_default_commercial_foundation(db)
    organizations = db.query(Organization).order_by(Organization.slug.asc()).all()
    return [organization_summary(db, organization) for organization in organizations]


def list_scoped_organization_summaries(
    db: Session,
    organization_ids: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """Return organization summaries constrained to authorized IDs when supplied."""
    bootstrap_default_commercial_foundation(db)
    query = db.query(Organization).order_by(Organization.slug.asc())
    if organization_ids is not None:
        if not organization_ids:
            return []
        query = query.filter(Organization.id.in_(organization_ids))
    return [organization_summary(db, organization) for organization in query.all()]


def parse_usage_period(period: str) -> tuple[datetime, datetime]:
    """Parse a billing period in YYYY-MM form into UTC-naive boundaries."""
    try:
        year_text, month_text = period.split("-", 1)
        year = int(year_text)
        month = int(month_text)
        start_date = date(year, month, 1)
    except (TypeError, ValueError) as exc:
        raise ValueError("period must use YYYY-MM format") from exc

    if month == 12:
        end_date = date(year + 1, 1, 1)
    else:
        end_date = date(year, month + 1, 1)

    return (
        datetime.combine(start_date, time.min, tzinfo=timezone.utc).replace(tzinfo=None),
        datetime.combine(end_date, time.min, tzinfo=timezone.utc).replace(tzinfo=None),
    )


def usage_period_for_current_month() -> str:
    """Return the current billing period key in YYYY-MM format."""
    today = date.today()
    return f"{today.year:04d}-{today.month:02d}"


def _metric(
    key: str,
    quantity: int,
    unit: str,
    period_start: datetime,
    period_end: datetime,
    organization_id: int,
    workspace_id: Optional[int] = None,
    source: str = "computed",
    external_customer_id: Optional[str] = None,
) -> Dict[str, Any]:
    scope = workspace_id if workspace_id is not None else "org"
    idempotency_key = (
        f"{source}:{organization_id}:{scope}:{key}:"
        f"{period_start.date().isoformat()}:{period_end.date().isoformat()}"
    )
    return {
        "metric": key,
        "quantity": int(quantity or 0),
        "unit": unit,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "organization_id": organization_id,
        "workspace_id": workspace_id,
        "source": source,
        "external_customer_id": external_customer_id,
        "idempotency_key": idempotency_key,
    }


def build_usage_export(
    db: Session,
    *,
    period: Optional[str] = None,
    external_customer_id: Optional[str] = None,
    organization_ids: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Build idempotent usage metrics suitable for provider monthly billing."""
    period_key = period or usage_period_for_current_month()
    period_start, period_end = parse_usage_period(period_key)
    bootstrap_default_commercial_foundation(db)

    organization_query = db.query(Organization).filter(Organization.active.is_(True))
    if organization_ids is not None:
        if not organization_ids:
            organizations = []
        else:
            organization_query = organization_query.filter(Organization.id.in_(organization_ids))
            organizations = None
    else:
        organizations = None
    if external_customer_id:
        organization_query = organization_query.join(BillingAccount).filter(
            BillingAccount.external_customer_id == external_customer_id
        )
    if organizations is None:
        organizations = organization_query.order_by(Organization.slug.asc()).all()

    exports = []
    for organization in organizations:
        workspaces = (
            db.query(Workspace)
            .filter(
                Workspace.organization_id == organization.id,
                Workspace.active.is_(True),
            )
            .order_by(Workspace.slug.asc())
            .all()
        )
        workspace_ids = [workspace.id for workspace in workspaces]
        billing_account = (
            db.query(BillingAccount)
            .filter(BillingAccount.organization_id == organization.id)
            .order_by(BillingAccount.id.asc())
            .first()
        )
        external_id = (
            billing_account.external_customer_id
            if billing_account and billing_account.external_customer_id
            else external_customer_id
        )

        metrics = [
            _metric(
                "customer_workspaces",
                len(workspace_ids),
                "workspaces",
                period_start,
                period_end,
                organization.id,
                external_customer_id=external_id,
            )
        ]
        if workspace_ids:
            active_domains = (
                db.query(func.count(Domain.id))
                .filter(
                    Domain.workspace_id.in_(workspace_ids),
                    Domain.active.is_(True),
                )
                .scalar()
                or 0
            )
            aggregate_reports = (
                db.query(func.count(DMARCReport.id))
                .join(Domain, DMARCReport.domain_id == Domain.id)
                .filter(
                    Domain.workspace_id.in_(workspace_ids),
                    DMARCReport.processed_at >= period_start,
                    DMARCReport.processed_at < period_end,
                )
                .scalar()
                or 0
            )
            aggregate_messages = (
                db.query(func.sum(ReportRecord.count))
                .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
                .join(Domain, DMARCReport.domain_id == Domain.id)
                .filter(
                    Domain.workspace_id.in_(workspace_ids),
                    DMARCReport.processed_at >= period_start,
                    DMARCReport.processed_at < period_end,
                )
                .scalar()
                or 0
            )
            sending_domains = (
                db.query(func.count(func.distinct(ReportRecord.header_from)))
                .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
                .join(Domain, DMARCReport.domain_id == Domain.id)
                .filter(
                    Domain.workspace_id.in_(workspace_ids),
                    DMARCReport.processed_at >= period_start,
                    DMARCReport.processed_at < period_end,
                    ReportRecord.header_from.isnot(None),
                )
                .scalar()
                or 0
            )
            forensic_reports = (
                db.query(func.count(ForensicReport.id))
                .join(Domain, ForensicReport.domain_id == Domain.id)
                .filter(
                    Domain.workspace_id.in_(workspace_ids),
                    ForensicReport.processed_at >= period_start,
                    ForensicReport.processed_at < period_end,
                )
                .scalar()
                or 0
            )
            active_users = (
                db.query(func.count(User.id))
                .filter(
                    User.workspace_id.in_(workspace_ids),
                    User.is_active.is_(True),
                )
                .scalar()
                or 0
            )
            metrics.extend(
                [
                    _metric(
                        "monitored_domains",
                        active_domains,
                        "domains",
                        period_start,
                        period_end,
                        organization.id,
                        external_customer_id=external_id,
                    ),
                    _metric(
                        "active_sending_domains",
                        sending_domains,
                        "domains",
                        period_start,
                        period_end,
                        organization.id,
                        external_customer_id=external_id,
                    ),
                    _metric(
                        "aggregate_reports",
                        aggregate_reports,
                        "reports",
                        period_start,
                        period_end,
                        organization.id,
                        external_customer_id=external_id,
                    ),
                    _metric(
                        "aggregate_messages",
                        aggregate_messages,
                        "messages",
                        period_start,
                        period_end,
                        organization.id,
                        external_customer_id=external_id,
                    ),
                    _metric(
                        "forensic_reports",
                        forensic_reports,
                        "reports",
                        period_start,
                        period_end,
                        organization.id,
                        external_customer_id=external_id,
                    ),
                    _metric(
                        "active_users",
                        active_users,
                        "users",
                        period_start,
                        period_end,
                        organization.id,
                        external_customer_id=external_id,
                    ),
                ]
            )

        stored_usage = (
            db.query(UsageRecord)
            .filter(
                UsageRecord.organization_id == organization.id,
                UsageRecord.period_start >= period_start,
                UsageRecord.period_end <= period_end,
            )
            .order_by(UsageRecord.metric.asc(), UsageRecord.workspace_id.asc())
            .all()
        )
        metrics.extend(
            [
                {
                    "metric": record.metric,
                    "quantity": record.quantity,
                    "unit": record.unit,
                    "period_start": record.period_start.isoformat(),
                    "period_end": record.period_end.isoformat(),
                    "organization_id": record.organization_id,
                    "workspace_id": record.workspace_id,
                    "source": record.source,
                    "external_customer_id": record.external_customer_id,
                    "idempotency_key": record.idempotency_key,
                }
                for record in stored_usage
            ]
        )

        exports.append(
            {
                "organization": {
                    "id": organization.id,
                    "slug": organization.slug,
                    "name": organization.name,
                },
                "billing_account": (
                    _billing_account_to_dict(billing_account) if billing_account else None
                ),
                "period": period_key,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "metrics": metrics,
            }
        )

    return {
        "period": period_key,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "organizations": exports,
    }


def update_external_subscription_state(
    db: Session,
    *,
    external_subscription_id: str,
    status: str,
    organization_ids: Optional[List[int]] = None,
    provider_id: Optional[str] = None,
    external_event_id: Optional[str] = None,
    payload_summary: Optional[str] = None,
    commit: bool = True,
) -> Dict[str, Any]:
    """Apply a provider-reported subscription lifecycle state."""
    normalized_status = (status or "").strip().lower()
    if normalized_status not in PROVIDER_SUBSCRIPTION_STATUSES:
        raise ValueError(
            "status must be one of " + ", ".join(sorted(PROVIDER_SUBSCRIPTION_STATUSES))
        )

    subscription = (
        db.query(Subscription)
        .filter(Subscription.external_subscription_id == external_subscription_id)
        .first()
    )
    if organization_ids is not None:
        if not organization_ids:
            subscription = None
        else:
            subscription = (
                db.query(Subscription)
                .filter(
                    Subscription.external_subscription_id == external_subscription_id,
                    Subscription.organization_id.in_(organization_ids),
                )
                .first()
            )
    if subscription is None:
        raise LookupError("external subscription not found")

    old_status = subscription.status
    subscription.status = normalized_status
    if normalized_status in {"canceled", "terminated"} and subscription.canceled_at is None:
        subscription.canceled_at = datetime.utcnow()

    event = BillingEvent(
        organization_id=subscription.organization_id,
        subscription_id=subscription.id,
        billing_mode=subscription.billing_mode,
        event_type="provider.subscription_state_updated",
        provider_id=provider_id,
        external_event_id=external_event_id,
        status="applied",
        payload_summary=_sanitize_payload_summary(payload_summary),
    )
    db.add(event)
    if commit:
        db.commit()
        db.refresh(subscription)
        db.refresh(event)
    else:
        db.flush()

    return {
        "subscription": _subscription_to_dict(subscription),
        "old_status": old_status,
        "new_status": subscription.status,
        "billing_event": {
            "id": event.id,
            "event_type": event.event_type,
            "provider_id": event.provider_id,
            "external_event_id": event.external_event_id,
            "status": event.status,
        },
    }
