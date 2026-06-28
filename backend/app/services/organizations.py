"""Organization and commercial-account bootstrap helpers."""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from html import escape
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.api_token import APIToken
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.organization import (
    BillingAccount,
    BillingEvent,
    Entitlement,
    Organization,
    OrganizationMembership,
    Plan,
    Subscription,
    UsageRecord,
)
from app.models.report import DMARCReport, ForensicReport, ReportRecord
from app.models.user import User
from app.models.webhook import WebhookEndpoint
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspaces import normalize_workspace_slug

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

STARTER_PLAN_CODE = "starter"
STARTER_PLAN_ENTITLEMENTS: Dict[str, str] = {
    "aggregate_reports": "true",
    "forensic_reports": "true",
    "dns_linting": "true",
    "alerts": "true",
    "monitored_domains": "1",
    "mail_sources": "1",
    "users": "1",
    "retention_days": "90",
    "api_tokens": "false",
    "webhooks": "false",
    "sso": "false",
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
ACCOUNT_ACTIVE_STATUSES = {"active", "trialing"}
ACCOUNT_GRACE_STATUSES = {"past_due_provider_reported"}
ACCOUNT_READ_ONLY_STATUSES = {"suspended", "canceled", "terminated"}
ACCOUNT_CLOSED_STATUSES = {"canceled", "terminated"}
ENFORCED_PLAN_LIMITS = {
    "aggregate_messages",
    "api_tokens",
    "monitored_domains",
    "retention_days",
    "users",
    "webhooks",
}
FEATURE_ENTITLEMENT_ALIASES: Dict[str, tuple[str, ...]] = {
    "api_tokens": ("api_tokens", "api_access"),
    "webhooks": ("webhooks",),
}
PLAN_LIMIT_ENTITLEMENT_ALIASES: Dict[str, tuple[str, ...]] = {
    "aggregate_messages": ("aggregate_messages", "message_volume", "included_message_volume"),
    "monitored_domains": ("monitored_domains", "sending_domains"),
    "mail_sources": ("mail_sources",),
    "users": ("users",),
    "api_tokens": FEATURE_ENTITLEMENT_ALIASES["api_tokens"],
    "webhooks": FEATURE_ENTITLEMENT_ALIASES["webhooks"],
    "retention_days": ("retention_days",),
}
PLAN_LIMIT_UNITS = {
    "aggregate_messages": "messages",
    "retention_days": "days",
}


class OrganizationPlanLimitError(ValueError):
    """Raised when a plan limit would be exceeded by a mutation."""

    def __init__(
        self,
        *,
        metric: str,
        current: int,
        limit: int,
        attempted: int,
        unit: str,
        entitlement_key: Optional[str],
    ):
        self.metric = metric
        self.current = current
        self.limit = limit
        self.attempted = attempted
        self.unit = unit
        self.entitlement_key = entitlement_key
        super().__init__(
            f"Plan limit for {metric} would be exceeded "
            f"({current} current + {attempted} requested > {limit} {unit})"
        )

    def to_detail(self) -> Dict[str, Any]:
        """Return an API-safe detail payload."""
        return {
            "code": "plan_limit_exceeded",
            "metric": self.metric,
            "current": self.current,
            "limit": self.limit,
            "attempted": self.attempted,
            "unit": self.unit,
            "entitlement_key": self.entitlement_key,
            "can_export": True,
            "message": str(self),
        }


def _sanitize_payload_summary(payload_summary: Optional[str]) -> Optional[str]:
    """Trim provider summaries to safe, displayable text."""
    if payload_summary is None:
        return None
    normalized = " ".join(str(payload_summary).split())
    if not normalized:
        return None
    escaped = escape(normalized, quote=True)
    return escaped[:MAX_PROVIDER_PAYLOAD_SUMMARY_LENGTH]


def _normalize_required_slug(value: str, *, field_name: str) -> str:
    slug = normalize_workspace_slug(value)
    if not slug:
        raise ValueError(f"{field_name} is required")
    return slug


def _clean_required(value: str, *, field_name: str) -> str:
    clean = (value or "").strip()
    if not clean:
        raise ValueError(f"{field_name} is required")
    return clean


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


def get_or_create_starter_plan(db: Session, *, commit: bool = True) -> Plan:
    """Return the built-in starter plan used by SaaS/customer onboarding."""
    plan = db.query(Plan).filter(Plan.code == STARTER_PLAN_CODE).first()
    if plan:
        return plan

    plan = Plan(
        code=STARTER_PLAN_CODE,
        name="Starter",
        description=(
            "Default first workspace plan for guided DMARC onboarding without "
            "external billing activation."
        ),
        billing_mode=BILLING_MODE_MANUAL_CONTRACT,
        public=True,
        active=True,
        currency="EUR",
        included_sending_domains=1,
        included_users=1,
        retention_days=90,
        features="aggregate_reports,forensic_reports,dns_linting,alerts",
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


def _primary_subscription(subscriptions: Iterable[Subscription]) -> Optional[Subscription]:
    subscription_list = list(subscriptions)
    for status_group in (
        ACCOUNT_ACTIVE_STATUSES,
        ACCOUNT_GRACE_STATUSES,
        {"suspended"},
        ACCOUNT_CLOSED_STATUSES,
    ):
        for subscription in subscription_list:
            if subscription.status in status_group:
                return subscription
    return subscription_list[0] if subscription_list else None


def account_state_for_subscriptions(
    subscriptions: Iterable[Subscription],
    *,
    include_plan_code: bool = True,
) -> Dict[str, Any]:
    """Return the effective commercial state used by UI and write guards."""
    subscription = _primary_subscription(subscriptions)
    if subscription is None:
        return {
            "status": "unconfigured",
            "billing_mode": None,
            "plan_code": None,
            "read_only": False,
            "can_mutate": True,
            "can_export": True,
            "grace_period": False,
            "closed": False,
            "reason": "No active subscription has been configured for this organization.",
            "blocking_subscription_id": None,
        }

    status_value = subscription.status
    read_only = status_value in ACCOUNT_READ_ONLY_STATUSES
    grace_period = status_value in ACCOUNT_GRACE_STATUSES
    closed = status_value in ACCOUNT_CLOSED_STATUSES
    if read_only:
        reason = (
            "This organization's subscription is read-only. Users can view and "
            "export existing data, but mutating actions are blocked until billing "
            "or provider state is restored."
        )
    elif grace_period:
        reason = (
            "This organization's subscription is in a provider-reported grace "
            "state. Mutating actions still work, but operators should resolve "
            "billing before the account becomes read-only."
        )
    elif status_value in ACCOUNT_ACTIVE_STATUSES:
        reason = "This organization's subscription allows normal workspace changes."
    else:
        reason = (
            "This organization's subscription status is not classified as "
            "read-only. Workspace changes currently remain allowed."
        )

    return {
        "status": status_value,
        "billing_mode": subscription.billing_mode,
        "plan_code": (subscription.plan.code if include_plan_code and subscription.plan else None),
        "read_only": read_only,
        "can_mutate": not read_only,
        "can_export": True,
        "grace_period": grace_period,
        "closed": closed,
        "reason": reason,
        "blocking_subscription_id": subscription.id if read_only else None,
    }


def _entitlements_by_key(entitlements: Iterable[Entitlement]) -> Dict[str, Entitlement]:
    mapped: Dict[str, Entitlement] = {}
    for entitlement in entitlements:
        mapped.setdefault(entitlement.key, entitlement)
    return mapped


def _active_entitlements_query(db: Session, organization: Organization):
    return (
        db.query(Entitlement)
        .filter(
            Entitlement.organization_id == organization.id,
            Entitlement.active.is_(True),
        )
        .order_by(
            Entitlement.key.asc(),
            Entitlement.updated_at.desc().nullslast(),
            Entitlement.effective_from.desc().nullslast(),
            Entitlement.created_at.desc().nullslast(),
            Entitlement.id.desc(),
        )
    )


def _entitlement_for_feature(
    entitlements: Dict[str, Entitlement],
    feature_key: str,
) -> Optional[Entitlement]:
    for key in FEATURE_ENTITLEMENT_ALIASES.get(feature_key, (feature_key,)):
        entitlement = entitlements.get(key)
        if entitlement is not None:
            return entitlement
    return None


def _normalized_entitlement_value(value: Any) -> str:
    return str(value if value is not None else "").strip().lower()


def _entitlement_allows(value: Any) -> bool:
    normalized = _normalized_entitlement_value(value)
    return normalized in {"true", "1", "yes", "y", "on", "enabled", "unlimited"}


def _entitlement_limit(value: Any) -> Optional[int]:
    normalized = _normalized_entitlement_value(value)
    if normalized in {"", "false", "no", "off", "disabled"}:
        return 0
    if normalized in {"true", "yes", "on", "enabled", "unlimited"}:
        return None
    try:
        limit = int(normalized)
    except (TypeError, ValueError):
        return None
    return max(0, limit)


def _limit_status(current: int, limit: Optional[int]) -> str:
    if limit is None:
        return "ok"
    if current > limit:
        return "exceeded"
    if limit > 0 and current >= _limit_warning_threshold(limit):
        return "warning"
    return "ok"


def _limit_warning_threshold(limit: Optional[int]) -> Optional[int]:
    if limit is None:
        return None
    if limit <= 0:
        return 0
    return max(1, int(limit * 0.8))


def _limit_usage_percent(current: int, limit: Optional[int]) -> Optional[float]:
    if limit is None:
        return None
    if limit <= 0:
        return 100.0 if current > 0 else 0.0
    return round((current / limit) * 100, 1)


def _metric_label(metric: str) -> str:
    return metric.replace("_", " ")


def _metric_verb() -> str:
    return "are"


def _limit_message(metric: str, current: int, limit: Optional[int], status: str) -> Optional[str]:
    if limit is None or status == "ok":
        return None
    label = _metric_label(metric)
    verb = _metric_verb()
    if status == "exceeded":
        return (
            f"{label} {verb} over the plan limit ({current} used, limit {limit}). "
            "Exports remain available; reduce usage or upgrade the plan."
        )
    remaining = max(0, limit - current)
    if remaining == 0:
        return f"{label} {verb} at the plan limit ({current}/{limit})."
    return f"{label} {verb} approaching the plan limit ({current}/{limit}); {remaining} remaining."


def _limit_payload(
    *,
    metric: str,
    current: int,
    limit: Optional[int],
    unit: str = "count",
    enforced: bool = True,
) -> Dict[str, Any]:
    current_value = int(current or 0)
    status = _limit_status(current_value, limit)
    return {
        "metric": metric,
        "current": current_value,
        "limit": limit,
        "remaining": None if limit is None else max(0, limit - current_value),
        "unit": unit,
        "status": status,
        "enforced": enforced,
        "near_limit": status in {"warning", "exceeded"},
        "usage_percent": _limit_usage_percent(current_value, limit),
        "warning_threshold": _limit_warning_threshold(limit),
        "message": _limit_message(metric, current_value, limit, status),
    }


def organization_feature_allowed(
    entitlements: Iterable[Entitlement],
    feature_key: str,
) -> bool:
    """Return whether an organization entitlement allows an optional feature."""
    entitlement = _entitlement_for_feature(_entitlements_by_key(entitlements), feature_key)
    if entitlement is None:
        return True
    return _entitlement_allows(entitlement.value)


def require_organization_feature(
    db: Session,
    organization: Organization,
    feature_key: str,
) -> None:
    """Raise ValueError when an optional feature is not included in the plan."""
    entitlements = _active_entitlements_query(db, organization).all()
    if organization_feature_allowed(entitlements, feature_key):
        return

    entitlement = _entitlement_for_feature(_entitlements_by_key(entitlements), feature_key)
    raise ValueError(
        f"Feature '{feature_key}' is not included in this organization's current plan"
        + (f" ({entitlement.key}={entitlement.value})" if entitlement else "")
    )


def _active_user_ids_for_organization(
    db: Session,
    organization: Organization,
    workspaces: Optional[List[Workspace]] = None,
) -> set[int]:
    """Return active user IDs that currently consume seats for an organization."""
    if workspaces is None:
        workspaces = (
            db.query(Workspace)
            .filter(Workspace.organization_id == organization.id)
            .order_by(Workspace.slug.asc())
            .all()
        )
    workspace_ids = [workspace.id for workspace in workspaces]
    workspace_filter = workspace_ids or [-1]

    user_ids = {
        user_id
        for (user_id,) in db.query(User.id)
        .filter(User.workspace_id.in_(workspace_filter), User.is_active.is_(True))
        .all()
    }
    user_ids.update(
        user_id
        for (user_id,) in db.query(WorkspaceMembership.user_id)
        .join(User, WorkspaceMembership.user_id == User.id)
        .filter(
            WorkspaceMembership.workspace_id.in_(workspace_filter),
            WorkspaceMembership.active.is_(True),
            User.is_active.is_(True),
        )
        .all()
    )
    user_ids.update(
        user_id
        for (user_id,) in db.query(OrganizationMembership.user_id)
        .join(User, OrganizationMembership.user_id == User.id)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.active.is_(True),
            User.is_active.is_(True),
        )
        .all()
    )
    return user_ids


def organization_user_has_active_seat(
    db: Session,
    organization: Organization,
    user: User,
) -> bool:
    """Return whether a user already consumes one active seat in an organization."""
    if not user.is_active:
        return False
    return user.id in _active_user_ids_for_organization(db, organization)


def _aggregate_messages_for_period(
    db: Session,
    workspace_ids: List[int],
    period_start: datetime,
    period_end: datetime,
) -> int:
    if not workspace_ids:
        return 0
    return int(
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


def _period_plan_limit_usage(
    db: Session,
    workspace_ids: List[int],
    metric_filter: set[str],
) -> tuple[Dict[str, int], Dict[str, Dict[str, str]]]:
    if "aggregate_messages" not in metric_filter:
        return {}, {}
    usage_period = usage_period_for_current_month()
    usage_period_start, usage_period_end = parse_usage_period(usage_period)
    return (
        {
            "aggregate_messages": _aggregate_messages_for_period(
                db,
                workspace_ids,
                usage_period_start,
                usage_period_end,
            )
        },
        {
            "aggregate_messages": {
                "period": usage_period,
                "period_start": usage_period_start.isoformat(),
                "period_end": usage_period_end.isoformat(),
            }
        },
    )


def _plan_limits_for_organization(
    db: Session,
    organization: Organization,
    workspaces: List[Workspace],
    entitlements: List[Entitlement],
    metrics: Optional[Iterable[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    entitlement_map = _entitlements_by_key(entitlements)
    workspace_ids = [workspace.id for workspace in workspaces]
    workspace_filter = workspace_ids or [-1]
    metric_filter = set(metrics) if metrics is not None else set(PLAN_LIMIT_ENTITLEMENT_ALIASES)

    current_values: Dict[str, int] = {}
    period_values, period_contexts = _period_plan_limit_usage(db, workspace_ids, metric_filter)
    current_values.update(period_values)
    if "monitored_domains" in metric_filter:
        current_values["monitored_domains"] = (
            db.query(func.count(Domain.id))
            .filter(Domain.workspace_id.in_(workspace_filter), Domain.active.is_(True))
            .scalar()
            or 0
        )
    if "mail_sources" in metric_filter:
        current_values["mail_sources"] = (
            db.query(func.count(MailSource.id))
            .filter(MailSource.workspace_id.in_(workspace_filter), MailSource.enabled.is_(True))
            .scalar()
            or 0
        )
    if "users" in metric_filter:
        current_values["users"] = len(
            _active_user_ids_for_organization(db, organization, workspaces)
        )
    if "api_tokens" in metric_filter:
        current_values["api_tokens"] = (
            db.query(func.count(APIToken.id))
            .filter(APIToken.workspace_id.in_(workspace_filter), APIToken.active.is_(True))
            .scalar()
            or 0
        )
    if "webhooks" in metric_filter:
        current_values["webhooks"] = (
            db.query(func.count(WebhookEndpoint.id))
            .filter(
                WebhookEndpoint.workspace_id.in_(workspace_filter),
                WebhookEndpoint.enabled.is_(True),
            )
            .scalar()
            or 0
        )
    if "retention_days" in metric_filter:
        current_values["retention_days"] = max(
            [
                value or 0
                for workspace in workspaces
                for value in (
                    workspace.report_retention_days,
                    workspace.forensic_retention_days,
                    workspace.tls_report_retention_days,
                )
            ]
            or [0]
        )

    limits: Dict[str, Dict[str, Any]] = {}
    for metric, aliases in PLAN_LIMIT_ENTITLEMENT_ALIASES.items():
        if metric not in metric_filter:
            continue
        entitlement = next(
            (entitlement_map.get(alias) for alias in aliases if alias in entitlement_map), None
        )
        if entitlement is None:
            continue
        limits[metric] = _limit_payload(
            metric=metric,
            current=current_values.get(metric, 0),
            limit=_entitlement_limit(entitlement.value),
            unit=PLAN_LIMIT_UNITS.get(metric, "count"),
            enforced=metric in ENFORCED_PLAN_LIMITS,
        )
        limits[metric]["source"] = entitlement.source
        limits[metric]["entitlement_key"] = entitlement.key
        limits[metric].update(period_contexts.get(metric, {}))
    return limits


def organization_plan_limit(
    db: Session,
    organization: Organization,
    metric: str,
) -> Optional[Dict[str, Any]]:
    """Return the current plan-limit payload for one metric, if configured."""
    entitlements = _active_entitlements_query(db, organization).all()
    workspaces = (
        db.query(Workspace)
        .filter(Workspace.organization_id == organization.id)
        .order_by(Workspace.slug.asc())
        .all()
    )
    return _plan_limits_for_organization(db, organization, workspaces, entitlements).get(metric)


def require_organization_plan_limit(
    db: Session,
    organization: Organization,
    metric: str,
    *,
    increment: int = 1,
) -> None:
    """Raise when a mutation would exceed a configured organization plan limit."""
    if increment <= 0:
        return
    locked_organization = (
        db.query(Organization)
        .filter(Organization.id == organization.id)
        .with_for_update()
        .one_or_none()
    )
    limit_payload = organization_plan_limit(db, locked_organization or organization, metric)
    if not limit_payload:
        return
    limit = limit_payload.get("limit")
    if limit is None:
        return
    current = int(limit_payload.get("current") or 0)
    attempted = int(increment)
    if current + attempted <= int(limit):
        return
    raise OrganizationPlanLimitError(
        metric=metric,
        current=current,
        limit=int(limit),
        attempted=attempted,
        unit=str(limit_payload.get("unit") or "count"),
        entitlement_key=limit_payload.get("entitlement_key"),
    )


def require_organization_retention_limit(
    db: Session,
    organization: Organization,
    requested_days: int,
) -> None:
    """Raise when a requested retention window exceeds the organization's plan."""
    if requested_days <= 0:
        return
    locked_organization = (
        db.query(Organization)
        .filter(Organization.id == organization.id)
        .with_for_update()
        .one_or_none()
    )
    limit_payload = organization_plan_limit(
        db,
        locked_organization or organization,
        "retention_days",
    )
    if not limit_payload:
        return
    limit = limit_payload.get("limit")
    if limit is None:
        return
    requested = int(requested_days)
    limit_value = int(limit)
    if requested <= limit_value:
        return
    current = int(limit_payload.get("current") or 0)
    raise OrganizationPlanLimitError(
        metric="retention_days",
        current=current,
        limit=limit_value,
        attempted=max(0, requested - current),
        unit="days",
        entitlement_key=limit_payload.get("entitlement_key"),
    )


def organization_summary(
    db: Session,
    organization: Organization,
    *,
    include_plan_limits: bool = True,
    include_plan_limit_metrics: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
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
    entitlements = _active_entitlements_query(db, organization).all()
    entitlements_by_key = _entitlements_by_key(entitlements)
    summary = {
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
        "account_state": account_state_for_subscriptions(subscriptions),
        "entitlements": {
            entitlement.key: {
                "value": entitlement.value,
                "source": entitlement.source,
                "expires_at": _iso(entitlement.expires_at),
            }
            for entitlement in entitlements_by_key.values()
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
    if include_plan_limits:
        summary["plan_limits"] = _plan_limits_for_organization(
            db,
            organization,
            workspaces,
            entitlements,
            metrics=include_plan_limit_metrics,
        )
    return summary


def _billing_event_to_dict(event: BillingEvent) -> Dict[str, Any]:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "provider_id": event.provider_id,
        "external_event_id": event.external_event_id,
        "status": event.status,
    }


def _find_provider_event(
    db: Session,
    *,
    provider_id: str,
    external_event_id: Optional[str],
) -> Optional[BillingEvent]:
    if not external_event_id:
        return None
    return (
        db.query(BillingEvent)
        .filter(
            BillingEvent.event_type == "provider.customer_provisioned",
            BillingEvent.external_event_id == external_event_id,
            BillingEvent.provider_id == provider_id,
        )
        .order_by(BillingEvent.id.asc())
        .first()
    )


def _find_provider_account(
    db: Session,
    *,
    provider_id: str,
    external_customer_id: str,
) -> Optional[BillingAccount]:
    return (
        db.query(BillingAccount)
        .filter(
            BillingAccount.external_customer_id == external_customer_id,
            BillingAccount.provider_id == provider_id,
        )
        .order_by(BillingAccount.id.asc())
        .first()
    )


def _provider_replay_response(
    db: Session,
    *,
    event: BillingEvent,
    provider_id: str,
    external_customer_id: str,
) -> Dict[str, Any]:
    organization = None
    if event.organization_id:
        organization = (
            db.query(Organization).filter(Organization.id == event.organization_id).first()
        )
    if organization is None:
        account = _find_provider_account(
            db,
            provider_id=provider_id,
            external_customer_id=external_customer_id,
        )
        organization = account.organization if account else None
    return {
        "created": False,
        "idempotent_replay": True,
        "organization": organization_summary(db, organization) if organization else None,
        "billing_event": _billing_event_to_dict(event),
    }


def _resolve_provider_organization_and_account(
    db: Session,
    *,
    provider_id: str,
    external_customer_id: str,
    organization_slug: str,
    organization_name: str,
) -> tuple[Organization, BillingAccount, bool]:
    account = _find_provider_account(
        db,
        provider_id=provider_id,
        external_customer_id=external_customer_id,
    )
    if account:
        organization = account.organization
        account_created = False
    else:
        organization = db.query(Organization).filter(Organization.slug == organization_slug).first()
        if organization is None:
            organization = Organization(slug=organization_slug, name=organization_name, active=True)
            db.add(organization)
            db.flush()
        else:
            conflicting_account = (
                db.query(BillingAccount)
                .filter(
                    BillingAccount.organization_id == organization.id,
                    BillingAccount.external_customer_id.isnot(None),
                    BillingAccount.external_customer_id != external_customer_id,
                )
                .first()
            )
            if conflicting_account:
                raise ValueError("organization_slug is already linked to another provider customer")
        account = BillingAccount(
            organization_id=organization.id,
            billing_mode=BILLING_MODE_PROVIDER_RESALE,
            status="active",
            provider_id=provider_id,
            external_customer_id=external_customer_id,
            invoice_delivery_mode="provider_invoice",
        )
        db.add(account)
        db.flush()
        account_created = True

    organization.name = organization_name
    organization.active = True
    account.status = "active"
    account.billing_mode = BILLING_MODE_PROVIDER_RESALE
    account.provider_id = provider_id
    account.external_customer_id = external_customer_id
    account.invoice_delivery_mode = "provider_invoice"
    return organization, account, account_created


def _resolve_provider_workspace(
    db: Session,
    *,
    organization: Organization,
    workspace_slug: str,
    workspace_name: str,
) -> tuple[Workspace, bool]:
    workspace = db.query(Workspace).filter(Workspace.slug == workspace_slug).first()
    if workspace and workspace.organization_id != organization.id:
        raise ValueError("workspace_slug is already linked to another organization")
    if workspace is None:
        workspace = Workspace(
            slug=workspace_slug,
            name=workspace_name,
            organization_id=organization.id,
            active=True,
        )
        db.add(workspace)
        return workspace, True
    workspace.name = workspace_name
    workspace.organization_id = organization.id
    workspace.active = True
    return workspace, False


def _resolve_provider_plan(db: Session, *, plan_code: str) -> Plan:
    plan = db.query(Plan).filter(Plan.code == plan_code, Plan.active.is_(True)).first()
    if plan:
        return plan
    if plan_code == STARTER_PLAN_CODE:
        return get_or_create_starter_plan(db, commit=False)
    raise ValueError("plan_code does not exist or is inactive")


def _resolve_provider_subscription(
    db: Session,
    *,
    organization: Organization,
    account: BillingAccount,
    plan: Plan,
    external_subscription_id: str,
    plan_code: str = STARTER_PLAN_CODE,
    external_product_code: Optional[str] = None,
) -> tuple[Subscription, bool]:
    subscription = (
        db.query(Subscription)
        .filter(Subscription.external_subscription_id == external_subscription_id)
        .first()
    )
    if subscription and subscription.organization_id != organization.id:
        raise ValueError("external_subscription_id is already linked to another organization")
    if subscription is None:
        subscription = Subscription(
            organization_id=organization.id,
            plan_id=plan.id,
            billing_account_id=account.id,
            billing_mode=BILLING_MODE_PROVIDER_RESALE,
            status="active",
            current_period_start=datetime.utcnow(),
            external_subscription_id=external_subscription_id,
            external_product_code=(external_product_code or plan_code).strip() or plan_code,
        )
        db.add(subscription)
        return subscription, True
    subscription.plan_id = plan.id
    subscription.billing_account_id = account.id
    subscription.billing_mode = BILLING_MODE_PROVIDER_RESALE
    subscription.status = "active"
    subscription.external_product_code = (
        external_product_code or subscription.external_product_code or plan_code
    ).strip() or plan_code
    subscription.canceled_at = None
    return subscription, False


def provision_provider_customer(
    db: Session,
    *,
    external_customer_id: str,
    external_subscription_id: str,
    organization_slug: str,
    organization_name: str,
    workspace_slug: Optional[str] = None,
    workspace_name: Optional[str] = None,
    provider_id: str,
    plan_code: str = STARTER_PLAN_CODE,
    external_product_code: Optional[str] = None,
    external_event_id: Optional[str] = None,
    payload_summary: Optional[str] = None,
    commit: bool = True,
) -> Dict[str, Any]:
    """Provision or update a provider-billed customer tenant idempotently."""
    provider = _clean_required(provider_id, field_name="provider_id")
    external_customer = _clean_required(
        external_customer_id,
        field_name="external_customer_id",
    )
    external_subscription = _clean_required(
        external_subscription_id,
        field_name="external_subscription_id",
    )
    org_slug = _normalize_required_slug(organization_slug, field_name="organization_slug")
    org_name = _clean_required(organization_name, field_name="organization_name")
    ws_slug = _normalize_required_slug(
        workspace_slug or f"{org_slug}-workspace",
        field_name="workspace_slug",
    )
    ws_name = _clean_required(
        workspace_name if workspace_name is not None else f"{org_name} Workspace",
        field_name="workspace_name",
    )
    plan_key = (plan_code or STARTER_PLAN_CODE).strip()
    if plan_key != STARTER_PLAN_CODE:
        raise ValueError("plan_code must be starter until provider entitlements are configurable")

    replay_event = _find_provider_event(
        db,
        provider_id=provider,
        external_event_id=external_event_id,
    )
    if replay_event:
        return _provider_replay_response(
            db,
            event=replay_event,
            provider_id=provider,
            external_customer_id=external_customer,
        )

    organization, account, created_account = _resolve_provider_organization_and_account(
        db,
        provider_id=provider,
        external_customer_id=external_customer,
        organization_slug=org_slug,
        organization_name=org_name,
    )
    _, created_workspace = _resolve_provider_workspace(
        db,
        organization=organization,
        workspace_slug=ws_slug,
        workspace_name=ws_name,
    )
    db.flush()

    plan = _resolve_provider_plan(db, plan_code=plan_key)
    subscription, created_subscription = _resolve_provider_subscription(
        db,
        organization=organization,
        account=account,
        plan=plan,
        external_subscription_id=external_subscription,
        plan_code=plan_key,
        external_product_code=external_product_code,
    )
    db.flush()

    ensure_entitlements(
        db,
        organization,
        subscription,
        STARTER_PLAN_ENTITLEMENTS,
        commit=False,
    )
    event = BillingEvent(
        organization_id=organization.id,
        subscription_id=subscription.id,
        billing_mode=BILLING_MODE_PROVIDER_RESALE,
        event_type="provider.customer_provisioned",
        provider_id=provider,
        external_event_id=external_event_id,
        status="applied",
        payload_summary=_sanitize_payload_summary(payload_summary),
    )
    db.add(event)
    if commit:
        db.commit()
        db.refresh(organization)
        db.refresh(event)
    else:
        db.flush()

    return {
        "created": created_account or created_workspace or created_subscription,
        "idempotent_replay": False,
        "organization": organization_summary(db, organization),
        "billing_event": _billing_event_to_dict(event),
    }


def list_organization_summaries(db: Session) -> List[Dict[str, Any]]:
    """Return all organizations with local commercial state materialized."""
    bootstrap_default_commercial_foundation(db)
    organizations = db.query(Organization).order_by(Organization.slug.asc()).all()
    return [
        organization_summary(db, organization, include_plan_limit_metrics=("users",))
        for organization in organizations
    ]


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
    return [
        organization_summary(db, organization, include_plan_limit_metrics=("users",))
        for organization in query.all()
    ]


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
