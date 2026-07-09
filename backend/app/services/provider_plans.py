"""Optional starter catalog for a newly installed provider deployment."""

from typing import Dict

from sqlalchemy.orm import Session

from app.models.organization import Plan
from app.services.organizations import BILLING_MODE_PROVIDER_RESALE

DEFAULT_PROVIDER_PLANS = (
    {
        "code": "monitor",
        "name": "DMARQ Monitor",
        "monthly_price_cents": 1900,
        "included_sending_domains": 5,
        "included_users": 10,
        "included_message_volume": 500_000,
        "retention_days": 90,
    },
    {
        "code": "protect",
        "name": "DMARQ Protect",
        "monthly_price_cents": 3900,
        "included_sending_domains": 15,
        "included_users": 25,
        "included_message_volume": 2_000_000,
        "retention_days": 180,
    },
    {
        "code": "protect_plus",
        "name": "DMARQ Protect Plus",
        "monthly_price_cents": 7900,
        "included_sending_domains": 50,
        "included_users": 100,
        "included_message_volume": 10_000_000,
        "retention_days": 400,
    },
)


def ensure_default_provider_plans(db: Session, *, commit: bool = True) -> Dict[str, int]:
    """Create missing provider plans without overwriting an existing catalog."""
    created = 0
    for defaults in DEFAULT_PROVIDER_PLANS:
        if db.query(Plan).filter(Plan.code == defaults["code"]).first() is not None:
            continue
        db.add(
            Plan(
                **defaults,
                description="Provider-managed DMARQ plan for multi-tenant deployments.",
                billing_mode=BILLING_MODE_PROVIDER_RESALE,
                public=True,
                active=True,
                currency="EUR",
                features=(
                    "aggregate_reports,forensic_reports,dns_linting,alerts,"
                    "multi_workspace,provider_support"
                ),
            )
        )
        created += 1
    if commit:
        db.commit()
    else:
        db.flush()
    return {"created": created, "available": len(DEFAULT_PROVIDER_PLANS)}
