from sqlalchemy.orm import Session

from app.models.organization import (
    BillingAccount,
    Entitlement,
    Organization,
    Plan,
    Subscription,
)
from app.models.workspace import Workspace
from app.services.organizations import (
    BILLING_MODE_SELF_HOSTED,
    DEFAULT_ORGANIZATION_SLUG,
    SELF_HOSTED_PLAN_CODE,
    bootstrap_default_commercial_foundation,
    list_organization_summaries,
)


def test_bootstrap_default_commercial_foundation_keeps_self_hosted_install_working(
    db_session: Session,
):
    workspace = Workspace(slug="default", name="Default Workspace", active=True)
    db_session.add(workspace)
    db_session.commit()

    organization = bootstrap_default_commercial_foundation(db_session)

    db_session.refresh(workspace)
    assert organization.slug == DEFAULT_ORGANIZATION_SLUG
    assert workspace.organization_id == organization.id
    assert (
        db_session.query(Plan).filter(Plan.code == SELF_HOSTED_PLAN_CODE).one().billing_mode
        == BILLING_MODE_SELF_HOSTED
    )
    assert (
        db_session.query(BillingAccount)
        .filter(BillingAccount.organization_id == organization.id)
        .one()
        .billing_mode
        == BILLING_MODE_SELF_HOSTED
    )
    assert (
        db_session.query(Subscription)
        .filter(Subscription.organization_id == organization.id)
        .one()
        .status
        == "active"
    )
    entitlement_keys = {
        entitlement.key
        for entitlement in db_session.query(Entitlement)
        .filter(Entitlement.organization_id == organization.id)
        .all()
    }
    assert {"aggregate_reports", "forensic_reports", "dns_linting"} <= entitlement_keys


def test_bootstrap_default_commercial_foundation_is_idempotent(db_session: Session):
    bootstrap_default_commercial_foundation(db_session)
    bootstrap_default_commercial_foundation(db_session)

    assert db_session.query(Organization).count() == 1
    assert db_session.query(Plan).count() == 1
    assert db_session.query(BillingAccount).count() == 1
    assert db_session.query(Subscription).count() == 1


def test_list_organization_summaries_materializes_account_state(db_session: Session):
    bootstrap_default_commercial_foundation(db_session)

    summaries = list_organization_summaries(db_session)

    assert summaries[0]["slug"] == DEFAULT_ORGANIZATION_SLUG
    assert summaries[0]["billing_accounts"][0]["billing_mode"] == BILLING_MODE_SELF_HOSTED
    assert summaries[0]["subscriptions"][0]["plan"]["code"] == SELF_HOSTED_PLAN_CODE
    assert summaries[0]["entitlements"]["aggregate_reports"]["value"] == "true"
