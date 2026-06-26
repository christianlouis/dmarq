"""add organization billing foundations

Revision ID: 5f6a7b8c9d0e
Revises: 4e5f6a7b8c9d
Create Date: 2026-06-26 11:15:00.000000
"""

from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "5f6a7b8c9d0e"
down_revision: Union[str, None] = "4e5f6a7b8c9d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None
__all__ = [
    "revision",
    "down_revision",
    "branch_labels",
    "depends_on",
    "upgrade",
    "downgrade",
]


def _default_org_id_sql() -> str:
    return "(SELECT id FROM organizations WHERE slug = 'default')"


def upgrade() -> None:
    now = datetime.utcnow()
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_organizations_id"), "organizations", ["id"])
    op.create_index(op.f("ix_organizations_slug"), "organizations", ["slug"])
    op.create_index(op.f("ix_organizations_active"), "organizations", ["active"])
    op.create_index(op.f("ix_organizations_created_at"), "organizations", ["created_at"])
    op.create_index("ix_organizations_active_slug", "organizations", ["active", "slug"])

    organizations = sa.table(
        "organizations",
        sa.column("slug", sa.String()),
        sa.column("name", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("active", sa.Boolean()),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    op.bulk_insert(
        organizations,
        [
            {
                "slug": "default",
                "name": "Default Organization",
                "description": "Automatically created for existing single-tenant installs.",
                "active": True,
                "created_at": now,
                "updated_at": now,
            }
        ],
    )

    with op.batch_alter_table("workspaces") as batch_op:
        batch_op.add_column(sa.Column("organization_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_workspaces_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
        )
        batch_op.create_index(op.f("ix_workspaces_organization_id"), ["organization_id"])

    op.execute(
        f"UPDATE workspaces SET organization_id = {_default_org_id_sql()} "
        "WHERE organization_id IS NULL"
    )

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_organization_memberships_org_role",
        "organization_memberships",
        ["organization_id", "role"],
    )
    op.create_index(
        "ix_organization_memberships_org_user",
        "organization_memberships",
        ["organization_id", "user_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_organization_memberships_organization_id"),
        "organization_memberships",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_organization_memberships_user_id"), "organization_memberships", ["user_id"]
    )
    op.create_index(op.f("ix_organization_memberships_role"), "organization_memberships", ["role"])
    op.create_index(
        op.f("ix_organization_memberships_active"), "organization_memberships", ["active"]
    )
    op.create_index(
        op.f("ix_organization_memberships_created_at"),
        "organization_memberships",
        ["created_at"],
    )

    op.create_table(
        "plans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("billing_mode", sa.String(length=50), nullable=False),
        sa.Column("public", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("monthly_price_cents", sa.Integer(), nullable=True),
        sa.Column("annual_price_cents", sa.Integer(), nullable=True),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("included_sending_domains", sa.Integer(), nullable=True),
        sa.Column("included_message_volume", sa.Integer(), nullable=True),
        sa.Column("included_users", sa.Integer(), nullable=True),
        sa.Column("retention_days", sa.Integer(), nullable=True),
        sa.Column("features", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )
    op.create_index(op.f("ix_plans_id"), "plans", ["id"])
    op.create_index(op.f("ix_plans_code"), "plans", ["code"])
    op.create_index(op.f("ix_plans_billing_mode"), "plans", ["billing_mode"])
    op.create_index(op.f("ix_plans_public"), "plans", ["public"])
    op.create_index(op.f("ix_plans_active"), "plans", ["active"])
    op.create_index(op.f("ix_plans_created_at"), "plans", ["created_at"])

    plans = sa.table(
        "plans",
        sa.column("code", sa.String()),
        sa.column("name", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("billing_mode", sa.String()),
        sa.column("public", sa.Boolean()),
        sa.column("active", sa.Boolean()),
        sa.column("currency", sa.String()),
        sa.column("included_sending_domains", sa.Integer()),
        sa.column("included_message_volume", sa.Integer()),
        sa.column("included_users", sa.Integer()),
        sa.column("retention_days", sa.Integer()),
        sa.column("features", sa.Text()),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    op.bulk_insert(
        plans,
        [
            {
                "code": "self_hosted",
                "name": "Self-hosted",
                "description": "Default local deployment plan with no external billing dependency.",
                "billing_mode": "self_hosted_license",
                "public": False,
                "active": True,
                "currency": "EUR",
                "included_sending_domains": None,
                "included_message_volume": None,
                "included_users": None,
                "retention_days": 400,
                "features": "aggregate_reports,forensic_reports,dns_linting,alerts,multi_workspace",
                "created_at": now,
                "updated_at": now,
            }
        ],
    )

    op.create_table(
        "billing_accounts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("billing_mode", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("provider_id", sa.String(length=120), nullable=True),
        sa.Column("external_customer_id", sa.String(length=120), nullable=True),
        sa.Column("stripe_customer_id", sa.String(length=120), nullable=True),
        sa.Column("invoice_delivery_mode", sa.String(length=50), nullable=False),
        sa.Column("tax_reference", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_billing_accounts_org_mode", "billing_accounts", ["organization_id", "billing_mode"]
    )
    op.create_index(op.f("ix_billing_accounts_id"), "billing_accounts", ["id"])
    op.create_index(
        op.f("ix_billing_accounts_organization_id"), "billing_accounts", ["organization_id"]
    )
    op.create_index(op.f("ix_billing_accounts_billing_mode"), "billing_accounts", ["billing_mode"])
    op.create_index(op.f("ix_billing_accounts_status"), "billing_accounts", ["status"])
    op.create_index(op.f("ix_billing_accounts_provider_id"), "billing_accounts", ["provider_id"])
    op.create_index(
        op.f("ix_billing_accounts_external_customer_id"),
        "billing_accounts",
        ["external_customer_id"],
    )
    op.create_index(
        op.f("ix_billing_accounts_stripe_customer_id"), "billing_accounts", ["stripe_customer_id"]
    )
    op.create_index(op.f("ix_billing_accounts_created_at"), "billing_accounts", ["created_at"])

    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("billing_account_id", sa.Integer(), nullable=True),
        sa.Column("billing_mode", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("current_period_start", sa.DateTime(), nullable=True),
        sa.Column("current_period_end", sa.DateTime(), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(length=120), nullable=True),
        sa.Column("external_subscription_id", sa.String(length=120), nullable=True),
        sa.Column("external_product_code", sa.String(length=120), nullable=True),
        sa.Column("canceled_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["billing_account_id"], ["billing_accounts.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["plan_id"], ["plans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("stripe_subscription_id"),
    )
    op.create_index(
        "ix_subscriptions_external", "subscriptions", ["billing_mode", "external_subscription_id"]
    )
    op.create_index("ix_subscriptions_org_status", "subscriptions", ["organization_id", "status"])
    op.create_index(op.f("ix_subscriptions_id"), "subscriptions", ["id"])
    op.create_index(op.f("ix_subscriptions_organization_id"), "subscriptions", ["organization_id"])
    op.create_index(op.f("ix_subscriptions_plan_id"), "subscriptions", ["plan_id"])
    op.create_index(
        op.f("ix_subscriptions_billing_account_id"), "subscriptions", ["billing_account_id"]
    )
    op.create_index(op.f("ix_subscriptions_billing_mode"), "subscriptions", ["billing_mode"])
    op.create_index(op.f("ix_subscriptions_status"), "subscriptions", ["status"])
    op.create_index(
        op.f("ix_subscriptions_current_period_start"), "subscriptions", ["current_period_start"]
    )
    op.create_index(
        op.f("ix_subscriptions_current_period_end"), "subscriptions", ["current_period_end"]
    )
    op.create_index(
        op.f("ix_subscriptions_stripe_subscription_id"),
        "subscriptions",
        ["stripe_subscription_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_subscriptions_external_subscription_id"),
        "subscriptions",
        ["external_subscription_id"],
    )
    op.create_index(op.f("ix_subscriptions_created_at"), "subscriptions", ["created_at"])

    op.create_table(
        "entitlements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=True),
        sa.Column("key", sa.String(length=120), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("effective_from", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscriptions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_entitlements_org_key_active", "entitlements", ["organization_id", "key", "active"]
    )
    op.create_index(op.f("ix_entitlements_id"), "entitlements", ["id"])
    op.create_index(op.f("ix_entitlements_organization_id"), "entitlements", ["organization_id"])
    op.create_index(op.f("ix_entitlements_subscription_id"), "entitlements", ["subscription_id"])
    op.create_index(op.f("ix_entitlements_key"), "entitlements", ["key"])
    op.create_index(op.f("ix_entitlements_source"), "entitlements", ["source"])
    op.create_index(op.f("ix_entitlements_active"), "entitlements", ["active"])
    op.create_index(op.f("ix_entitlements_effective_from"), "entitlements", ["effective_from"])
    op.create_index(op.f("ix_entitlements_expires_at"), "entitlements", ["expires_at"])
    op.create_index(op.f("ix_entitlements_created_at"), "entitlements", ["created_at"])

    op.create_table(
        "usage_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=True),
        sa.Column("metric", sa.String(length=120), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("unit", sa.String(length=50), nullable=False),
        sa.Column("period_start", sa.DateTime(), nullable=False),
        sa.Column("period_end", sa.DateTime(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("external_customer_id", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_index(
        "ix_usage_records_org_metric_period",
        "usage_records",
        ["organization_id", "metric", "period_start"],
    )
    op.create_index(op.f("ix_usage_records_id"), "usage_records", ["id"])
    op.create_index(op.f("ix_usage_records_organization_id"), "usage_records", ["organization_id"])
    op.create_index(op.f("ix_usage_records_workspace_id"), "usage_records", ["workspace_id"])
    op.create_index(op.f("ix_usage_records_metric"), "usage_records", ["metric"])
    op.create_index(op.f("ix_usage_records_period_start"), "usage_records", ["period_start"])
    op.create_index(op.f("ix_usage_records_period_end"), "usage_records", ["period_end"])
    op.create_index(
        op.f("ix_usage_records_idempotency_key"), "usage_records", ["idempotency_key"], unique=True
    )
    op.create_index(op.f("ix_usage_records_source"), "usage_records", ["source"])
    op.create_index(
        op.f("ix_usage_records_external_customer_id"), "usage_records", ["external_customer_id"]
    )
    op.create_index(op.f("ix_usage_records_created_at"), "usage_records", ["created_at"])

    op.create_table(
        "provider_integrations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("provider_type", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("external_provider_id", sa.String(length=120), nullable=True),
        sa.Column("scopes", sa.Text(), nullable=True),
        sa.Column("callback_url", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_provider_integrations_type_status",
        "provider_integrations",
        ["provider_type", "status"],
    )
    op.create_index(op.f("ix_provider_integrations_id"), "provider_integrations", ["id"])
    op.create_index(
        op.f("ix_provider_integrations_organization_id"),
        "provider_integrations",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_provider_integrations_provider_type"), "provider_integrations", ["provider_type"]
    )
    op.create_index(op.f("ix_provider_integrations_status"), "provider_integrations", ["status"])
    op.create_index(
        op.f("ix_provider_integrations_external_provider_id"),
        "provider_integrations",
        ["external_provider_id"],
    )
    op.create_index(
        op.f("ix_provider_integrations_created_at"), "provider_integrations", ["created_at"]
    )

    op.create_table(
        "billing_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("subscription_id", sa.Integer(), nullable=True),
        sa.Column("billing_mode", sa.String(length=50), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("provider_id", sa.String(length=120), nullable=True),
        sa.Column("external_event_id", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("payload_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscriptions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_billing_events_provider_event", "billing_events", ["provider_id", "external_event_id"]
    )
    op.create_index(op.f("ix_billing_events_id"), "billing_events", ["id"])
    op.create_index(
        op.f("ix_billing_events_organization_id"), "billing_events", ["organization_id"]
    )
    op.create_index(
        op.f("ix_billing_events_subscription_id"), "billing_events", ["subscription_id"]
    )
    op.create_index(op.f("ix_billing_events_billing_mode"), "billing_events", ["billing_mode"])
    op.create_index(op.f("ix_billing_events_event_type"), "billing_events", ["event_type"])
    op.create_index(op.f("ix_billing_events_provider_id"), "billing_events", ["provider_id"])
    op.create_index(
        op.f("ix_billing_events_external_event_id"), "billing_events", ["external_event_id"]
    )
    op.create_index(op.f("ix_billing_events_status"), "billing_events", ["status"])
    op.create_index(op.f("ix_billing_events_created_at"), "billing_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("billing_events")
    op.drop_table("provider_integrations")
    op.drop_table("usage_records")
    op.drop_table("entitlements")
    op.drop_table("subscriptions")
    op.drop_table("billing_accounts")
    op.drop_table("plans")
    op.drop_table("organization_memberships")

    with op.batch_alter_table("workspaces") as batch_op:
        batch_op.drop_index(op.f("ix_workspaces_organization_id"))
        batch_op.drop_constraint("fk_workspaces_organization_id_organizations", type_="foreignkey")
        batch_op.drop_column("organization_id")

    op.drop_table("organizations")
