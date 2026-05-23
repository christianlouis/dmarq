"""add webhook event framework

Revision ID: 1b2c3d4e5f6a
Revises: 0a1b2c3d4e5f
Create Date: 2026-05-23 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1b2c3d4e5f6a"
down_revision: Union[str, Sequence[str], None] = "0a1b2c3d4e5f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create outbound webhook endpoint and delivery tables."""
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=False),
        sa.Column("event_types", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_webhook_endpoints_id"), "webhook_endpoints", ["id"])
    op.create_index(op.f("ix_webhook_endpoints_enabled"), "webhook_endpoints", ["enabled"])
    op.create_index(op.f("ix_webhook_endpoints_created_at"), "webhook_endpoints", ["created_at"])
    op.create_index(
        op.f("ix_webhook_endpoints_last_success_at"),
        "webhook_endpoints",
        ["last_success_at"],
    )
    op.create_index(
        op.f("ix_webhook_endpoints_last_failure_at"),
        "webhook_endpoints",
        ["last_failure_at"],
    )
    op.create_index(
        "ix_webhook_endpoints_enabled_events",
        "webhook_endpoints",
        ["enabled", "event_types"],
    )

    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("response_excerpt", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["endpoint_id"], ["webhook_endpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_webhook_deliveries_id"), "webhook_deliveries", ["id"])
    op.create_index(
        op.f("ix_webhook_deliveries_endpoint_id"), "webhook_deliveries", ["endpoint_id"]
    )
    op.create_index(op.f("ix_webhook_deliveries_event_type"), "webhook_deliveries", ["event_type"])
    op.create_index(
        op.f("ix_webhook_deliveries_idempotency_key"), "webhook_deliveries", ["idempotency_key"]
    )
    op.create_index(op.f("ix_webhook_deliveries_status"), "webhook_deliveries", ["status"])
    op.create_index(
        op.f("ix_webhook_deliveries_next_attempt_at"),
        "webhook_deliveries",
        ["next_attempt_at"],
    )
    op.create_index(
        op.f("ix_webhook_deliveries_last_attempt_at"),
        "webhook_deliveries",
        ["last_attempt_at"],
    )
    op.create_index(
        op.f("ix_webhook_deliveries_delivered_at"), "webhook_deliveries", ["delivered_at"]
    )
    op.create_index(op.f("ix_webhook_deliveries_created_at"), "webhook_deliveries", ["created_at"])
    op.create_index(
        "ix_webhook_delivery_endpoint_idempotency",
        "webhook_deliveries",
        ["endpoint_id", "idempotency_key"],
        unique=True,
    )
    op.create_index(
        "ix_webhook_delivery_due",
        "webhook_deliveries",
        ["status", "next_attempt_at"],
    )


def downgrade() -> None:
    """Drop outbound webhook endpoint and delivery tables."""
    op.drop_index("ix_webhook_delivery_due", table_name="webhook_deliveries")
    op.drop_index("ix_webhook_delivery_endpoint_idempotency", table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_created_at"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_delivered_at"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_last_attempt_at"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_next_attempt_at"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_status"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_idempotency_key"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_event_type"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_endpoint_id"), table_name="webhook_deliveries")
    op.drop_index(op.f("ix_webhook_deliveries_id"), table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")

    op.drop_index("ix_webhook_endpoints_enabled_events", table_name="webhook_endpoints")
    op.drop_index(op.f("ix_webhook_endpoints_last_failure_at"), table_name="webhook_endpoints")
    op.drop_index(op.f("ix_webhook_endpoints_last_success_at"), table_name="webhook_endpoints")
    op.drop_index(op.f("ix_webhook_endpoints_created_at"), table_name="webhook_endpoints")
    op.drop_index(op.f("ix_webhook_endpoints_enabled"), table_name="webhook_endpoints")
    op.drop_index(op.f("ix_webhook_endpoints_id"), table_name="webhook_endpoints")
    op.drop_table("webhook_endpoints")
