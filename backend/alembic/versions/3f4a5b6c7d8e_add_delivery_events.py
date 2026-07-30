"""Add privacy-minimized delivery event evidence.

Revision ID: 3f4a5b6c7d8e
Revises: 2e3f4a5b6c7d
"""

import sqlalchemy as sa
from alembic import op

revision = "3f4a5b6c7d8e"
down_revision = "2e3f4a5b6c7d"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "workspaces",
        sa.Column(
            "delivery_event_retention_days", sa.Integer(), nullable=False, server_default="30"
        ),
    )
    op.create_table(
        "delivery_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("source_system", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("event_id", sa.String(length=160), nullable=False),
        sa.Column("normalized_event", sa.String(length=32), nullable=False),
        sa.Column("original_event", sa.String(length=120), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=True),
        sa.Column("status_code", sa.String(length=32), nullable=True),
        sa.Column("diagnostic_type", sa.String(length=80), nullable=True),
        sa.Column("diagnostic_text", sa.Text(), nullable=True),
        sa.Column("cause_family", sa.String(length=64), nullable=False),
        sa.Column("recipient_domain", sa.String(length=255), nullable=True),
        sa.Column("recipient_hash", sa.String(length=64), nullable=True),
        sa.Column("message_id_hash", sa.String(length=64), nullable=True),
        sa.Column("envelope_id_hash", sa.String(length=64), nullable=True),
        sa.Column("reporting_mta", sa.String(length=255), nullable=True),
        sa.Column("remote_mta", sa.String(length=255), nullable=True),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("retention_until", sa.DateTime(), nullable=False),
        sa.Column("correlation_confidence", sa.String(length=24), nullable=False),
        sa.Column("correlation_reasons", sa.Text(), nullable=True),
        sa.Column("provider_semantics", sa.Text(), nullable=True),
        sa.Column("signal_json", sa.Text(), nullable=False),
        sa.Column("sanitized_payload", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "source_system",
            "provider",
            "event_id",
            name="uq_delivery_event_workspace_source_event",
        ),
    )
    for column in (
        "id",
        "workspace_id",
        "domain",
        "source_system",
        "provider",
        "normalized_event",
        "status_code",
        "cause_family",
        "recipient_domain",
        "recipient_hash",
        "message_id_hash",
        "envelope_id_hash",
        "occurred_at",
        "received_at",
        "retention_until",
    ):
        op.create_index(f"ix_delivery_events_{column}", "delivery_events", [column])
    op.create_index(
        "ix_delivery_events_workspace_domain_occurred",
        "delivery_events",
        ["workspace_id", "domain", "occurred_at"],
    )
    op.create_index(
        "ix_delivery_events_workspace_outcome_occurred",
        "delivery_events",
        ["workspace_id", "normalized_event", "occurred_at"],
    )


def downgrade():
    op.drop_table("delivery_events")
    op.drop_column("workspaces", "delivery_event_retention_days")
