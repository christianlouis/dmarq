"""Persist calm-watch incident state per workspace.

Revision ID: fa1b2c3d4e5f
Revises: f9a0b1c2d3e4
Create Date: 2026-07-26 16:50:00
"""

from alembic import op
import sqlalchemy as sa


revision = "fa1b2c3d4e5f"
down_revision = "f9a0b1c2d3e4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "workspaces",
        sa.Column("notification_posture", sa.String(length=32), nullable=False, server_default="actionable_only"),
    )
    op.create_table(
        "mail_health_incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("incident_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("outcome", sa.String(length=64), nullable=False),
        sa.Column("intended_mail_impact", sa.String(length=32), nullable=False),
        sa.Column("urgency", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("material_state_hash", sa.String(length=64), nullable=False),
        sa.Column("assessment", sa.Text(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_material_change_at", sa.DateTime(), nullable=False),
        sa.Column("last_notified_at", sa.DateTime(), nullable=True),
        sa.Column("last_notification_reason", sa.String(length=64), nullable=True),
        sa.Column("snoozed_until", sa.DateTime(), nullable=True),
        sa.Column("operator_note", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolution_evidence", sa.Text(), nullable=True),
    )
    op.create_index("ix_mail_health_incidents_workspace_status", "mail_health_incidents", ["workspace_id", "status"])
    op.create_index("ix_mail_health_incidents_workspace_domain", "mail_health_incidents", ["workspace_id", "domain"])


def downgrade():
    op.drop_index("ix_mail_health_incidents_workspace_domain", table_name="mail_health_incidents")
    op.drop_index("ix_mail_health_incidents_workspace_status", table_name="mail_health_incidents")
    op.drop_table("mail_health_incidents")
    op.drop_column("workspaces", "notification_posture")
