"""add health score snapshots

Revision ID: b1c2d3e4f5a6
Revises: a0b1c2d3e4f5
Create Date: 2026-06-29 15:45:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b1c2d3e4f5a6"
down_revision: Union[str, Sequence[str], None] = "a0b1c2d3e4f5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create persisted domain health score snapshots."""
    op.create_table(
        "health_score_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("domain_name", sa.String(length=255), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("grade", sa.String(length=4), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("policy", sa.String(length=32), nullable=True),
        sa.Column("compliance_rate", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_emails", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_emails", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("report_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dns_posture_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("policy_strength_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("report_confidence_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("top_actions", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "domain_name",
            "snapshot_date",
            name="uq_health_score_snapshot_workspace_domain_date",
        ),
    )
    op.create_index(
        op.f("ix_health_score_snapshots_id"), "health_score_snapshots", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_health_score_snapshots_workspace_id"),
        "health_score_snapshots",
        ["workspace_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_health_score_snapshots_domain_name"),
        "health_score_snapshots",
        ["domain_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_health_score_snapshots_snapshot_date"),
        "health_score_snapshots",
        ["snapshot_date"],
        unique=False,
    )
    op.create_index(
        op.f("ix_health_score_snapshots_created_at"),
        "health_score_snapshots",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_health_score_snapshots_workspace_domain",
        "health_score_snapshots",
        ["workspace_id", "domain_name"],
        unique=False,
    )


def downgrade() -> None:
    """Drop persisted domain health score snapshots."""
    op.drop_index("ix_health_score_snapshots_workspace_domain", table_name="health_score_snapshots")
    op.drop_index(op.f("ix_health_score_snapshots_created_at"), table_name="health_score_snapshots")
    op.drop_index(
        op.f("ix_health_score_snapshots_snapshot_date"), table_name="health_score_snapshots"
    )
    op.drop_index(
        op.f("ix_health_score_snapshots_domain_name"), table_name="health_score_snapshots"
    )
    op.drop_index(
        op.f("ix_health_score_snapshots_workspace_id"), table_name="health_score_snapshots"
    )
    op.drop_index(op.f("ix_health_score_snapshots_id"), table_name="health_score_snapshots")
    op.drop_table("health_score_snapshots")
