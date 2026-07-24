"""Add ingestion-time sender read projections.

Revision ID: c7d8e9f0a1b2
Revises: b6c7d8e9f0a
Create Date: 2026-07-24 17:10:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c7d8e9f0a1b2"
down_revision: Union[str, Sequence[str], None] = "b6c7d8e9f0a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create a daily sender fact table and mark reports once projected."""
    op.add_column("dmarc_reports", sa.Column("source_projection_at", sa.DateTime(), nullable=True))
    op.create_index(
        op.f("ix_dmarc_reports_source_projection_at"),
        "dmarc_reports",
        ["source_projection_at"],
    )
    op.create_table(
        "domain_source_daily_projections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("source_ip", sa.String(), nullable=False),
        sa.Column("observed_at", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.Integer(), nullable=True),
        sa.Column("last_seen", sa.Integer(), nullable=True),
        sa.Column("message_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("report_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("spf_pass_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("spf_fail_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("spf_unknown_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dkim_pass_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dkim_fail_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dkim_unknown_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dmarc_pass_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dmarc_fail_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("disposition_counts", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("source_evidence", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "domain_id",
            "source_ip",
            "observed_at",
            name="uq_domain_source_daily_projection",
        ),
    )
    op.create_index(
        "ix_domain_source_daily_projection_window",
        "domain_source_daily_projections",
        ["domain_id", "observed_at", "source_ip"],
    )
    op.create_index(
        "ix_domain_source_daily_projection_last_seen",
        "domain_source_daily_projections",
        ["domain_id", "last_seen", "source_ip"],
    )


def downgrade() -> None:
    """Remove sender read projections."""
    op.drop_index(
        "ix_domain_source_daily_projection_last_seen",
        table_name="domain_source_daily_projections",
    )
    op.drop_index(
        "ix_domain_source_daily_projection_window",
        table_name="domain_source_daily_projections",
    )
    op.drop_table("domain_source_daily_projections")
    op.drop_index(op.f("ix_dmarc_reports_source_projection_at"), table_name="dmarc_reports")
    op.drop_column("dmarc_reports", "source_projection_at")
