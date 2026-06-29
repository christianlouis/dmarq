"""add mail source backfill jobs

Revision ID: a0b1c2d3e4f5
Revises: 9d0e1f2a3b4c
Create Date: 2026-06-29 03:10:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a0b1c2d3e4f5"
down_revision: Union[str, Sequence[str], None] = "9d0e1f2a3b4c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create persisted mailbox backfill progress rows."""
    op.create_index(
        "ix_mail_sources_id_workspace_id_unique",
        "mail_sources",
        ["id", "workspace_id"],
        unique=True,
    )
    op.create_table(
        "mail_source_backfill_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("mail_source_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="queued"),
        sa.Column("trigger", sa.String(length=40), nullable=False, server_default="manual"),
        sa.Column("requested_start", sa.DateTime(), nullable=True),
        sa.Column("requested_end", sa.DateTime(), nullable=True),
        sa.Column("requested_by", sa.String(length=120), nullable=True),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reports_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_reports", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("cursor", sa.String(length=255), nullable=True),
        sa.Column("errors", sa.Text(), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["mail_source_id", "workspace_id"],
            ["mail_sources.id", "mail_sources.workspace_id"],
            name="fk_mail_source_backfill_source_workspace",
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_mail_source_backfill_jobs_id"), "mail_source_backfill_jobs", ["id"])
    op.create_index(
        op.f("ix_mail_source_backfill_jobs_workspace_id"),
        "mail_source_backfill_jobs",
        ["workspace_id"],
    )
    op.create_index(
        op.f("ix_mail_source_backfill_jobs_mail_source_id"),
        "mail_source_backfill_jobs",
        ["mail_source_id"],
    )
    op.create_index(
        op.f("ix_mail_source_backfill_jobs_status"),
        "mail_source_backfill_jobs",
        ["status"],
    )
    op.create_index(
        op.f("ix_mail_source_backfill_jobs_created_at"),
        "mail_source_backfill_jobs",
        ["created_at"],
    )
    op.create_index(
        "ix_mail_source_backfill_workspace_status",
        "mail_source_backfill_jobs",
        ["workspace_id", "status"],
    )
    op.create_index(
        "ix_mail_source_backfill_source_status",
        "mail_source_backfill_jobs",
        ["mail_source_id", "status"],
    )
    op.create_index(
        "ix_mail_source_backfill_retry",
        "mail_source_backfill_jobs",
        ["status", "next_retry_at"],
    )


def downgrade() -> None:
    """Drop mailbox backfill progress rows."""
    op.drop_index("ix_mail_source_backfill_retry", table_name="mail_source_backfill_jobs")
    op.drop_index("ix_mail_source_backfill_source_status", table_name="mail_source_backfill_jobs")
    op.drop_index(
        "ix_mail_source_backfill_workspace_status",
        table_name="mail_source_backfill_jobs",
    )
    op.drop_index(
        op.f("ix_mail_source_backfill_jobs_created_at"), table_name="mail_source_backfill_jobs"
    )
    op.drop_index(
        op.f("ix_mail_source_backfill_jobs_status"), table_name="mail_source_backfill_jobs"
    )
    op.drop_index(
        op.f("ix_mail_source_backfill_jobs_mail_source_id"),
        table_name="mail_source_backfill_jobs",
    )
    op.drop_index(
        op.f("ix_mail_source_backfill_jobs_workspace_id"),
        table_name="mail_source_backfill_jobs",
    )
    op.drop_index(op.f("ix_mail_source_backfill_jobs_id"), table_name="mail_source_backfill_jobs")
    op.drop_table("mail_source_backfill_jobs")
    op.drop_index("ix_mail_sources_id_workspace_id_unique", table_name="mail_sources")
