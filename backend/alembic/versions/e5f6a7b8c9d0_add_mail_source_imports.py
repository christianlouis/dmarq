"""add mail source import history

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-05-22 19:40:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, Sequence[str], None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the mail_source_imports table."""
    op.create_table(
        "mail_source_imports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("mail_source_id", sa.Integer(), nullable=False),
        sa.Column("trigger", sa.String(), nullable=False, server_default="manual"),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reports_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_reports", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new_domains", sa.Text(), nullable=True),
        sa.Column("errors", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["mail_source_id"], ["mail_sources.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_mail_source_imports_id"), "mail_source_imports", ["id"])
    op.create_index(
        op.f("ix_mail_source_imports_mail_source_id"),
        "mail_source_imports",
        ["mail_source_id"],
    )
    op.create_index(
        op.f("ix_mail_source_imports_status"),
        "mail_source_imports",
        ["status"],
    )
    op.create_index(
        op.f("ix_mail_source_imports_started_at"),
        "mail_source_imports",
        ["started_at"],
    )
    op.create_index(
        op.f("ix_mail_source_imports_finished_at"),
        "mail_source_imports",
        ["finished_at"],
    )


def downgrade() -> None:
    """Drop the mail_source_imports table."""
    op.drop_index(op.f("ix_mail_source_imports_finished_at"), table_name="mail_source_imports")
    op.drop_index(op.f("ix_mail_source_imports_started_at"), table_name="mail_source_imports")
    op.drop_index(op.f("ix_mail_source_imports_status"), table_name="mail_source_imports")
    op.drop_index(
        op.f("ix_mail_source_imports_mail_source_id"),
        table_name="mail_source_imports",
    )
    op.drop_index(op.f("ix_mail_source_imports_id"), table_name="mail_source_imports")
    op.drop_table("mail_source_imports")
