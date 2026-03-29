"""add mail_sources table

Revision ID: a1b2c3d4e5f6
Revises: 88b549786e2d
Create Date: 2026-03-29 17:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "88b549786e2d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the mail_sources table."""
    op.create_table(
        "mail_sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("server", sa.String(), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("password", sa.Text(), nullable=True),
        sa.Column("use_ssl", sa.Boolean(), nullable=True),
        sa.Column("folder", sa.String(), nullable=True),
        sa.Column("polling_interval", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("last_checked", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_mail_sources_id"), "mail_sources", ["id"], unique=False)
    op.create_index(
        op.f("ix_mail_sources_enabled"), "mail_sources", ["enabled"], unique=False
    )


def downgrade() -> None:
    """Drop the mail_sources table."""
    op.drop_index(op.f("ix_mail_sources_enabled"), table_name="mail_sources")
    op.drop_index(op.f("ix_mail_sources_id"), table_name="mail_sources")
    op.drop_table("mail_sources")
