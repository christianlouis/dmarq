"""add Gmail API fields to mail_sources

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-29 19:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add Gmail OAuth2 credential columns to mail_sources."""
    op.add_column("mail_sources", sa.Column("gmail_client_id", sa.String(), nullable=True))
    op.add_column("mail_sources", sa.Column("gmail_client_secret", sa.Text(), nullable=True))
    op.add_column("mail_sources", sa.Column("gmail_access_token", sa.Text(), nullable=True))
    op.add_column("mail_sources", sa.Column("gmail_refresh_token", sa.Text(), nullable=True))
    op.add_column("mail_sources", sa.Column("gmail_email", sa.String(), nullable=True))
    op.add_column(
        "mail_sources",
        sa.Column("gmail_ingested_ids", sa.Text(), nullable=True, server_default="[]"),
    )


def downgrade() -> None:
    """Remove Gmail OAuth2 credential columns from mail_sources."""
    op.drop_column("mail_sources", "gmail_ingested_ids")
    op.drop_column("mail_sources", "gmail_email")
    op.drop_column("mail_sources", "gmail_refresh_token")
    op.drop_column("mail_sources", "gmail_access_token")
    op.drop_column("mail_sources", "gmail_client_secret")
    op.drop_column("mail_sources", "gmail_client_id")
