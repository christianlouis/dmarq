"""Add Microsoft 365 Graph mail source fields.

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-05-23 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3a4b5c6d7e8"
down_revision: Union[str, Sequence[str], None] = "e2f3a4b5c6d7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("mail_sources", sa.Column("m365_tenant_id", sa.String(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_client_id", sa.String(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_client_secret", sa.Text(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_access_token", sa.Text(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_refresh_token", sa.Text(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_mailbox", sa.String(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_email", sa.String(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_ingested_ids", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("mail_sources", "m365_ingested_ids")
    op.drop_column("mail_sources", "m365_email")
    op.drop_column("mail_sources", "m365_mailbox")
    op.drop_column("mail_sources", "m365_refresh_token")
    op.drop_column("mail_sources", "m365_access_token")
    op.drop_column("mail_sources", "m365_client_secret")
    op.drop_column("mail_sources", "m365_client_id")
    op.drop_column("mail_sources", "m365_tenant_id")
