"""Persist local per-message ignore dispositions outside ingested ID windows."""

import sqlalchemy as sa
from alembic import op

revision = "f9b0c1d2e3f4"
down_revision = "f8a9b0c1d2e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("mail_sources", sa.Column("gmail_ignored_ids", sa.Text(), nullable=True))
    op.add_column("mail_sources", sa.Column("m365_ignored_ids", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("mail_sources", "m365_ignored_ids")
    op.drop_column("mail_sources", "gmail_ignored_ids")
