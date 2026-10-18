"""Add stable, source-bound metadata for per-message import recovery."""

import sqlalchemy as sa
from alembic import op

revision = "f8a9b0c1d2e3"
down_revision = "fc2d3e4f5a6b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("mail_source_imports", sa.Column("recovery_metadata", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("mail_source_imports", "recovery_metadata")
