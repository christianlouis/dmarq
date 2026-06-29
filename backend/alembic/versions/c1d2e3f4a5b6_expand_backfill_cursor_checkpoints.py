"""expand backfill cursor checkpoints

Revision ID: c1d2e3f4a5b6
Revises: b1c2d3e4f5a6
Create Date: 2026-06-29 19:45:00.000000

"""

import sqlalchemy as sa
from alembic import op

revision = "c1d2e3f4a5b6"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Allow provider cursor checkpoints to store opaque page tokens safely."""
    with op.batch_alter_table("mail_source_backfill_jobs") as batch_op:
        batch_op.alter_column(
            "cursor",
            existing_type=sa.String(length=255),
            type_=sa.Text(),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Restore the original short cursor column."""
    with op.batch_alter_table("mail_source_backfill_jobs") as batch_op:
        batch_op.alter_column(
            "cursor",
            existing_type=sa.Text(),
            type_=sa.String(length=255),
            existing_nullable=True,
        )
