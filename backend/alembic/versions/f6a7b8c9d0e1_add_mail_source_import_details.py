"""add mail source import details

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-05-22 20:05:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, Sequence[str], None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add a sanitized details payload to import history rows."""
    op.add_column("mail_source_imports", sa.Column("details", sa.Text(), nullable=True))


def downgrade() -> None:
    """Remove import details payloads."""
    op.drop_column("mail_source_imports", "details")
