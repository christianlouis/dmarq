"""Add point-in-time sender evidence to DMARC report records.

Revision ID: a5b6c7d8e9f0
Revises: f4a5b6c7d8e9
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a5b6c7d8e9f0"
down_revision: Union[str, Sequence[str], None] = "f4a5b6c7d8e9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("report_records", sa.Column("source_evidence", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("report_records", "source_evidence")
