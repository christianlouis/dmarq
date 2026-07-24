"""Index report windows by domain and end date.

Revision ID: b6c7d8e9f0a
Revises: a5b6c7d8e9f0
Create Date: 2026-07-24 16:45:00.000000
"""

from typing import Sequence, Union

from alembic import op


revision: str = "b6c7d8e9f0a"
down_revision: Union[str, Sequence[str], None] = "a5b6c7d8e9f0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Support bounded domain-report reads without scanning report history."""
    op.create_index(
        "ix_dmarc_reports_domain_end_date",
        "dmarc_reports",
        ["domain_id", "end_date"],
    )


def downgrade() -> None:
    """Remove the bounded domain-report read index."""
    op.drop_index("ix_dmarc_reports_domain_end_date", table_name="dmarc_reports")
