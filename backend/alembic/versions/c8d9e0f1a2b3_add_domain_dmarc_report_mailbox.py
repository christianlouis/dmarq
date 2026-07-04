"""add domain dmarc report mailbox

Revision ID: c8d9e0f1a2b3
Revises: b1c2d3e4f5a6, 6a7b8c9d0e1f, 1b2c3d4e5f6a
Create Date: 2026-07-04 05:25:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8d9e0f1a2b3"
down_revision: Union[str, Sequence[str], None] = (
    "b1c2d3e4f5a6",
    "6a7b8c9d0e1f",
    "1b2c3d4e5f6a",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Store optional domain-specific DMARC aggregate-report mailbox overrides."""
    op.add_column("domains", sa.Column("dmarc_report_mailbox", sa.String(), nullable=True))


def downgrade() -> None:
    """Remove domain-specific DMARC aggregate-report mailbox overrides."""
    op.drop_column("domains", "dmarc_report_mailbox")
