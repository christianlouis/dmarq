"""add workspace operator controls

Revision ID: 4e5f6a7b8c9d
Revises: 3d4e5f6a7b8c
Create Date: 2026-05-23 20:05:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "4e5f6a7b8c9d"
down_revision: Union[str, None] = "3d4e5f6a7b8c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "workspaces",
        sa.Column("report_retention_days", sa.Integer(), nullable=False, server_default="400"),
    )
    op.add_column(
        "workspaces",
        sa.Column("forensic_retention_days", sa.Integer(), nullable=False, server_default="90"),
    )
    op.add_column(
        "workspaces",
        sa.Column("tls_report_retention_days", sa.Integer(), nullable=False, server_default="400"),
    )


def downgrade() -> None:
    op.drop_column("workspaces", "tls_report_retention_days")
    op.drop_column("workspaces", "forensic_retention_days")
    op.drop_column("workspaces", "report_retention_days")
