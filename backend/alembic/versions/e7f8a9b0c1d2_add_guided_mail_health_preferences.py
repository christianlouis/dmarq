"""add workspace guided mail health preferences

Revision ID: e7f8a9b0c1d2
Revises: c7d8e9f0a1b2
Create Date: 2026-07-26 14:30:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "e7f8a9b0c1d2"
down_revision: Union[str, Sequence[str], None] = "c7d8e9f0a1b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add opt-in preferences without changing existing workspace behaviour."""
    op.add_column(
        "workspaces",
        sa.Column("guided_mail_health_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "workspaces",
        sa.Column("guidance_depth", sa.String(length=24), nullable=False, server_default="standard"),
    )
    op.add_column(
        "workspaces",
        sa.Column("guidance_context", sa.String(length=24), nullable=False, server_default="watch"),
    )


def downgrade() -> None:
    """Remove the guided experience preferences."""
    op.drop_column("workspaces", "guidance_context")
    op.drop_column("workspaces", "guidance_depth")
    op.drop_column("workspaces", "guided_mail_health_enabled")
