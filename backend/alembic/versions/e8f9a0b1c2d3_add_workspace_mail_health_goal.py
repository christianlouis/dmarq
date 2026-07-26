"""add workspace mail health goal

Revision ID: e8f9a0b1c2d3
Revises: e7f8a9b0c1d2
Create Date: 2026-07-26 15:10:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "e8f9a0b1c2d3"
down_revision: Union[str, Sequence[str], None] = "e7f8a9b0c1d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Persist optional problem-first onboarding answers per workspace."""
    op.add_column("workspaces", sa.Column("mail_health_goal", sa.String(length=48), nullable=True))
    op.add_column("workspaces", sa.Column("guidance_interview_completed_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Remove optional problem-first onboarding answers."""
    op.drop_column("workspaces", "guidance_interview_completed_at")
    op.drop_column("workspaces", "mail_health_goal")
