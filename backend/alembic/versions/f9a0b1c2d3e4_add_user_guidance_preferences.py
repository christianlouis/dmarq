"""Add per-user guided mail health presentation preferences.

Revision ID: f9a0b1c2d3e4
Revises: e8f9a0b1c2d3
Create Date: 2026-07-26 14:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "f9a0b1c2d3e4"
down_revision = "e8f9a0b1c2d3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("guidance_depth", sa.String(length=24), nullable=True))
    op.add_column("users", sa.Column("guidance_context", sa.String(length=24), nullable=True))


def downgrade():
    op.drop_column("users", "guidance_context")
    op.drop_column("users", "guidance_depth")
