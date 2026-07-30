"""Expand persisted user and workspace guidance profiles.

Revision ID: 1d2e3f4a5b6c
Revises: 0c1d2e3f4a5b
Create Date: 2026-07-30 01:20:00
"""

import sqlalchemy as sa
from alembic import op

revision = "1d2e3f4a5b6c"
down_revision = "0c1d2e3f4a5b"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column("guidance_teaching_hints_enabled", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("guidance_profile_version", sa.Integer(), nullable=True),
    )
    op.add_column(
        "workspaces",
        sa.Column("guidance_teaching_hints_enabled", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "workspaces",
        sa.Column("guidance_installation_goals", sa.Text(), nullable=True),
    )
    op.add_column(
        "workspaces",
        sa.Column("sovereignty_preference", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "workspaces",
        sa.Column("guidance_mail_context", sa.Text(), nullable=True),
    )
    op.add_column(
        "workspaces",
        sa.Column(
            "guidance_profile_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "workspaces",
        sa.Column(
            "guidance_interview_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )


def downgrade():
    op.drop_column("workspaces", "guidance_interview_version")
    op.drop_column("workspaces", "guidance_profile_version")
    op.drop_column("workspaces", "guidance_mail_context")
    op.drop_column("workspaces", "sovereignty_preference")
    op.drop_column("workspaces", "guidance_installation_goals")
    op.drop_column("workspaces", "guidance_teaching_hints_enabled")
    op.drop_column("users", "guidance_profile_version")
    op.drop_column("users", "guidance_teaching_hints_enabled")
