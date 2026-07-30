"""Add expiring DNS zone baseline evidence.

Revision ID: 2e3f4a5b6c7d
Revises: 1d2e3f4a5b6c
"""

import sqlalchemy as sa
from alembic import op

revision = "2e3f4a5b6c7d"
down_revision = "1d2e3f4a5b6c"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dns_zone_baselines",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_hash", sa.String(length=64), nullable=False),
        sa.Column("records_json", sa.Text(), nullable=False),
        sa.Column("comparison_json", sa.Text(), nullable=True),
        sa.Column("imported_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("removed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "id",
        "workspace_id",
        "domain",
        "source_hash",
        "imported_at",
        "expires_at",
        "removed_at",
    ):
        op.create_index(f"ix_dns_zone_baselines_{column}", "dns_zone_baselines", [column])
    op.create_index(
        "ix_dns_zone_baseline_workspace_domain", "dns_zone_baselines", ["workspace_id", "domain"]
    )


def downgrade():
    op.drop_table("dns_zone_baselines")
