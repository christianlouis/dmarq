"""Store the complete score factors used by persisted health snapshots.

Revision ID: fb1c2d3e4f5a
Revises: fa1b2c3d4e5f
Create Date: 2026-07-28 10:15:00
"""

from alembic import op
import sqlalchemy as sa


revision = "fb1c2d3e4f5a"
down_revision = "fa1b2c3d4e5f"
branch_labels = None
depends_on = None


def upgrade():
    """Add the missing factor and compact evidence provenance."""
    op.add_column(
        "health_score_snapshots",
        sa.Column("source_reputation_score", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "health_score_snapshots",
        sa.Column("evidence_summary", sa.Text(), nullable=True),
    )


def downgrade():
    """Remove snapshot provenance fields."""
    op.drop_column("health_score_snapshots", "evidence_summary")
    op.drop_column("health_score_snapshots", "source_reputation_score")
