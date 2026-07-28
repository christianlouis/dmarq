"""Persist immutable DNS posture snapshots and current pointers.

Revision ID: 0c1d2e3f4a5b
Revises: fb1c2d3e4f5a
Create Date: 2026-07-28 11:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "0c1d2e3f4a5b"
down_revision = "fb1c2d3e4f5a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "domain_dns_posture_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=True),
        sa.Column("trigger", sa.String(length=32), nullable=False, server_default="scheduled"),
        sa.Column("selector_hash", sa.String(length=64), nullable=False),
        sa.Column("result_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("provenance_json", sa.Text(), nullable=True),
        sa.Column("delta_json", sa.Text(), nullable=True),
        sa.Column("lookup_status", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("accepted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("captured_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dns_posture_snapshot_domain_captured", "domain_dns_posture_snapshots", ["domain_id", "captured_at"])
    op.create_index("ix_dns_posture_snapshot_workspace_domain", "domain_dns_posture_snapshots", ["workspace_id", "domain_id"])
    op.create_index("ix_domain_dns_posture_snapshots_selector_hash", "domain_dns_posture_snapshots", ["selector_hash"])
    op.create_index("ix_domain_dns_posture_snapshots_result_fingerprint", "domain_dns_posture_snapshots", ["result_fingerprint"])
    op.create_index("ix_domain_dns_posture_snapshots_accepted", "domain_dns_posture_snapshots", ["accepted"])
    op.create_index("ix_domain_dns_posture_snapshots_captured_at", "domain_dns_posture_snapshots", ["captured_at"])
    op.create_table(
        "domain_dns_posture_current",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=True),
        sa.Column("accepted_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("latest_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("requested_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("next_trigger", sa.String(length=32), nullable=True),
        sa.Column("selector_hash", sa.String(length=64), nullable=True),
        sa.Column("absence_observations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["accepted_snapshot_id"], ["domain_dns_posture_snapshots.id"]),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.ForeignKeyConstraint(["latest_snapshot_id"], ["domain_dns_posture_snapshots.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id", name="uq_domain_dns_posture_current_domain"),
    )
    op.create_index("ix_dns_posture_current_requested", "domain_dns_posture_current", ["requested_at", "domain_id"])
    op.create_index("ix_domain_dns_posture_current_workspace_id", "domain_dns_posture_current", ["workspace_id"])
    op.create_index("ix_domain_dns_posture_current_accepted_snapshot_id", "domain_dns_posture_current", ["accepted_snapshot_id"])
    op.create_index("ix_domain_dns_posture_current_latest_snapshot_id", "domain_dns_posture_current", ["latest_snapshot_id"])
    op.create_index("ix_domain_dns_posture_current_completed_at", "domain_dns_posture_current", ["completed_at"])


def downgrade():
    op.drop_table("domain_dns_posture_current")
    op.drop_table("domain_dns_posture_snapshots")
