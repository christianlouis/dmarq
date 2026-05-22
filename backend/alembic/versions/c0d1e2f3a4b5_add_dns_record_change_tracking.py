"""add dns record change tracking

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-05-23 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c0d1e2f3a4b5"
down_revision: Union[str, Sequence[str], None] = "b9c0d1e2f3a4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create DNS record snapshot and change history tables."""
    op.create_table(
        "dns_record_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("zone_id", sa.String(), nullable=True),
        sa.Column("record_key", sa.String(length=128), nullable=False),
        sa.Column("record_id", sa.String(), nullable=True),
        sa.Column("record_type", sa.String(length=20), nullable=False),
        sa.Column("record_name", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("proxied", sa.Boolean(), nullable=True),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "domain", "provider", "record_key", name="uq_dns_record_snapshot_lookup"
        ),
    )
    op.create_index(op.f("ix_dns_record_snapshots_id"), "dns_record_snapshots", ["id"])
    op.create_index(op.f("ix_dns_record_snapshots_domain"), "dns_record_snapshots", ["domain"])
    op.create_index(op.f("ix_dns_record_snapshots_provider"), "dns_record_snapshots", ["provider"])
    op.create_index(op.f("ix_dns_record_snapshots_zone_id"), "dns_record_snapshots", ["zone_id"])
    op.create_index(
        op.f("ix_dns_record_snapshots_record_key"),
        "dns_record_snapshots",
        ["record_key"],
    )
    op.create_index(
        op.f("ix_dns_record_snapshots_record_id"),
        "dns_record_snapshots",
        ["record_id"],
    )
    op.create_index(
        op.f("ix_dns_record_snapshots_record_type"),
        "dns_record_snapshots",
        ["record_type"],
    )
    op.create_index(
        op.f("ix_dns_record_snapshots_record_name"),
        "dns_record_snapshots",
        ["record_name"],
    )
    op.create_index(
        op.f("ix_dns_record_snapshots_record_hash"),
        "dns_record_snapshots",
        ["record_hash"],
    )
    op.create_index(op.f("ix_dns_record_snapshots_active"), "dns_record_snapshots", ["active"])
    op.create_index(
        op.f("ix_dns_record_snapshots_first_seen_at"),
        "dns_record_snapshots",
        ["first_seen_at"],
    )
    op.create_index(
        op.f("ix_dns_record_snapshots_last_seen_at"),
        "dns_record_snapshots",
        ["last_seen_at"],
    )
    op.create_index(
        "ix_dns_record_snapshots_domain_active",
        "dns_record_snapshots",
        ["domain", "active"],
    )
    op.create_index(
        "ix_dns_record_snapshots_domain_seen",
        "dns_record_snapshots",
        ["domain", "last_seen_at"],
    )

    op.create_table(
        "dns_record_changes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("zone_id", sa.String(), nullable=True),
        sa.Column("record_key", sa.String(length=128), nullable=False),
        sa.Column("record_id", sa.String(), nullable=True),
        sa.Column("record_type", sa.String(length=20), nullable=False),
        sa.Column("record_name", sa.String(), nullable=False),
        sa.Column("change_type", sa.String(length=20), nullable=False),
        sa.Column("previous_content", sa.Text(), nullable=True),
        sa.Column("current_content", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dns_record_changes_id"), "dns_record_changes", ["id"])
    op.create_index(op.f("ix_dns_record_changes_domain"), "dns_record_changes", ["domain"])
    op.create_index(op.f("ix_dns_record_changes_provider"), "dns_record_changes", ["provider"])
    op.create_index(op.f("ix_dns_record_changes_zone_id"), "dns_record_changes", ["zone_id"])
    op.create_index(op.f("ix_dns_record_changes_record_key"), "dns_record_changes", ["record_key"])
    op.create_index(op.f("ix_dns_record_changes_record_id"), "dns_record_changes", ["record_id"])
    op.create_index(
        op.f("ix_dns_record_changes_record_type"), "dns_record_changes", ["record_type"]
    )
    op.create_index(
        op.f("ix_dns_record_changes_record_name"), "dns_record_changes", ["record_name"]
    )
    op.create_index(
        op.f("ix_dns_record_changes_change_type"), "dns_record_changes", ["change_type"]
    )
    op.create_index(
        op.f("ix_dns_record_changes_observed_at"), "dns_record_changes", ["observed_at"]
    )
    op.create_index(
        "ix_dns_record_changes_domain_observed",
        "dns_record_changes",
        ["domain", "observed_at"],
    )
    op.create_index(
        "ix_dns_record_changes_record_observed",
        "dns_record_changes",
        ["record_key", "observed_at"],
    )


def downgrade() -> None:
    """Drop DNS record snapshot and change history tables."""
    op.drop_index("ix_dns_record_changes_record_observed", table_name="dns_record_changes")
    op.drop_index("ix_dns_record_changes_domain_observed", table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_observed_at"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_change_type"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_record_name"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_record_type"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_record_id"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_record_key"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_zone_id"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_provider"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_domain"), table_name="dns_record_changes")
    op.drop_index(op.f("ix_dns_record_changes_id"), table_name="dns_record_changes")
    op.drop_table("dns_record_changes")

    op.drop_index("ix_dns_record_snapshots_domain_seen", table_name="dns_record_snapshots")
    op.drop_index("ix_dns_record_snapshots_domain_active", table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_last_seen_at"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_first_seen_at"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_active"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_record_hash"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_record_name"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_record_type"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_record_id"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_record_key"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_zone_id"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_provider"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_domain"), table_name="dns_record_snapshots")
    op.drop_index(op.f("ix_dns_record_snapshots_id"), table_name="dns_record_snapshots")
    op.drop_table("dns_record_snapshots")
