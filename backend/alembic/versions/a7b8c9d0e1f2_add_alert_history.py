"""add alert history

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-05-22 23:12:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, Sequence[str], None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create persisted alert history rows."""
    op.create_table(
        "alert_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("rule", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("observed_count", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint"),
    )
    op.create_index(op.f("ix_alert_history_id"), "alert_history", ["id"], unique=False)
    op.create_index(
        op.f("ix_alert_history_fingerprint"),
        "alert_history",
        ["fingerprint"],
        unique=False,
    )
    op.create_index(op.f("ix_alert_history_rule"), "alert_history", ["rule"], unique=False)
    op.create_index(
        op.f("ix_alert_history_severity"),
        "alert_history",
        ["severity"],
        unique=False,
    )
    op.create_index(op.f("ix_alert_history_domain"), "alert_history", ["domain"], unique=False)
    op.create_index(
        op.f("ix_alert_history_is_active"),
        "alert_history",
        ["is_active"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_history_first_seen_at"),
        "alert_history",
        ["first_seen_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_history_last_seen_at"),
        "alert_history",
        ["last_seen_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_history_resolved_at"),
        "alert_history",
        ["resolved_at"],
        unique=False,
    )
    op.create_index(
        "ix_alert_history_active_last_seen",
        "alert_history",
        ["is_active", "last_seen_at"],
        unique=False,
    )
    op.create_index(
        "ix_alert_history_rule_domain",
        "alert_history",
        ["rule", "domain"],
        unique=False,
    )


def downgrade() -> None:
    """Drop persisted alert history rows."""
    op.drop_index("ix_alert_history_rule_domain", table_name="alert_history")
    op.drop_index("ix_alert_history_active_last_seen", table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_resolved_at"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_last_seen_at"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_first_seen_at"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_is_active"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_domain"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_severity"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_rule"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_fingerprint"), table_name="alert_history")
    op.drop_index(op.f("ix_alert_history_id"), table_name="alert_history")
    op.drop_table("alert_history")
