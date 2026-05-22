"""add alert configuration audit

Revision ID: b9c0d1e2f3a4
Revises: b8c9d0e1f2a3
Create Date: 2026-05-23 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b9c0d1e2f3a4"
down_revision: Union[str, Sequence[str], None] = "b8c9d0e1f2a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create alert configuration audit trail rows."""
    op.create_table(
        "alert_configuration_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("changed_by", sa.String(length=100), nullable=True),
        sa.Column("auth_type", sa.String(length=50), nullable=True),
        sa.Column("changed_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_alert_configuration_audit_id"),
        "alert_configuration_audit",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_configuration_audit_key"),
        "alert_configuration_audit",
        ["key"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_configuration_audit_changed_by"),
        "alert_configuration_audit",
        ["changed_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_configuration_audit_changed_at"),
        "alert_configuration_audit",
        ["changed_at"],
        unique=False,
    )
    op.create_index(
        "ix_alert_configuration_audit_key_changed_at",
        "alert_configuration_audit",
        ["key", "changed_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop alert configuration audit trail rows."""
    op.drop_index(
        "ix_alert_configuration_audit_key_changed_at",
        table_name="alert_configuration_audit",
    )
    op.drop_index(
        op.f("ix_alert_configuration_audit_changed_at"),
        table_name="alert_configuration_audit",
    )
    op.drop_index(
        op.f("ix_alert_configuration_audit_changed_by"),
        table_name="alert_configuration_audit",
    )
    op.drop_index(op.f("ix_alert_configuration_audit_key"), table_name="alert_configuration_audit")
    op.drop_index(op.f("ix_alert_configuration_audit_id"), table_name="alert_configuration_audit")
    op.drop_table("alert_configuration_audit")
