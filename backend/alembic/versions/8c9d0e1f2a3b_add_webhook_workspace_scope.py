"""add workspace scope to webhook endpoints

Revision ID: 8c9d0e1f2a3b
Revises: 7b8c9d0e1f2a
Create Date: 2026-06-28 00:05:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "8c9d0e1f2a3b"
down_revision: Union[str, Sequence[str], None] = "7b8c9d0e1f2a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _default_workspace_id_sql() -> str:
    return "(SELECT id FROM workspaces WHERE slug = 'default' LIMIT 1)"


def upgrade() -> None:
    """Attach existing webhook endpoints to the default workspace."""
    with op.batch_alter_table("webhook_endpoints") as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_webhook_endpoints_workspace_id_workspaces",
            "workspaces",
            ["workspace_id"],
            ["id"],
        )
        batch_op.create_index(op.f("ix_webhook_endpoints_workspace_id"), ["workspace_id"])
        batch_op.create_index(
            "ix_webhook_endpoints_workspace_enabled",
            ["workspace_id", "enabled"],
        )
    op.execute(f"UPDATE webhook_endpoints SET workspace_id = {_default_workspace_id_sql()}")


def downgrade() -> None:
    """Remove webhook endpoint workspace scoping."""
    with op.batch_alter_table("webhook_endpoints") as batch_op:
        batch_op.drop_index("ix_webhook_endpoints_workspace_enabled")
        batch_op.drop_index(op.f("ix_webhook_endpoints_workspace_id"))
        batch_op.drop_constraint(
            "fk_webhook_endpoints_workspace_id_workspaces",
            type_="foreignkey",
        )
        batch_op.drop_column("workspace_id")
