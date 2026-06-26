"""add api token workspace scope

Revision ID: 6a7b8c9d0e1f
Revises: 5f6a7b8c9d0e
Create Date: 2026-06-26 22:30:00.000000
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "6a7b8c9d0e1f"
down_revision: Union[str, None] = "5f6a7b8c9d0e"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def _default_workspace_id_sql() -> str:
    return "(SELECT id FROM workspaces WHERE slug = 'default')"


def upgrade() -> None:
    """Attach existing persistent API tokens to the default workspace."""
    with op.batch_alter_table("api_tokens") as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_api_tokens_workspace_id_workspaces",
            "workspaces",
            ["workspace_id"],
            ["id"],
        )
        batch_op.create_index(op.f("ix_api_tokens_workspace_id"), ["workspace_id"])
        batch_op.create_index("ix_api_tokens_workspace_active", ["workspace_id", "active"])

    op.execute(f"UPDATE api_tokens SET workspace_id = {_default_workspace_id_sql()}")


def downgrade() -> None:
    """Remove API token workspace ownership."""
    with op.batch_alter_table("api_tokens") as batch_op:
        batch_op.drop_index("ix_api_tokens_workspace_active")
        batch_op.drop_index(op.f("ix_api_tokens_workspace_id"))
        batch_op.drop_constraint("fk_api_tokens_workspace_id_workspaces", type_="foreignkey")
        batch_op.drop_column("workspace_id")
