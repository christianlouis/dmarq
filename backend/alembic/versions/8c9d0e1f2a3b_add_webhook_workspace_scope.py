"""add workspace scope to webhook endpoints

Revision ID: 8c9d0e1f2a3b
Revises: 7b8c9d0e1f2a
Create Date: 2026-06-28 00:05:00.000000

"""

import sqlalchemy as sa
from alembic import op

revision = "8c9d0e1f2a3b"
down_revision = "7b8c9d0e1f2a"
branch_labels = None
depends_on = None


def _default_workspace_id_sql() -> str:
    return "(SELECT id FROM workspaces WHERE slug = 'default' LIMIT 1)"


def _ensure_default_workspace() -> None:
    op.execute("""
        INSERT INTO workspaces (slug, name, description, active, created_at, updated_at)
        SELECT
            'default',
            'Default Workspace',
            'Automatically created for existing single-tenant installs.',
            TRUE,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        WHERE NOT EXISTS (SELECT 1 FROM workspaces WHERE slug = 'default')
        """)


def upgrade() -> None:
    """Attach existing webhook endpoints to the default workspace."""
    _ensure_default_workspace()
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
    op.execute(
        f"UPDATE webhook_endpoints SET workspace_id = {_default_workspace_id_sql()} "
        "WHERE workspace_id IS NULL"
    )
    with op.batch_alter_table("webhook_endpoints") as batch_op:
        batch_op.alter_column("workspace_id", existing_type=sa.Integer(), nullable=False)


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
