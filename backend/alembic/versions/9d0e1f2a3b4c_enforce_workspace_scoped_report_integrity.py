"""enforce workspace-scoped report integrity

Revision ID: 9d0e1f2a3b4c
Revises: 8c9d0e1f2a3b
Create Date: 2026-06-28 00:40:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "9d0e1f2a3b4c"
down_revision = "8c9d0e1f2a3b"
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
    """Prevent tenant-scoped rows from retaining NULL workspace/domain owners."""
    _ensure_default_workspace()
    op.execute(
        f"UPDATE webhook_endpoints SET workspace_id = {_default_workspace_id_sql()} "
        "WHERE workspace_id IS NULL"
    )

    with op.batch_alter_table("webhook_endpoints") as batch_op:
        batch_op.alter_column("workspace_id", existing_type=sa.Integer(), nullable=False)
    with op.batch_alter_table("forensic_reports") as batch_op:
        batch_op.alter_column("domain_id", existing_type=sa.Integer(), nullable=False)
    with op.batch_alter_table("tls_reports") as batch_op:
        batch_op.alter_column("domain_id", existing_type=sa.Integer(), nullable=False)


def downgrade() -> None:
    """Allow legacy NULL owners again."""
    with op.batch_alter_table("tls_reports") as batch_op:
        batch_op.alter_column("domain_id", existing_type=sa.Integer(), nullable=True)
    with op.batch_alter_table("forensic_reports") as batch_op:
        batch_op.alter_column("domain_id", existing_type=sa.Integer(), nullable=True)
    with op.batch_alter_table("webhook_endpoints") as batch_op:
        batch_op.alter_column("workspace_id", existing_type=sa.Integer(), nullable=True)
