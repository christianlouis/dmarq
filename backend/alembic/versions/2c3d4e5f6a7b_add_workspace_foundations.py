"""add workspace foundations

Revision ID: 2c3d4e5f6a7b
Revises: 1b2c3d4e5f6a
Create Date: 2026-05-23 18:58:00.000000
"""

from datetime import datetime

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "2c3d4e5f6a7b"
down_revision = "1b2c3d4e5f6a"
branch_labels = None
depends_on = None


def _default_workspace_id_sql() -> str:
    return "(SELECT id FROM workspaces WHERE slug = 'default')"


def upgrade() -> None:
    """Create workspaces and attach existing single-tenant rows to default."""
    op.create_table(
        "workspaces",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_workspaces_id"), "workspaces", ["id"])
    op.create_index(op.f("ix_workspaces_slug"), "workspaces", ["slug"])
    op.create_index(op.f("ix_workspaces_active"), "workspaces", ["active"])
    op.create_index(op.f("ix_workspaces_created_at"), "workspaces", ["created_at"])
    op.create_index("ix_workspaces_active_slug", "workspaces", ["active", "slug"])

    now = datetime.utcnow()
    workspaces = sa.table(
        "workspaces",
        sa.column("slug", sa.String()),
        sa.column("name", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("active", sa.Boolean()),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    op.bulk_insert(
        workspaces,
        [
            {
                "slug": "default",
                "name": "Default Workspace",
                "description": "Automatically created for existing single-tenant installs.",
                "active": True,
                "created_at": now,
                "updated_at": now,
            }
        ],
    )

    with op.batch_alter_table("domains") as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_domains_workspace_id_workspaces",
            "workspaces",
            ["workspace_id"],
            ["id"],
        )
        batch_op.create_index(op.f("ix_domains_workspace_id"), ["workspace_id"])
        batch_op.create_index("ix_domains_workspace_name", ["workspace_id", "name"])

    with op.batch_alter_table("mail_sources") as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_mail_sources_workspace_id_workspaces",
            "workspaces",
            ["workspace_id"],
            ["id"],
        )
        batch_op.create_index(op.f("ix_mail_sources_workspace_id"), ["workspace_id"])
        batch_op.create_index("ix_mail_sources_workspace_enabled", ["workspace_id", "enabled"])

    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_users_workspace_id_workspaces",
            "workspaces",
            ["workspace_id"],
            ["id"],
        )
        batch_op.create_index(op.f("ix_users_workspace_id"), ["workspace_id"])

    op.execute(f"UPDATE domains SET workspace_id = {_default_workspace_id_sql()}")
    op.execute(f"UPDATE mail_sources SET workspace_id = {_default_workspace_id_sql()}")
    op.execute(f"UPDATE users SET workspace_id = {_default_workspace_id_sql()}")


def downgrade() -> None:
    """Remove workspace ownership columns and table."""
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index(op.f("ix_users_workspace_id"))
        batch_op.drop_constraint("fk_users_workspace_id_workspaces", type_="foreignkey")
        batch_op.drop_column("workspace_id")

    with op.batch_alter_table("mail_sources") as batch_op:
        batch_op.drop_index("ix_mail_sources_workspace_enabled")
        batch_op.drop_index(op.f("ix_mail_sources_workspace_id"))
        batch_op.drop_constraint("fk_mail_sources_workspace_id_workspaces", type_="foreignkey")
        batch_op.drop_column("workspace_id")

    with op.batch_alter_table("domains") as batch_op:
        batch_op.drop_index("ix_domains_workspace_name")
        batch_op.drop_index(op.f("ix_domains_workspace_id"))
        batch_op.drop_constraint("fk_domains_workspace_id_workspaces", type_="foreignkey")
        batch_op.drop_column("workspace_id")

    op.drop_index("ix_workspaces_active_slug", table_name="workspaces")
    op.drop_index(op.f("ix_workspaces_created_at"), table_name="workspaces")
    op.drop_index(op.f("ix_workspaces_active"), table_name="workspaces")
    op.drop_index(op.f("ix_workspaces_slug"), table_name="workspaces")
    op.drop_index(op.f("ix_workspaces_id"), table_name="workspaces")
    op.drop_table("workspaces")
