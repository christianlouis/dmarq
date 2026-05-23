"""add workspace rbac audit foundations

Revision ID: 3d4e5f6a7b8c
Revises: 2c3d4e5f6a7b
Create Date: 2026-05-23 19:20:00.000000
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "3d4e5f6a7b8c"
down_revision = "2c3d4e5f6a7b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create workspace membership and sanitized audit log tables."""
    op.create_table(
        "workspace_memberships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_workspace_memberships_id"), "workspace_memberships", ["id"])
    op.create_index(
        op.f("ix_workspace_memberships_workspace_id"),
        "workspace_memberships",
        ["workspace_id"],
    )
    op.create_index(op.f("ix_workspace_memberships_user_id"), "workspace_memberships", ["user_id"])
    op.create_index(op.f("ix_workspace_memberships_role"), "workspace_memberships", ["role"])
    op.create_index(op.f("ix_workspace_memberships_active"), "workspace_memberships", ["active"])
    op.create_index(
        op.f("ix_workspace_memberships_created_at"),
        "workspace_memberships",
        ["created_at"],
    )
    op.create_index(
        "ix_workspace_memberships_workspace_user",
        "workspace_memberships",
        ["workspace_id", "user_id"],
        unique=True,
    )
    op.create_index(
        "ix_workspace_memberships_workspace_role",
        "workspace_memberships",
        ["workspace_id", "role"],
    )

    op.create_table(
        "workspace_audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("actor_type", sa.String(length=50), nullable=False),
        sa.Column("actor_id", sa.String(length=120), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=80), nullable=False),
        sa.Column("entity_id", sa.String(length=120), nullable=True),
        sa.Column("entity_name", sa.String(length=255), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_workspace_audit_logs_id"), "workspace_audit_logs", ["id"])
    op.create_index(
        op.f("ix_workspace_audit_logs_workspace_id"),
        "workspace_audit_logs",
        ["workspace_id"],
    )
    op.create_index(
        op.f("ix_workspace_audit_logs_actor_type"),
        "workspace_audit_logs",
        ["actor_type"],
    )
    op.create_index(
        op.f("ix_workspace_audit_logs_actor_id"),
        "workspace_audit_logs",
        ["actor_id"],
    )
    op.create_index(op.f("ix_workspace_audit_logs_action"), "workspace_audit_logs", ["action"])
    op.create_index(
        op.f("ix_workspace_audit_logs_entity_type"),
        "workspace_audit_logs",
        ["entity_type"],
    )
    op.create_index(
        op.f("ix_workspace_audit_logs_entity_id"),
        "workspace_audit_logs",
        ["entity_id"],
    )
    op.create_index(
        op.f("ix_workspace_audit_logs_created_at"),
        "workspace_audit_logs",
        ["created_at"],
    )
    op.create_index(
        "ix_workspace_audit_workspace_created",
        "workspace_audit_logs",
        ["workspace_id", "created_at"],
    )
    op.create_index(
        "ix_workspace_audit_workspace_action",
        "workspace_audit_logs",
        ["workspace_id", "action"],
    )
    op.create_index(
        "ix_workspace_audit_entity",
        "workspace_audit_logs",
        ["entity_type", "entity_id"],
    )


def downgrade() -> None:
    """Remove workspace RBAC and audit foundations."""
    op.drop_index("ix_workspace_audit_entity", table_name="workspace_audit_logs")
    op.drop_index("ix_workspace_audit_workspace_action", table_name="workspace_audit_logs")
    op.drop_index("ix_workspace_audit_workspace_created", table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_created_at"), table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_entity_id"), table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_entity_type"), table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_action"), table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_actor_id"), table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_actor_type"), table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_workspace_id"), table_name="workspace_audit_logs")
    op.drop_index(op.f("ix_workspace_audit_logs_id"), table_name="workspace_audit_logs")
    op.drop_table("workspace_audit_logs")

    op.drop_index("ix_workspace_memberships_workspace_role", table_name="workspace_memberships")
    op.drop_index("ix_workspace_memberships_workspace_user", table_name="workspace_memberships")
    op.drop_index(op.f("ix_workspace_memberships_created_at"), table_name="workspace_memberships")
    op.drop_index(op.f("ix_workspace_memberships_active"), table_name="workspace_memberships")
    op.drop_index(op.f("ix_workspace_memberships_role"), table_name="workspace_memberships")
    op.drop_index(op.f("ix_workspace_memberships_user_id"), table_name="workspace_memberships")
    op.drop_index(op.f("ix_workspace_memberships_workspace_id"), table_name="workspace_memberships")
    op.drop_index(op.f("ix_workspace_memberships_id"), table_name="workspace_memberships")
    op.drop_table("workspace_memberships")
