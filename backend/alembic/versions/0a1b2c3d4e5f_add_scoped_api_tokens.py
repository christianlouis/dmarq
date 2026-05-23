"""add scoped api tokens

Revision ID: 0a1b2c3d4e5f
Revises: f7a8b9c0d1e2
Create Date: 2026-05-23 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0a1b2c3d4e5f"
down_revision: Union[str, Sequence[str], None] = "f7a8b9c0d1e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create scoped API token storage."""
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_ip", sa.String(length=64), nullable=True),
        sa.Column("usage_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_index(op.f("ix_api_tokens_id"), "api_tokens", ["id"])
    op.create_index(op.f("ix_api_tokens_key_hash"), "api_tokens", ["key_hash"])
    op.create_index(op.f("ix_api_tokens_key_prefix"), "api_tokens", ["key_prefix"])
    op.create_index(op.f("ix_api_tokens_active"), "api_tokens", ["active"])
    op.create_index(op.f("ix_api_tokens_created_at"), "api_tokens", ["created_at"])
    op.create_index(op.f("ix_api_tokens_revoked_at"), "api_tokens", ["revoked_at"])
    op.create_index(op.f("ix_api_tokens_last_used_at"), "api_tokens", ["last_used_at"])
    op.create_index("ix_api_tokens_active_scope", "api_tokens", ["active", "scopes"])
    op.create_index("ix_api_tokens_last_used", "api_tokens", ["last_used_at"])


def downgrade() -> None:
    """Drop scoped API token storage."""
    op.drop_index("ix_api_tokens_last_used", table_name="api_tokens")
    op.drop_index("ix_api_tokens_active_scope", table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_last_used_at"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_revoked_at"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_created_at"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_active"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_key_prefix"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_key_hash"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_id"), table_name="api_tokens")
    op.drop_table("api_tokens")
