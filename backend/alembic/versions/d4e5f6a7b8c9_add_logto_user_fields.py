"""Add Logto fields to users table.

Adds the columns required for Logto OIDC integration and general user-profile
enhancements:

- ``logto_id``      – the Logto subject claim (``sub``); acts as the stable
                      external identity reference.
- ``username``      – optional display username synced from Logto.
- ``picture``       – profile-picture URL synced from Logto.
- ``created_at``    – row-creation timestamp.
- ``updated_at``    – last-update timestamp.

``hashed_password`` is made nullable because Logto-authenticated users
authenticate externally and have no local password.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-03-30 10:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply schema changes."""
    with op.batch_alter_table("users") as batch_op:
        # New columns
        batch_op.add_column(
            sa.Column("logto_id", sa.String(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("username", sa.String(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("picture", sa.String(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=True,
                server_default=sa.func.now(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=True,
                server_default=sa.func.now(),
            )
        )
        # Make hashed_password nullable (Logto users have no local password)
        batch_op.alter_column("hashed_password", nullable=True)
        # Set is_superuser default to True (all users are admins for now)
        batch_op.alter_column("is_superuser", server_default=sa.true())

    # Add unique index on logto_id
    op.create_index(
        op.f("ix_users_logto_id"),
        "users",
        ["logto_id"],
        unique=True,
    )


def downgrade() -> None:
    """Revert schema changes."""
    op.drop_index(op.f("ix_users_logto_id"), table_name="users")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("updated_at")
        batch_op.drop_column("created_at")
        batch_op.drop_column("picture")
        batch_op.drop_column("username")
        batch_op.drop_column("logto_id")
        batch_op.alter_column("hashed_password", nullable=False)
        batch_op.alter_column("is_superuser", server_default=sa.false())
