"""Persist whether an external identity supplied authoritative roles."""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "fc2d3e4f5a6b"
down_revision: Union[str, Sequence[str], None] = "3f4a5b6c7d8e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "external_roles_authoritative",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    for table in ("workspace_memberships", "organization_memberships"):
        op.add_column(
            table,
            sa.Column(
                "external_role_managed",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )
        op.create_index(
            f"ix_{table}_external_role_managed",
            table,
            ["external_role_managed"],
        )
    connection = op.get_bind()
    # Legacy OIDC/Authentik rows came from additive sync and have ambiguous
    # provenance. Deactivate them once; Logto/SCIM and manual grants remain.
    for table in ("workspace_memberships", "organization_memberships"):
        connection.execute(
            sa.text(
                f"""
                UPDATE {table}
                SET active = FALSE, external_role_managed = TRUE
                WHERE user_id IN (
                    SELECT id FROM users
                    WHERE logto_id LIKE 'oidc:%' OR logto_id LIKE 'authentik:%'
                )
                """
            )
        )


def downgrade() -> None:
    op.drop_index(
        "ix_organization_memberships_external_role_managed",
        table_name="organization_memberships",
    )
    op.drop_index(
        "ix_workspace_memberships_external_role_managed",
        table_name="workspace_memberships",
    )
    op.drop_column("organization_memberships", "external_role_managed")
    op.drop_column("workspace_memberships", "external_role_managed")
    op.drop_column("users", "external_roles_authoritative")
