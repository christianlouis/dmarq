"""Add Microsoft 365 application authentication mode.

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f4a5b6c7d8e9"
down_revision: Union[str, Sequence[str], None] = "e3f4a5b6c7d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "mail_sources",
        sa.Column(
            "m365_auth_mode",
            sa.String(),
            nullable=False,
            server_default="delegated",
        ),
    )


def downgrade() -> None:
    op.drop_column("mail_sources", "m365_auth_mode")
