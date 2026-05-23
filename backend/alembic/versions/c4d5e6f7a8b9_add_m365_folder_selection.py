"""Add Microsoft 365 folder selection.

Revision ID: c4d5e6f7a8b9
Revises: f3a4b5c6d7e8
Create Date: 2026-05-23 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, Sequence[str], None] = "f3a4b5c6d7e8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("mail_sources", sa.Column("m365_folder_id", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("mail_sources", "m365_folder_id")
