"""merge mail auth and backfill migration heads

Revision ID: d9e0f1a2b3c4
Revises: c1d2e3f4a5b6, c8d9e0f1a2b3
Create Date: 2026-07-04 06:35:00.000000

"""

from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = "d9e0f1a2b3c4"
down_revision: Union[str, Sequence[str], None] = (
    "c1d2e3f4a5b6",
    "c8d9e0f1a2b3",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Merge parallel migration branches without changing schema."""


def downgrade() -> None:
    """Unmerge only the Alembic revision marker."""
