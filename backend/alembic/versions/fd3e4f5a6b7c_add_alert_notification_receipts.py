"""Remember successful alert deliveries for each active occurrence."""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "fd3e4f5a6b7c"
down_revision: Union[str, Sequence[str], None] = "4b5c6d7e8f9a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("alert_history", sa.Column("last_notified_at", sa.DateTime(), nullable=True))
    op.add_column("alert_history", sa.Column("notified_severity", sa.String(), nullable=True))
    op.add_column("alert_history", sa.Column("occurrence_id", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("alert_history", "occurrence_id")
    op.drop_column("alert_history", "notified_severity")
    op.drop_column("alert_history", "last_notified_at")
