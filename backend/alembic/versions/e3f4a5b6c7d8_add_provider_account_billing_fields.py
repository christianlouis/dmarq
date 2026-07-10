"""Add provider account billing contact and price override fields.

Revision ID: e3f4a5b6c7d8
Revises: d9e0f1a2b3c4
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e3f4a5b6c7d8"
down_revision: Union[str, Sequence[str], None] = "d9e0f1a2b3c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "billing_accounts",
        sa.Column("billing_contact_email", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "subscriptions",
        sa.Column("monthly_price_cents", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("subscriptions", "monthly_price_cents")
    op.drop_column("billing_accounts", "billing_contact_email")
