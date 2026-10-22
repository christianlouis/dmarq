"""add mail source imap uid cursor

Revision ID: 4b5c6d7e8f9a
Revises: 3f4a5b6c7d8e
Create Date: 2026-09-20 10:15:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "4b5c6d7e8f9a"
# Follow the current migration head.  The original contribution was based on
# an older branch point and would otherwise introduce a second Alembic head.
down_revision = "f9b0c1d2e3f4"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("mail_sources") as batch_op:
        batch_op.add_column(sa.Column("last_uid", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("uid_validity", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("uid_account", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("uid_folder", sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table("mail_sources") as batch_op:
        batch_op.drop_column("uid_validity")
        batch_op.drop_column("last_uid")
        batch_op.drop_column("uid_account")
        batch_op.drop_column("uid_folder")
