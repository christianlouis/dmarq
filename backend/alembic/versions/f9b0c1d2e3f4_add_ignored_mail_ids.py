"""Persist durable, source-scoped local ignore dispositions."""

import sqlalchemy as sa
from alembic import op

revision = "f9b0c1d2e3f4"
down_revision = "f8a9b0c1d2e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mail_source_ignored_messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("mail_source_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("message_id", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["mail_source_id"], ["mail_sources.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "mail_source_id",
            "provider",
            "message_id",
            name="uq_mail_source_ignored_message",
        ),
    )
    op.create_index(
        "ix_mail_source_ignored_message_source_provider",
        "mail_source_ignored_messages",
        ["mail_source_id", "provider"],
    )
    op.create_index(
        op.f("ix_mail_source_ignored_messages_workspace_id"),
        "mail_source_ignored_messages",
        ["workspace_id"],
    )
    op.create_index(
        op.f("ix_mail_source_ignored_messages_mail_source_id"),
        "mail_source_ignored_messages",
        ["mail_source_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_mail_source_ignored_messages_mail_source_id"),
        table_name="mail_source_ignored_messages",
    )
    op.drop_index(
        op.f("ix_mail_source_ignored_messages_workspace_id"),
        table_name="mail_source_ignored_messages",
    )
    op.drop_index(
        "ix_mail_source_ignored_message_source_provider",
        table_name="mail_source_ignored_messages",
    )
    op.drop_table("mail_source_ignored_messages")
