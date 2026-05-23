"""add forensic reports

Revision ID: d1e2f3a4b5c6
Revises: c0d1e2f3a4b5
Create Date: 2026-05-23 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d1e2f3a4b5c6"
down_revision: Union[str, Sequence[str], None] = "c0d1e2f3a4b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create DMARC forensic/failure report storage."""
    op.create_table(
        "forensic_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=True),
        sa.Column("report_id", sa.String(), nullable=False),
        sa.Column("source_email", sa.String(), nullable=True),
        sa.Column("feedback_type", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("reported_domain", sa.String(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("auth_failure", sa.String(), nullable=True),
        sa.Column("delivery_result", sa.String(), nullable=True),
        sa.Column("arrival_date", sa.DateTime(), nullable=True),
        sa.Column("authentication_results", sa.Text(), nullable=True),
        sa.Column("original_mail_from", sa.String(), nullable=True),
        sa.Column("original_from", sa.String(), nullable=True),
        sa.Column("original_to", sa.String(), nullable=True),
        sa.Column("original_subject", sa.String(), nullable=True),
        sa.Column("original_message_id", sa.String(), nullable=True),
        sa.Column("original_date", sa.String(), nullable=True),
        sa.Column("feedback_headers", sa.Text(), nullable=True),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id", name="uq_forensic_reports_report_id"),
    )
    op.create_index(op.f("ix_forensic_reports_id"), "forensic_reports", ["id"])
    op.create_index(op.f("ix_forensic_reports_domain_id"), "forensic_reports", ["domain_id"])
    op.create_index(op.f("ix_forensic_reports_report_id"), "forensic_reports", ["report_id"])
    op.create_index(
        op.f("ix_forensic_reports_feedback_type"), "forensic_reports", ["feedback_type"]
    )
    op.create_index(
        op.f("ix_forensic_reports_reported_domain"), "forensic_reports", ["reported_domain"]
    )
    op.create_index(op.f("ix_forensic_reports_source_ip"), "forensic_reports", ["source_ip"])
    op.create_index(op.f("ix_forensic_reports_auth_failure"), "forensic_reports", ["auth_failure"])
    op.create_index(op.f("ix_forensic_reports_arrival_date"), "forensic_reports", ["arrival_date"])
    op.create_index(op.f("ix_forensic_reports_processed_at"), "forensic_reports", ["processed_at"])
    op.create_index(
        "ix_forensic_reports_domain_arrival",
        "forensic_reports",
        ["domain_id", "arrival_date"],
    )
    op.create_index(
        "ix_forensic_reports_failure_source",
        "forensic_reports",
        ["auth_failure", "source_ip"],
    )


def downgrade() -> None:
    """Drop DMARC forensic/failure report storage."""
    op.drop_index("ix_forensic_reports_failure_source", table_name="forensic_reports")
    op.drop_index("ix_forensic_reports_domain_arrival", table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_processed_at"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_arrival_date"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_auth_failure"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_source_ip"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_reported_domain"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_feedback_type"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_report_id"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_domain_id"), table_name="forensic_reports")
    op.drop_index(op.f("ix_forensic_reports_id"), table_name="forensic_reports")
    op.drop_table("forensic_reports")
