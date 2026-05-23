"""add tls reports

Revision ID: f7a8b9c0d1e2
Revises: c4d5e6f7a8b9
Create Date: 2026-05-23 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f7a8b9c0d1e2"
down_revision: Union[str, Sequence[str], None] = "c4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create privacy-conscious SMTP TLS report storage."""
    op.create_table(
        "tls_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=True),
        sa.Column("report_id", sa.String(), nullable=False),
        sa.Column("org_name", sa.String(), nullable=True),
        sa.Column("contact_info", sa.String(), nullable=True),
        sa.Column("policy_domain", sa.String(), nullable=False),
        sa.Column("policy_type", sa.String(), nullable=True),
        sa.Column("begin_date", sa.DateTime(), nullable=True),
        sa.Column("end_date", sa.DateTime(), nullable=True),
        sa.Column("total_successful_sessions", sa.Integer(), nullable=False),
        sa.Column("total_failure_sessions", sa.Integer(), nullable=False),
        sa.Column("raw_policy", sa.Text(), nullable=True),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id", "policy_domain", name="uq_tls_reports_report_domain"),
    )
    op.create_index(op.f("ix_tls_reports_id"), "tls_reports", ["id"])
    op.create_index(op.f("ix_tls_reports_domain_id"), "tls_reports", ["domain_id"])
    op.create_index(op.f("ix_tls_reports_report_id"), "tls_reports", ["report_id"])
    op.create_index(op.f("ix_tls_reports_org_name"), "tls_reports", ["org_name"])
    op.create_index(op.f("ix_tls_reports_policy_domain"), "tls_reports", ["policy_domain"])
    op.create_index(op.f("ix_tls_reports_policy_type"), "tls_reports", ["policy_type"])
    op.create_index(op.f("ix_tls_reports_begin_date"), "tls_reports", ["begin_date"])
    op.create_index(op.f("ix_tls_reports_end_date"), "tls_reports", ["end_date"])
    op.create_index(op.f("ix_tls_reports_processed_at"), "tls_reports", ["processed_at"])
    op.create_index(
        "ix_tls_reports_domain_dates",
        "tls_reports",
        ["domain_id", "begin_date", "end_date"],
    )
    op.create_index(
        "ix_tls_reports_policy_domain_dates",
        "tls_reports",
        ["policy_domain", "begin_date", "end_date"],
    )

    op.create_table(
        "tls_report_failures",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("report_id", sa.Integer(), nullable=False),
        sa.Column("result_type", sa.String(), nullable=False),
        sa.Column("failed_session_count", sa.Integer(), nullable=False),
        sa.Column("sending_mta_ip", sa.String(), nullable=True),
        sa.Column("receiving_mx_hostname", sa.String(), nullable=True),
        sa.Column("receiving_mx_helo", sa.String(), nullable=True),
        sa.Column("receiving_ip", sa.String(), nullable=True),
        sa.Column("failure_reason_code", sa.String(), nullable=True),
        sa.Column("additional_information", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["report_id"], ["tls_reports.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tls_report_failures_id"), "tls_report_failures", ["id"])
    op.create_index(op.f("ix_tls_report_failures_report_id"), "tls_report_failures", ["report_id"])
    op.create_index(
        op.f("ix_tls_report_failures_result_type"), "tls_report_failures", ["result_type"]
    )
    op.create_index(
        op.f("ix_tls_report_failures_sending_mta_ip"),
        "tls_report_failures",
        ["sending_mta_ip"],
    )
    op.create_index(
        op.f("ix_tls_report_failures_receiving_mx_hostname"),
        "tls_report_failures",
        ["receiving_mx_hostname"],
    )
    op.create_index(
        "ix_tls_report_failures_result_count",
        "tls_report_failures",
        ["result_type", "failed_session_count"],
    )
    op.create_index(
        "ix_tls_report_failures_report_result",
        "tls_report_failures",
        ["report_id", "result_type"],
    )


def downgrade() -> None:
    """Drop SMTP TLS report storage."""
    op.drop_index("ix_tls_report_failures_report_result", table_name="tls_report_failures")
    op.drop_index("ix_tls_report_failures_result_count", table_name="tls_report_failures")
    op.drop_index(
        op.f("ix_tls_report_failures_receiving_mx_hostname"),
        table_name="tls_report_failures",
    )
    op.drop_index(op.f("ix_tls_report_failures_sending_mta_ip"), table_name="tls_report_failures")
    op.drop_index(op.f("ix_tls_report_failures_result_type"), table_name="tls_report_failures")
    op.drop_index(op.f("ix_tls_report_failures_report_id"), table_name="tls_report_failures")
    op.drop_index(op.f("ix_tls_report_failures_id"), table_name="tls_report_failures")
    op.drop_table("tls_report_failures")
    op.drop_index("ix_tls_reports_policy_domain_dates", table_name="tls_reports")
    op.drop_index("ix_tls_reports_domain_dates", table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_processed_at"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_end_date"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_begin_date"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_policy_type"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_policy_domain"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_org_name"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_report_id"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_domain_id"), table_name="tls_reports")
    op.drop_index(op.f("ix_tls_reports_id"), table_name="tls_reports")
    op.drop_table("tls_reports")
