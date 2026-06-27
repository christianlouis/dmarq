"""scope forensic and TLS report uniqueness by workspace

Revision ID: 7b8c9d0e1f2a
Revises: 6a7b8c9d0e1f
Create Date: 2026-06-28 00:00:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "7b8c9d0e1f2a"
down_revision = "6a7b8c9d0e1f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Allow different workspaces to ingest matching external report ids."""
    with op.batch_alter_table("forensic_reports") as batch_op:
        batch_op.drop_constraint("uq_forensic_reports_report_id", type_="unique")
        batch_op.create_unique_constraint(
            "uq_forensic_reports_domain_report",
            ["domain_id", "report_id"],
        )

    with op.batch_alter_table("tls_reports") as batch_op:
        batch_op.drop_constraint("uq_tls_reports_report_domain", type_="unique")
        batch_op.create_unique_constraint(
            "uq_tls_reports_domain_report_policy",
            ["domain_id", "report_id", "policy_domain"],
        )


def downgrade() -> None:
    """Restore global report-id uniqueness constraints."""
    with op.batch_alter_table("tls_reports") as batch_op:
        batch_op.drop_constraint("uq_tls_reports_domain_report_policy", type_="unique")
        batch_op.create_unique_constraint(
            "uq_tls_reports_report_domain",
            ["report_id", "policy_domain"],
        )

    with op.batch_alter_table("forensic_reports") as batch_op:
        batch_op.drop_constraint("uq_forensic_reports_domain_report", type_="unique")
        batch_op.create_unique_constraint(
            "uq_forensic_reports_report_id",
            ["report_id"],
        )
