"""add dmarcbis aggregate fields

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
Create Date: 2026-05-23 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e2f3a4b5c6d7"
down_revision: Union[str, Sequence[str], None] = "d1e2f3a4b5c6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Persist optional RFC 9990 / DMARCbis aggregate metadata."""
    op.add_column("dmarc_reports", sa.Column("extra_contact_info", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("generator", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("report_errors", sa.Text(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("non_subdomain_policy", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("failure_options", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("testing", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("discovery_method", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("schema_version", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("report_variant", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("xml_namespace", sa.String(), nullable=True))
    op.add_column("dmarc_reports", sa.Column("report_extensions", sa.Text(), nullable=True))
    op.add_column("report_records", sa.Column("envelope_to", sa.String(), nullable=True))
    op.add_column("report_records", sa.Column("policy_override_reasons", sa.Text(), nullable=True))
    op.add_column("report_records", sa.Column("record_extensions", sa.Text(), nullable=True))


def downgrade() -> None:
    """Remove optional RFC 9990 / DMARCbis aggregate metadata."""
    op.drop_column("report_records", "record_extensions")
    op.drop_column("report_records", "policy_override_reasons")
    op.drop_column("report_records", "envelope_to")
    op.drop_column("dmarc_reports", "report_extensions")
    op.drop_column("dmarc_reports", "xml_namespace")
    op.drop_column("dmarc_reports", "report_variant")
    op.drop_column("dmarc_reports", "schema_version")
    op.drop_column("dmarc_reports", "discovery_method")
    op.drop_column("dmarc_reports", "testing")
    op.drop_column("dmarc_reports", "failure_options")
    op.drop_column("dmarc_reports", "non_subdomain_policy")
    op.drop_column("dmarc_reports", "report_errors")
    op.drop_column("dmarc_reports", "generator")
    op.drop_column("dmarc_reports", "extra_contact_info")
