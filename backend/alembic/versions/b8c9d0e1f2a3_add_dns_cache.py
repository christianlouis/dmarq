"""add dns cache

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-05-22 23:28:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, Sequence[str], None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create a DNS result cache table."""
    op.create_table(
        "dns_cache",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("selectors_key", sa.String(length=64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain", "provider", "selectors_key", name="uq_dns_cache_lookup"),
    )
    op.create_index(op.f("ix_dns_cache_id"), "dns_cache", ["id"], unique=False)
    op.create_index(op.f("ix_dns_cache_domain"), "dns_cache", ["domain"], unique=False)
    op.create_index(op.f("ix_dns_cache_provider"), "dns_cache", ["provider"], unique=False)
    op.create_index(
        op.f("ix_dns_cache_selectors_key"),
        "dns_cache",
        ["selectors_key"],
        unique=False,
    )
    op.create_index(op.f("ix_dns_cache_checked_at"), "dns_cache", ["checked_at"], unique=False)
    op.create_index(
        "ix_dns_cache_domain_checked",
        "dns_cache",
        ["domain", "checked_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the DNS result cache table."""
    op.drop_index("ix_dns_cache_domain_checked", table_name="dns_cache")
    op.drop_index(op.f("ix_dns_cache_checked_at"), table_name="dns_cache")
    op.drop_index(op.f("ix_dns_cache_selectors_key"), table_name="dns_cache")
    op.drop_index(op.f("ix_dns_cache_provider"), table_name="dns_cache")
    op.drop_index(op.f("ix_dns_cache_domain"), table_name="dns_cache")
    op.drop_index(op.f("ix_dns_cache_id"), table_name="dns_cache")
    op.drop_table("dns_cache")
