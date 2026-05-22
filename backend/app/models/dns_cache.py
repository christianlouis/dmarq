from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Index, Integer, String, Text, UniqueConstraint

from app.core.database import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class DNSCache(Base):
    """Cached DNS authentication result for a domain and selector set."""

    __tablename__ = "dns_cache"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False, index=True)
    selectors_key = Column(String(64), nullable=False, index=True)
    result_json = Column(Text, nullable=False)
    checked_at = Column(DateTime, default=_utcnow_naive, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("domain", "provider", "selectors_key", name="uq_dns_cache_lookup"),
        Index("ix_dns_cache_domain_checked", "domain", "checked_at"),
    )

    def __repr__(self):
        return f"<DNSCache {self.domain} provider={self.provider}>"
