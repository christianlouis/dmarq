from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text, UniqueConstraint

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


class DNSRecordSnapshot(Base):
    """Last observed DNS record state for provider-backed DNS integrations."""

    __tablename__ = "dns_record_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False, index=True)
    zone_id = Column(String, nullable=True, index=True)
    record_key = Column(String(128), nullable=False, index=True)
    record_id = Column(String, nullable=True, index=True)
    record_type = Column(String(20), nullable=False, index=True)
    record_name = Column(String, nullable=False, index=True)
    content = Column(Text, nullable=True)
    proxied = Column(Boolean, nullable=True)
    ttl = Column(Integer, nullable=True)
    record_hash = Column(String(64), nullable=False, index=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    first_seen_at = Column(DateTime, default=_utcnow_naive, nullable=False, index=True)
    last_seen_at = Column(DateTime, default=_utcnow_naive, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint(
            "domain",
            "provider",
            "record_key",
            name="uq_dns_record_snapshot_lookup",
        ),
        Index("ix_dns_record_snapshots_domain_active", "domain", "active"),
        Index("ix_dns_record_snapshots_domain_seen", "domain", "last_seen_at"),
    )

    def __repr__(self):
        return f"<DNSRecordSnapshot {self.domain} {self.record_type} {self.record_name}>"


class DNSRecordChange(Base):
    """Append-only DNS record change event detected during provider sync."""

    __tablename__ = "dns_record_changes"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False, index=True)
    zone_id = Column(String, nullable=True, index=True)
    record_key = Column(String(128), nullable=False, index=True)
    record_id = Column(String, nullable=True, index=True)
    record_type = Column(String(20), nullable=False, index=True)
    record_name = Column(String, nullable=False, index=True)
    change_type = Column(String(20), nullable=False, index=True)
    previous_content = Column(Text, nullable=True)
    current_content = Column(Text, nullable=True)
    observed_at = Column(DateTime, default=_utcnow_naive, nullable=False, index=True)

    __table_args__ = (
        Index("ix_dns_record_changes_domain_observed", "domain", "observed_at"),
        Index("ix_dns_record_changes_record_observed", "record_key", "observed_at"),
    )

    def __repr__(self):
        return f"<DNSRecordChange {self.domain} {self.change_type} {self.record_name}>"
