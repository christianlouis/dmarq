"""Immutable DNS posture evidence and its mutable read projection."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from app.core.database import Base


class DomainDNSPostureSnapshot(Base):
    """One completed DNS observation; rows are never mutated after capture."""

    __tablename__ = "domain_dns_posture_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=True, index=True)
    trigger = Column(String(32), nullable=False, default="scheduled")
    selector_hash = Column(String(64), nullable=False, index=True)
    result_fingerprint = Column(String(64), nullable=False, index=True)
    result_json = Column(Text, nullable=False)
    provenance_json = Column(Text, nullable=True)
    delta_json = Column(Text, nullable=True)
    lookup_status = Column(String(32), nullable=False, default="unknown")
    accepted = Column(Boolean, nullable=False, default=False, index=True)
    captured_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_dns_posture_snapshot_domain_captured", "domain_id", "captured_at"),
        Index("ix_dns_posture_snapshot_workspace_domain", "workspace_id", "domain_id"),
    )


class DomainDNSPostureCurrent(Base):
    """Small mutable pointer used by normal UI reads and refresh coalescing."""

    __tablename__ = "domain_dns_posture_current"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False, unique=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=True, index=True)
    accepted_snapshot_id = Column(
        Integer, ForeignKey("domain_dns_posture_snapshots.id"), nullable=True, index=True
    )
    latest_snapshot_id = Column(
        Integer, ForeignKey("domain_dns_posture_snapshots.id"), nullable=True, index=True
    )
    requested_at = Column(DateTime, nullable=True, index=True)
    completed_at = Column(DateTime, nullable=True, index=True)
    next_trigger = Column(String(32), nullable=True)
    selector_hash = Column(String(64), nullable=True)
    absence_observations = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("domain_id", name="uq_domain_dns_posture_current_domain"),
        Index("ix_dns_posture_current_requested", "requested_at", "domain_id"),
    )
