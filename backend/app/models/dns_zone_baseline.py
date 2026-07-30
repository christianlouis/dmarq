"""Imported DNS zone baselines used only as comparison evidence."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.core.database import Base


class DNSZoneBaseline(Base):
    """An expiring, removable BIND-style zone import."""

    __tablename__ = "dns_zone_baselines"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    source = Column(String(32), nullable=False, default="manual_bind_import")
    source_hash = Column(String(64), nullable=False, index=True)
    records_json = Column(Text, nullable=False)
    comparison_json = Column(Text, nullable=True)
    imported_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    removed_at = Column(DateTime, nullable=True, index=True)

    __table_args__ = (Index("ix_dns_zone_baseline_workspace_domain", "workspace_id", "domain"),)
