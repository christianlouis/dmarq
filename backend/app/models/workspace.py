from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class Workspace(Base):
    """Tenant/workspace boundary for monitored DMARC assets."""

    __tablename__ = "workspaces"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    domains = relationship("Domain", back_populates="workspace")
    mail_sources = relationship("MailSource", back_populates="workspace")
    users = relationship("User", back_populates="workspace")

    __table_args__ = (Index("ix_workspaces_active_slug", "active", "slug"),)

    def __repr__(self):
        return f"<Workspace {self.slug}>"
