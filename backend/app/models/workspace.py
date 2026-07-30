from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class Workspace(Base):
    """Tenant/workspace boundary for monitored DMARC assets."""

    __tablename__ = "workspaces"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    slug = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    report_retention_days = Column(Integer, default=400, nullable=False)
    forensic_retention_days = Column(Integer, default=90, nullable=False)
    tls_report_retention_days = Column(Integer, default=400, nullable=False)
    # DSNs and provider events can contain recipient-level correlation data.
    # Keep their default retention deliberately shorter than aggregate reports.
    delivery_event_retention_days = Column(Integer, default=30, nullable=False)
    # The guided experience is deliberately workspace-scoped. This protects
    # established operators from an unexpected dashboard change while allowing
    # a new or less technical workspace to opt in.
    guided_mail_health_enabled = Column(Boolean, default=False, nullable=False)
    # New workspaces start guided. Existing rows keep their persisted standard
    # value, so upgrades never remove detail without an operator choice.
    guidance_depth = Column(String(24), default="guided", nullable=False)
    guidance_context = Column(String(24), default="watch", nullable=False)
    guidance_teaching_hints_enabled = Column(Boolean, nullable=True)
    # Calm Watch defaults to only situations where intended mail may need an
    # operator decision. Expert deployments can deliberately widen this later.
    notification_posture = Column(String(32), default="actionable_only", nullable=False)
    # Keep the initial reason for installing DMARQ with the workspace, rather
    # than turning a one-time setup answer into browser-only state.
    mail_health_goal = Column(String(48), nullable=True)
    guidance_installation_goals = Column(Text, nullable=True)
    sovereignty_preference = Column(String(32), nullable=True)
    guidance_mail_context = Column(Text, nullable=True)
    guidance_profile_version = Column(Integer, default=1, nullable=False)
    guidance_interview_version = Column(Integer, default=1, nullable=False)
    guidance_interview_completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="workspaces")
    domains = relationship("Domain", back_populates="workspace")
    mail_sources = relationship("MailSource", back_populates="workspace")
    users = relationship("User", back_populates="workspace")

    __table_args__ = (Index("ix_workspaces_active_slug", "active", "slug"),)

    def __repr__(self):
        return f"<Workspace {self.slug}>"
