from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class MailSourceBackfillJob(Base):
    """Persisted progress row for a resumable mailbox backfill request."""

    __tablename__ = "mail_source_backfill_jobs"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    mail_source_id = Column(Integer, nullable=False, index=True)

    status = Column(String(length=24), nullable=False, default="queued", index=True)
    trigger = Column(String(length=40), nullable=False, default="manual")
    requested_start = Column(DateTime, nullable=True)
    requested_end = Column(DateTime, nullable=True)
    requested_by = Column(String(length=120), nullable=True)

    processed = Column(Integer, nullable=False, default=0)
    reports_found = Column(Integer, nullable=False, default=0)
    duplicate_reports = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)
    attempt_count = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=3)

    cursor = Column(Text, nullable=True)
    errors = Column(Text, nullable=True)
    details = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    next_retry_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    mail_source = relationship("MailSource", back_populates="backfill_jobs")
    workspace = relationship("Workspace", overlaps="backfill_jobs,mail_source")

    __table_args__ = (
        ForeignKeyConstraint(
            ["mail_source_id", "workspace_id"],
            ["mail_sources.id", "mail_sources.workspace_id"],
            name="fk_mail_source_backfill_source_workspace",
        ),
        Index("ix_mail_source_backfill_workspace_status", "workspace_id", "status"),
        Index("ix_mail_source_backfill_source_status", "mail_source_id", "status"),
        Index("ix_mail_source_backfill_retry", "status", "next_retry_at"),
    )

    def __repr__(self):
        return (
            f"<MailSourceBackfillJob id={self.id} source={self.mail_source_id} "
            f"status={self.status!r}>"
        )
