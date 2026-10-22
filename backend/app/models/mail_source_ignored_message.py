"""Durable local ignore dispositions for provider mail messages."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.core.database import Base


class MailSourceIgnoredMessage(Base):
    """A locally ignored provider message, scoped to its source and workspace."""

    __tablename__ = "mail_source_ignored_messages"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    mail_source_id = Column(
        Integer,
        ForeignKey("mail_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider = Column(String, nullable=False)
    binding_key = Column(String(64), nullable=False)
    message_id = Column(String(512), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    mail_source = relationship("MailSource", back_populates="ignored_messages")

    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "mail_source_id",
            "provider",
            "binding_key",
            "message_id",
            name="uq_mail_source_ignored_message",
        ),
        Index(
            "ix_mail_source_ignored_message_source_provider",
            "mail_source_id",
            "provider",
            "binding_key",
        ),
    )
