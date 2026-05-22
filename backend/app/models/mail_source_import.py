from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class MailSourceImport(Base):
    """Sanitized audit record for one mail source import attempt."""

    __tablename__ = "mail_source_imports"

    id = Column(Integer, primary_key=True, index=True)
    mail_source_id = Column(Integer, ForeignKey("mail_sources.id"), nullable=False, index=True)

    trigger = Column(String, nullable=False, default="manual")
    status = Column(String, nullable=False, index=True)

    processed = Column(Integer, nullable=False, default=0)
    reports_found = Column(Integer, nullable=False, default=0)
    duplicate_reports = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)

    new_domains = Column(Text, nullable=True)
    errors = Column(Text, nullable=True)
    details = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    mail_source = relationship("MailSource", back_populates="imports")

    def __repr__(self):
        return (
            f"<MailSourceImport id={self.id} source={self.mail_source_id} "
            f"status={self.status!r}>"
        )
