from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text

from app.core.database import Base


class AlertHistory(Base):
    """Persisted alert lifecycle record."""

    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True, index=True)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    rule = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    domain = Column(String, nullable=True, index=True)
    title = Column(String, nullable=False)
    detail = Column(Text, nullable=False)
    payload = Column(Text, nullable=True)
    observed_count = Column(Integer, nullable=False, default=1)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    resolved_at = Column(DateTime, nullable=True, index=True)

    __table_args__ = (
        Index("ix_alert_history_active_last_seen", "is_active", "last_seen_at"),
        Index("ix_alert_history_rule_domain", "rule", "domain"),
    )

    def __repr__(self):
        return f"<AlertHistory {self.rule} active={self.is_active}>"
