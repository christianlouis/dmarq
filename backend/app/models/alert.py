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


class AlertConfigurationAudit(Base):
    """Audit trail for notification and alert-rule configuration changes."""

    __tablename__ = "alert_configuration_audit"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), nullable=False, index=True)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    changed_by = Column(String(100), nullable=True, index=True)
    auth_type = Column(String(50), nullable=True)
    changed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (Index("ix_alert_configuration_audit_key_changed_at", "key", "changed_at"),)

    def __repr__(self):
        return f"<AlertConfigurationAudit {self.key}>"
