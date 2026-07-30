"""Privacy-minimized evidence for actual delivery-status observations."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from app.core.database import Base


class DeliveryEvent(Base):
    """One normalized DSN recipient result or authenticated provider event."""

    __tablename__ = "delivery_events"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    domain = Column(String, nullable=True, index=True)
    source_system = Column(String(64), nullable=False, index=True)
    provider = Column(String(80), nullable=False, default="smtp", index=True)
    event_id = Column(String(160), nullable=False)
    normalized_event = Column(String(32), nullable=False, index=True)
    original_event = Column(String(120), nullable=True)
    action = Column(String(32), nullable=True)
    status_code = Column(String(32), nullable=True, index=True)
    diagnostic_type = Column(String(80), nullable=True)
    diagnostic_text = Column(Text, nullable=True)
    cause_family = Column(String(64), nullable=False, default="unknown_other", index=True)
    recipient_domain = Column(String(255), nullable=True, index=True)
    recipient_hash = Column(String(64), nullable=True, index=True)
    message_id_hash = Column(String(64), nullable=True, index=True)
    envelope_id_hash = Column(String(64), nullable=True, index=True)
    reporting_mta = Column(String(255), nullable=True)
    remote_mta = Column(String(255), nullable=True)
    occurred_at = Column(DateTime, nullable=False, index=True)
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    retention_until = Column(DateTime, nullable=False, index=True)
    correlation_confidence = Column(String(24), nullable=False, default="low")
    correlation_reasons = Column(Text, nullable=True)
    provider_semantics = Column(Text, nullable=True)
    signal_json = Column(Text, nullable=False)
    sanitized_payload = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "source_system",
            "provider",
            "event_id",
            name="uq_delivery_event_workspace_source_event",
        ),
        Index(
            "ix_delivery_events_workspace_domain_occurred",
            "workspace_id",
            "domain",
            "occurred_at",
        ),
        Index(
            "ix_delivery_events_workspace_outcome_occurred",
            "workspace_id",
            "normalized_event",
            "occurred_at",
        ),
    )

    def __repr__(self):
        return f"<DeliveryEvent {self.source_system}:{self.event_id} {self.normalized_event}>"
