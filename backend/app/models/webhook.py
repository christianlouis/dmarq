from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.core.database import Base


class WebhookEndpoint(Base):
    """Outbound webhook endpoint configured by an operator."""

    __tablename__ = "webhook_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=True, index=True)
    name = Column(String(120), nullable=False)
    url = Column(Text, nullable=False)
    secret = Column(Text, nullable=False)
    event_types = Column(Text, nullable=False, default="*")
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    max_attempts = Column(Integer, default=5, nullable=False)
    timeout_seconds = Column(Integer, default=10, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_success_at = Column(DateTime, nullable=True, index=True)
    last_failure_at = Column(DateTime, nullable=True, index=True)
    failure_count = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("ix_webhook_endpoints_enabled_events", "enabled", "event_types"),
        Index("ix_webhook_endpoints_workspace_enabled", "workspace_id", "enabled"),
    )

    def __repr__(self):
        return f"<WebhookEndpoint {self.name} enabled={self.enabled}>"


class WebhookDelivery(Base):
    """Single outbound webhook delivery attempt state."""

    __tablename__ = "webhook_deliveries"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("webhook_endpoints.id"), nullable=False, index=True)
    event_type = Column(String(80), nullable=False, index=True)
    payload = Column(Text, nullable=False)
    idempotency_key = Column(String(160), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="pending", index=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=5, nullable=False)
    next_attempt_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_attempt_at = Column(DateTime, nullable=True, index=True)
    delivered_at = Column(DateTime, nullable=True, index=True)
    last_status_code = Column(Integer, nullable=True)
    last_error = Column(Text, nullable=True)
    response_excerpt = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index(
            "ix_webhook_delivery_endpoint_idempotency",
            "endpoint_id",
            "idempotency_key",
            unique=True,
        ),
        Index("ix_webhook_delivery_due", "status", "next_attempt_at"),
    )

    def __repr__(self):
        return f"<WebhookDelivery endpoint={self.endpoint_id} event={self.event_type} status={self.status}>"
