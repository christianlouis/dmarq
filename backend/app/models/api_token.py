from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text

from app.core.database import Base


class APIToken(Base):
    """Scoped API token for stable automation access."""

    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    key_prefix = Column(String(16), nullable=False, index=True)
    scopes = Column(Text, nullable=False)
    active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True, index=True)
    last_used_at = Column(DateTime, nullable=True, index=True)
    last_used_ip = Column(String(64), nullable=True)
    usage_count = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("ix_api_tokens_active_scope", "active", "scopes"),
        Index("ix_api_tokens_last_used", "last_used_at"),
    )

    def __repr__(self):
        return f"<APIToken {self.name} active={self.active}>"
