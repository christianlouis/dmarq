from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.core.database import Base


class Setting(Base):
    """
    Key-value store for system-wide application settings.

    Settings are grouped by a ``category`` prefix (e.g. ``general``,
    ``dmarc``, ``cloudflare``) to make bulk retrieval and UI grouping easy.
    The ``value`` is always stored as text; callers are responsible for
    serialising/deserialising typed values (int, bool, JSON) via the
    ``value_type`` hint.
    """

    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)
    # Human-readable description shown in the admin UI
    description = Column(String(255), nullable=True)
    # Hint for the UI / API on how to interpret the value: string | integer | boolean | json
    value_type = Column(String(20), nullable=False, default="string")
    # Category / section grouping (e.g. "general", "dmarc", "cloudflare", "dns")
    category = Column(String(50), nullable=False, default="general")
    # Audit fields
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    def __repr__(self):
        return f"<Setting key={self.key!r} category={self.category!r}>"
