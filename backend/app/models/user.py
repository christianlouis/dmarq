from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class User(Base):
    """User model – local shadow of the identity managed by Logto."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    # Logto subject claim (the user's stable ID inside Logto).
    # Null for users that pre-date Logto integration or for
    # programmatic/service accounts created directly in the DB.
    logto_id = Column(String, unique=True, index=True, nullable=True)
    # hashed_password kept for possible future local-auth fallback; nullable
    # because Logto users authenticate externally and have no local password.
    hashed_password = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    # For now all users are treated as admin.  RBAC tiers are planned.
    is_superuser = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)

    # Profile – synced from Logto claims on every login
    full_name = Column(String, nullable=True)
    username = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    picture = Column(String, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=True)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=True,
    )

    # Relationships
    user_domains = relationship("UserDomain", back_populates="user", cascade="all, delete-orphan")
