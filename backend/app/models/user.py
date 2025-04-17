from typing import List, Optional
from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class User(Base):
    """User model"""
    
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    
    # Additional fields
    full_name = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    
    # Relationships
    user_domains = relationship("UserDomain", back_populates="user", cascade="all, delete-orphan")