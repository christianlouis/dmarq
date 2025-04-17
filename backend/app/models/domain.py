from typing import List, Optional
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class Domain(Base):
    """Domain model representing a monitored domain"""
    
    __tablename__ = "domains"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True)
    
    # DMARC policy information
    dmarc_policy = Column(String, nullable=True)
    spf_record = Column(String, nullable=True)
    dkim_selectors = Column(String, nullable=True)  # Comma-separated list of DKIM selectors
    
    # DNS verification status
    verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    
    # Date fields
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    reports = relationship("DMARCReport", back_populates="domain", cascade="all, delete-orphan")
    user_domains = relationship("UserDomain", back_populates="domain", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Domain {self.name}>"


class UserDomain(Base):
    """Association table for users and domains"""
    
    __tablename__ = "user_domains"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    
    # Access level (admin, viewer, etc)
    role = Column(String, default="viewer", nullable=False)
    
    # Date fields
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="user_domains")
    domain = relationship("Domain", back_populates="user_domains")