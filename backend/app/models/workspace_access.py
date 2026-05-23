from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class WorkspaceMembership(Base):
    """User role assignment inside one workspace."""

    __tablename__ = "workspace_memberships"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String(50), nullable=False, index=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    workspace = relationship("Workspace")
    user = relationship("User")

    __table_args__ = (
        Index("ix_workspace_memberships_workspace_user", "workspace_id", "user_id", unique=True),
        Index("ix_workspace_memberships_workspace_role", "workspace_id", "role"),
    )

    def __repr__(self):
        return f"<WorkspaceMembership workspace={self.workspace_id} user={self.user_id}>"


class WorkspaceAuditLog(Base):
    """Sanitized audit trail for sensitive workspace-scoped changes."""

    __tablename__ = "workspace_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    actor_type = Column(String(50), nullable=False, index=True)
    actor_id = Column(String(120), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    entity_type = Column(String(80), nullable=False, index=True)
    entity_id = Column(String(120), nullable=True, index=True)
    entity_name = Column(String(255), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    workspace = relationship("Workspace")

    __table_args__ = (
        Index("ix_workspace_audit_workspace_created", "workspace_id", "created_at"),
        Index("ix_workspace_audit_workspace_action", "workspace_id", "action"),
        Index("ix_workspace_audit_entity", "entity_type", "entity_id"),
    )

    def __repr__(self):
        return f"<WorkspaceAuditLog {self.action} {self.entity_type}>"
