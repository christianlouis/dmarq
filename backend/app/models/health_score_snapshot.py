from datetime import date, datetime

from sqlalchemy import (
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from app.core.database import Base


class HealthScoreSnapshot(Base):
    """Persisted daily health score evidence for one domain in one workspace."""

    __tablename__ = "health_score_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    domain_name = Column(String(255), nullable=False, index=True)
    snapshot_date = Column(Date, nullable=False, default=date.today, index=True)
    score = Column(Integer, nullable=False)
    grade = Column(String(4), nullable=False)
    status = Column(String(24), nullable=False)
    policy = Column(String(32), nullable=True)
    compliance_rate = Column(Integer, nullable=False, default=0)
    total_emails = Column(Integer, nullable=False, default=0)
    failed_emails = Column(Integer, nullable=False, default=0)
    report_count = Column(Integer, nullable=False, default=0)
    dns_posture_score = Column(Integer, nullable=False, default=0)
    policy_strength_score = Column(Integer, nullable=False, default=0)
    report_confidence_score = Column(Integer, nullable=False, default=0)
    top_actions = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "domain_name",
            "snapshot_date",
            name="uq_health_score_snapshot_workspace_domain_date",
        ),
        Index("ix_health_score_snapshots_workspace_domain", "workspace_id", "domain_name"),
    )

    def __repr__(self):
        return f"<HealthScoreSnapshot {self.domain_name} {self.snapshot_date} {self.score}>"
