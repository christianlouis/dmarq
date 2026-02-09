from datetime import datetime

from app.core.database import Base
from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship


class DMARCReport(Base):
    """DMARC Aggregate Report model"""

    __tablename__ = "dmarc_reports"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False, index=True)

    # Report metadata
    report_id = Column(String, index=True, nullable=False)
    org_name = Column(String, nullable=False, index=True)
    begin_date = Column(Integer, nullable=False, index=True)  # Unix timestamp
    end_date = Column(Integer, nullable=False, index=True)  # Unix timestamp
    source_email = Column(String, nullable=True)

    # Policy information
    policy = Column(String, nullable=True, index=True)  # none, quarantine, reject
    subdomain_policy = Column(String, nullable=True)
    adkim = Column(String(1), nullable=True)  # r (relaxed) or s (strict)
    aspf = Column(String(1), nullable=True)  # r (relaxed) or s (strict)
    percentage = Column(Integer, nullable=True)

    # Processing metadata
    processed_at = Column(DateTime, default=datetime.utcnow, index=True)
    raw_data = Column(Text, nullable=True)  # Original XML content (optional)

    # Relationships
    domain = relationship("Domain", back_populates="reports")
    records = relationship("ReportRecord", back_populates="report", cascade="all, delete-orphan")

    # Indexes for common queries
    __table_args__ = (
        # Composite index for domain and date range queries (common dashboard queries)
        Index("ix_dmarc_reports_domain_dates", "domain_id", "begin_date", "end_date"),
        # Index for finding reports by policy
        Index("ix_dmarc_reports_policy", "policy"),
        # Index for finding recent reports (dashboard statistics)
        Index("ix_dmarc_reports_processed", "processed_at"),
    )

    def __repr__(self):
        return f"<DMARCReport {self.report_id} for {self.domain_id}>"


class ReportRecord(Base):
    """Individual record within a DMARC report"""

    __tablename__ = "report_records"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("dmarc_reports.id"), nullable=False, index=True)

    # Source information
    source_ip = Column(String, nullable=False, index=True)
    count = Column(Integer, nullable=False, default=0)

    # Policy evaluation
    disposition = Column(String, nullable=False, index=True)  # none, quarantine, reject
    dkim = Column(String, nullable=True, index=True)  # pass, fail
    spf = Column(String, nullable=True, index=True)  # pass, fail

    # Identifiers
    header_from = Column(String, nullable=True, index=True)
    envelope_from = Column(String, nullable=True)

    # Authentication details (optional JSON fields)
    dkim_auth_details = Column(Text, nullable=True)  # JSON array of DKIM results
    spf_auth_details = Column(Text, nullable=True)  # JSON array of SPF results

    # Relationships
    report = relationship("DMARCReport", back_populates="records")

    # Indexes for common queries
    __table_args__ = (
        # Composite index for source IP and evaluation results (for filtering)
        Index("ix_report_records_source_auth", "source_ip", "dkim", "spf"),
        # Composite index for disposition and count (for statistics)
        Index("ix_report_records_disposition", "disposition", "count"),
    )

    def __repr__(self):
        return f"<ReportRecord {self.id} ({self.source_ip})>"
