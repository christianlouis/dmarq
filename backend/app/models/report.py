from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.core.database import Base


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
    extra_contact_info = Column(String, nullable=True)
    generator = Column(String, nullable=True)
    report_errors = Column(Text, nullable=True)

    # Policy information
    policy = Column(String, nullable=True)  # none, quarantine, reject (indexed via __table_args__)
    subdomain_policy = Column(String, nullable=True)
    non_subdomain_policy = Column(String, nullable=True)
    adkim = Column(String(1), nullable=True)  # r (relaxed) or s (strict)
    aspf = Column(String(1), nullable=True)  # r (relaxed) or s (strict)
    percentage = Column(Integer, nullable=True)
    failure_options = Column(String, nullable=True)
    testing = Column(String, nullable=True)
    discovery_method = Column(String, nullable=True)

    # Processing metadata
    schema_version = Column(String, nullable=True)
    report_variant = Column(String, nullable=True)
    xml_namespace = Column(String, nullable=True)
    report_extensions = Column(Text, nullable=True)
    processed_at = Column(DateTime, default=datetime.utcnow)
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
    disposition = Column(
        String, nullable=False
    )  # none, quarantine, reject (indexed via __table_args__)
    dkim = Column(String, nullable=True, index=True)  # pass, fail
    spf = Column(String, nullable=True, index=True)  # pass, fail

    # Identifiers
    header_from = Column(String, nullable=True, index=True)
    envelope_from = Column(String, nullable=True)
    envelope_to = Column(String, nullable=True)

    # Authentication details (optional JSON fields)
    dkim_auth_details = Column(Text, nullable=True)  # JSON array of DKIM results
    spf_auth_details = Column(Text, nullable=True)  # JSON array of SPF results
    policy_override_reasons = Column(Text, nullable=True)  # JSON array of policy reasons
    record_extensions = Column(Text, nullable=True)  # JSON object of extension values
    # Point-in-time PTR, network, and reputation evidence captured after ingestion.
    source_evidence = Column(Text, nullable=True)

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


class ForensicReport(Base):
    """DMARC forensic/failure report model (RFC 6591 / ARF)."""

    __tablename__ = "forensic_reports"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False, index=True)

    # Report metadata
    report_id = Column(String, nullable=False, index=True)
    source_email = Column(String, nullable=True)
    feedback_type = Column(String, nullable=True, index=True)
    user_agent = Column(String, nullable=True)
    version = Column(String, nullable=True)

    # DMARC failure fields
    reported_domain = Column(String, nullable=True, index=True)
    source_ip = Column(String, nullable=True, index=True)
    auth_failure = Column(String, nullable=True, index=True)
    delivery_result = Column(String, nullable=True)
    arrival_date = Column(DateTime, nullable=True, index=True)
    authentication_results = Column(Text, nullable=True)

    # Redacted original-message metadata. Never store original body content here.
    original_mail_from = Column(String, nullable=True)
    original_from = Column(String, nullable=True)
    original_to = Column(String, nullable=True)
    original_subject = Column(String, nullable=True)
    original_message_id = Column(String, nullable=True)
    original_date = Column(String, nullable=True)

    # Sanitized parser details for operators/debugging.
    feedback_headers = Column(Text, nullable=True)
    processed_at = Column(DateTime, default=datetime.utcnow, index=True)

    domain = relationship("Domain", back_populates="forensic_reports")

    __table_args__ = (
        UniqueConstraint("domain_id", "report_id", name="uq_forensic_reports_domain_report"),
        Index("ix_forensic_reports_domain_arrival", "domain_id", "arrival_date"),
        Index("ix_forensic_reports_failure_source", "auth_failure", "source_ip"),
    )

    def __repr__(self):
        return f"<ForensicReport {self.report_id}>"


class TLSReport(Base):
    """SMTP TLS reporting (TLS-RPT) aggregate report."""

    __tablename__ = "tls_reports"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False, index=True)

    report_id = Column(String, nullable=False, index=True)
    org_name = Column(String, nullable=True, index=True)
    contact_info = Column(String, nullable=True)
    policy_domain = Column(String, nullable=False, index=True)
    policy_type = Column(String, nullable=True, index=True)
    begin_date = Column(DateTime, nullable=True, index=True)
    end_date = Column(DateTime, nullable=True, index=True)
    total_successful_sessions = Column(Integer, nullable=False, default=0)
    total_failure_sessions = Column(Integer, nullable=False, default=0)
    raw_policy = Column(Text, nullable=True)
    processed_at = Column(DateTime, default=datetime.utcnow, index=True)

    domain = relationship("Domain", back_populates="tls_reports")
    failures = relationship(
        "TLSReportFailure",
        back_populates="report",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint(
            "domain_id",
            "report_id",
            "policy_domain",
            name="uq_tls_reports_domain_report_policy",
        ),
        Index("ix_tls_reports_domain_dates", "domain_id", "begin_date", "end_date"),
        Index("ix_tls_reports_policy_domain_dates", "policy_domain", "begin_date", "end_date"),
    )

    def __repr__(self):
        return f"<TLSReport {self.report_id} {self.policy_domain}>"


class TLSReportFailure(Base):
    """Grouped TLS-RPT failure detail without message-level identifiers."""

    __tablename__ = "tls_report_failures"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("tls_reports.id"), nullable=False, index=True)
    result_type = Column(String, nullable=False, index=True)
    failed_session_count = Column(Integer, nullable=False, default=0)
    sending_mta_ip = Column(String, nullable=True, index=True)
    receiving_mx_hostname = Column(String, nullable=True, index=True)
    receiving_mx_helo = Column(String, nullable=True)
    receiving_ip = Column(String, nullable=True)
    failure_reason_code = Column(String, nullable=True)
    additional_information = Column(Text, nullable=True)

    report = relationship("TLSReport", back_populates="failures")

    __table_args__ = (
        Index("ix_tls_report_failures_result_count", "result_type", "failed_session_count"),
        Index("ix_tls_report_failures_report_result", "report_id", "result_type"),
    )

    def __repr__(self):
        return f"<TLSReportFailure {self.result_type} count={self.failed_session_count}>"
