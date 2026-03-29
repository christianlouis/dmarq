"""Tests for the StatsSummarizer with real database queries."""

import shutil
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models.domain  # noqa: F401
import app.models.report  # noqa: F401
import app.models.user  # noqa: F401
from app.core.database import Base
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.utils.stats_summarizer import StatsSummarizer


@pytest.fixture()
def db_session():
    """Create a fresh in-memory SQLite database session."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def summarizer():
    """Create a StatsSummarizer with a temp cache directory."""
    cache_dir = tempfile.mkdtemp()
    s = StatsSummarizer(cache_dir=cache_dir)
    yield s
    shutil.rmtree(cache_dir, ignore_errors=True)


def _seed_domain_and_reports(db, domain_name="example.com"):
    """Insert a domain with reports and records into the database."""
    domain = Domain(name=domain_name)
    db.add(domain)
    db.flush()

    # Report 1: 2 records, 1 fully passing, 1 failing
    report1 = DMARCReport(
        domain_id=domain.id,
        report_id="rpt-001",
        org_name="google.com",
        begin_date=1597449600,  # 2020-08-15
        end_date=1597535999,
        policy="none",
    )
    db.add(report1)
    db.flush()

    # Record: 5 emails, both pass
    rec1 = ReportRecord(
        report_id=report1.id,
        source_ip="203.0.113.1",
        count=5,
        disposition="none",
        dkim="pass",
        spf="pass",
    )
    # Record: 3 emails, both fail
    rec2 = ReportRecord(
        report_id=report1.id,
        source_ip="198.51.100.1",
        count=3,
        disposition="quarantine",
        dkim="fail",
        spf="fail",
    )
    db.add_all([rec1, rec2])
    db.flush()
    return domain


class TestStatsSummarizerGlobal:
    """Tests for global statistics."""

    def test_empty_database_returns_zeros(self, db_session, summarizer):
        stats = summarizer.calculate_summary_statistics(db_session)
        assert stats["total_domains"] == 0
        assert stats["total_emails"] == 0
        assert stats["compliance_rate"] == 0.0
        assert stats["reports_processed"] == 0
        assert stats["top_sources"] == []
        assert stats["compliance_trend"] == []

    def test_global_stats_with_data(self, db_session, summarizer):
        _seed_domain_and_reports(db_session, "example.com")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session)
        assert stats["total_domains"] == 1
        assert stats["total_emails"] == 8  # 5 + 3
        assert stats["compliant_emails"] == 5  # only rec1 passes
        assert stats["compliance_rate"] == 62.5  # 5/8 * 100
        assert stats["reports_processed"] == 1

    def test_global_top_sources(self, db_session, summarizer):
        _seed_domain_and_reports(db_session)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session)
        assert len(stats["top_sources"]) == 2
        # Sorted by count descending
        assert stats["top_sources"][0]["ip"] == "203.0.113.1"
        assert stats["top_sources"][0]["count"] == 5

    def test_multiple_domains(self, db_session, summarizer):
        _seed_domain_and_reports(db_session, "example.com")
        _seed_domain_and_reports(db_session, "test.org")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session)
        assert stats["total_domains"] == 2
        assert stats["total_emails"] == 16  # 8 * 2
        assert stats["reports_processed"] == 2


class TestStatsSummarizerDomain:
    """Tests for domain-specific statistics."""

    def test_nonexistent_domain(self, db_session, summarizer):
        stats = summarizer.calculate_summary_statistics(db_session, domain_id="nope.com")
        assert stats["domain"] == "nope.com"
        assert stats["total_emails"] == 0
        assert stats["compliance_rate"] == 0.0

    def test_domain_stats_with_data(self, db_session, summarizer):
        _seed_domain_and_reports(db_session, "example.com")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, domain_id="example.com")
        assert stats["domain"] == "example.com"
        assert stats["total_emails"] == 8
        assert stats["compliant_emails"] == 5
        assert stats["compliance_rate"] == 62.5
        assert stats["reports_processed"] == 1

    def test_domain_sources(self, db_session, summarizer):
        _seed_domain_and_reports(db_session, "example.com")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, domain_id="example.com")
        assert len(stats["sources"]) == 2
        # First source should be the highest count
        assert stats["sources"][0]["ip"] == "203.0.113.1"
        assert stats["sources"][0]["count"] == 5

    def test_domain_isolation(self, db_session, summarizer):
        """Stats for one domain should not include data from another."""
        _seed_domain_and_reports(db_session, "example.com")
        _seed_domain_and_reports(db_session, "other.org")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, domain_id="example.com")
        assert stats["total_emails"] == 8  # Only example.com's data


class TestStatsSummarizerCaching:
    """Tests for the caching layer."""

    def test_caching_returns_same_data(self, db_session, summarizer):
        _seed_domain_and_reports(db_session)
        db_session.commit()

        stats1 = summarizer.calculate_summary_statistics(db_session)
        stats2 = summarizer.calculate_summary_statistics(db_session)
        assert stats1 == stats2

    def test_invalidate_cache(self, db_session, summarizer):
        _seed_domain_and_reports(db_session)
        db_session.commit()

        summarizer.calculate_summary_statistics(db_session)
        summarizer.invalidate_cache()
        # Should recalculate after invalidation
        stats = summarizer.calculate_summary_statistics(db_session)
        assert stats["total_domains"] == 1
