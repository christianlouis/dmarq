"""Tests for the StatsSummarizer with real database queries."""

import shutil
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models.domain  # noqa: F401
import app.models.mail_source  # noqa: F401
import app.models.organization  # noqa: F401
import app.models.report  # noqa: F401
import app.models.user  # noqa: F401
import app.models.workspace  # noqa: F401
import app.models.workspace_access  # noqa: F401
from app.core.database import Base
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.workspace import Workspace
from app.utils.stats_summarizer import StatsSummarizer, _auth_status_from_counts


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


def _workspace(db, slug: str) -> Workspace:
    workspace = Workspace(slug=slug, name=slug.title(), active=True)
    db.add(workspace)
    db.flush()
    return workspace


def _seed_domain_and_reports(db, domain_name="example.com", workspace_id=None):
    """Insert a domain with reports and records into the database."""
    domain = Domain(name=domain_name, workspace_id=workspace_id)
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


def _seed_mixed_source_records(db, domain_name="example.com"):
    """Insert multiple auth outcomes for one source IP."""
    domain = Domain(name=domain_name)
    db.add(domain)
    db.flush()

    report = DMARCReport(
        domain_id=domain.id,
        report_id="rpt-mixed",
        org_name="google.com",
        begin_date=1597449600,
        end_date=1597535999,
        policy="none",
    )
    db.add(report)
    db.flush()

    db.add_all(
        [
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.55",
                count=8,
                disposition="none",
                dkim="pass",
                spf="fail",
            ),
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.55",
                count=2,
                disposition="reject",
                dkim="fail",
                spf="fail",
            ),
        ]
    )
    db.flush()
    return domain


def _timestamp_days_ago(days):
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())


def _seed_recent_trend_records(db, domain_name="example.com"):
    """Insert recent reports across multiple days for trend calculations."""
    domain = Domain(name=domain_name)
    db.add(domain)
    db.flush()

    report1 = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-recent-1",
        org_name="google.com",
        begin_date=_timestamp_days_ago(2),
        end_date=_timestamp_days_ago(2) + 3600,
        policy="none",
    )
    report2 = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-recent-2",
        org_name="google.com",
        begin_date=_timestamp_days_ago(0),
        end_date=_timestamp_days_ago(0) + 3600,
        policy="none",
    )
    report3 = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-old",
        org_name="google.com",
        begin_date=_timestamp_days_ago(20),
        end_date=_timestamp_days_ago(20) + 3600,
        policy="none",
    )
    db.add_all([report1, report2, report3])
    db.flush()

    db.add_all(
        [
            ReportRecord(
                report_id=report1.id,
                source_ip="203.0.113.10",
                count=6,
                disposition="none",
                dkim="pass",
                spf="fail",
            ),
            ReportRecord(
                report_id=report1.id,
                source_ip="203.0.113.11",
                count=4,
                disposition="reject",
                dkim="fail",
                spf="fail",
            ),
            ReportRecord(
                report_id=report2.id,
                source_ip="203.0.113.12",
                count=5,
                disposition="none",
                dkim="pass",
                spf="pass",
            ),
            ReportRecord(
                report_id=report3.id,
                source_ip="203.0.113.13",
                count=99,
                disposition="none",
                dkim="pass",
                spf="pass",
            ),
        ]
    )
    db.flush()
    return domain


def _seed_new_source_records(db, domain_name="example.com"):
    """Insert an old source and a current first-seen source."""
    domain = Domain(name=domain_name)
    db.add(domain)
    db.flush()

    old_report = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-old-source",
        org_name="google.com",
        begin_date=_timestamp_days_ago(10),
        end_date=_timestamp_days_ago(10) + 3600,
        policy="none",
    )
    current_report = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-new-source",
        org_name="google.com",
        begin_date=_timestamp_days_ago(1),
        end_date=_timestamp_days_ago(1) + 3600,
        policy="none",
    )
    db.add_all([old_report, current_report])
    db.flush()

    db.add_all(
        [
            ReportRecord(
                report_id=old_report.id,
                source_ip="203.0.113.20",
                count=12,
                disposition="none",
                dkim="pass",
                spf="pass",
            ),
            ReportRecord(
                report_id=current_report.id,
                source_ip="203.0.113.21",
                count=7,
                disposition="none",
                dkim="pass",
                spf="fail",
            ),
        ]
    )
    db.flush()
    return domain


def _seed_compliance_drop_records(db, domain_name="example.com"):
    """Insert a recent compliance drop with a source that is not new."""
    domain = Domain(name=domain_name)
    db.add(domain)
    db.flush()

    old_report = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-known-source",
        org_name="google.com",
        begin_date=_timestamp_days_ago(10),
        end_date=_timestamp_days_ago(10) + 3600,
        policy="none",
    )
    previous_report = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-passing-day",
        org_name="google.com",
        begin_date=_timestamp_days_ago(2),
        end_date=_timestamp_days_ago(2) + 3600,
        policy="none",
    )
    current_report = DMARCReport(
        domain_id=domain.id,
        report_id=f"{domain_name}-failing-day",
        org_name="google.com",
        begin_date=_timestamp_days_ago(0),
        end_date=_timestamp_days_ago(0) + 3600,
        policy="none",
    )
    db.add_all([old_report, previous_report, current_report])
    db.flush()

    db.add_all(
        [
            ReportRecord(
                report_id=old_report.id,
                source_ip="203.0.113.30",
                count=3,
                disposition="none",
                dkim="pass",
                spf="pass",
            ),
            ReportRecord(
                report_id=previous_report.id,
                source_ip="203.0.113.30",
                count=10,
                disposition="none",
                dkim="pass",
                spf="pass",
            ),
            ReportRecord(
                report_id=current_report.id,
                source_ip="203.0.113.30",
                count=10,
                disposition="none",
                dkim="fail",
                spf="fail",
            ),
        ]
    )
    db.flush()
    return domain


def test_auth_status_from_counts_returns_none_without_results():
    assert _auth_status_from_counts(0, 0) == "none"


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

    def test_global_top_sources_include_pass_fail_rollups(self, db_session, summarizer):
        _seed_mixed_source_records(db_session)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session)
        source = stats["top_sources"][0]
        assert source["ip"] == "203.0.113.55"
        assert source["count"] == 10
        assert source["spf_pass_count"] == 0
        assert source["spf_fail_count"] == 10
        assert source["dkim_pass_count"] == 8
        assert source["dkim_fail_count"] == 2
        assert source["dmarc_pass_count"] == 8
        assert source["dmarc_fail_count"] == 2
        assert source["spf"] == "fail"
        assert source["dkim"] == "mixed"
        assert source["dmarc"] == "mixed"

    def test_multiple_domains(self, db_session, summarizer):
        _seed_domain_and_reports(db_session, "example.com")
        _seed_domain_and_reports(db_session, "test.org")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session)
        assert stats["total_domains"] == 2
        assert stats["total_emails"] == 16  # 8 * 2
        assert stats["reports_processed"] == 2

    def test_workspace_global_stats_exclude_other_workspaces(self, db_session, summarizer):
        alpha = _workspace(db_session, "alpha-stats")
        beta = _workspace(db_session, "beta-stats")
        _seed_domain_and_reports(db_session, "alpha.example", workspace_id=alpha.id)
        _seed_domain_and_reports(db_session, "beta.example", workspace_id=beta.id)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, workspace_id=alpha.id)

        assert stats["total_domains"] == 1
        assert stats["total_emails"] == 8
        assert stats["reports_processed"] == 1
        assert {source["ip"] for source in stats["top_sources"]} == {
            "203.0.113.1",
            "198.51.100.1",
        }

    def test_global_trend_includes_volume_and_failure_rate(self, db_session, summarizer):
        _seed_recent_trend_records(db_session)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, period_days=7)
        assert len(stats["compliance_trend"]) == 2

        first_day = stats["compliance_trend"][0]
        assert first_day["total"] == 10
        assert first_day["volume"] == 10
        assert first_day["passed"] == 6
        assert first_day["failed"] == 4
        assert first_day["rate"] == 60.0
        assert first_day["compliance_rate"] == 60.0
        assert first_day["failure_rate"] == 40.0

    def test_global_trend_respects_period_days(self, db_session, summarizer):
        _seed_recent_trend_records(db_session)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, period_days=1)
        assert len(stats["compliance_trend"]) == 1
        assert stats["compliance_trend"][0]["total"] == 5

    def test_global_change_summary_detects_new_source(self, db_session, summarizer):
        _seed_new_source_records(db_session)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, period_days=7)
        new_sources = [item for item in stats["change_summary"] if item["type"] == "new_source"]

        assert len(new_sources) == 1
        assert new_sources[0]["domain"] == "example.com"
        assert new_sources[0]["source_ip"] == "203.0.113.21"
        assert new_sources[0]["message_count"] == 7

    def test_global_change_summary_detects_compliance_drop(self, db_session, summarizer):
        _seed_compliance_drop_records(db_session)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, period_days=7)
        drops = [item for item in stats["change_summary"] if item["type"] == "compliance_drop"]

        assert len(drops) == 1
        assert drops[0]["previous_rate"] == 100.0
        assert drops[0]["current_rate"] == 0.0
        assert drops[0]["drop"] == 100.0
        assert drops[0]["failed"] == 10


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

    def test_domain_sources_group_by_ip_with_pass_fail_rollups(self, db_session, summarizer):
        _seed_mixed_source_records(db_session, "example.com")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, domain_id="example.com")
        assert len(stats["sources"]) == 1
        source = stats["sources"][0]
        assert source["ip"] == "203.0.113.55"
        assert source["count"] == 10
        assert source["spf_fail_count"] == 10
        assert source["dkim_pass_count"] == 8
        assert source["dkim_fail_count"] == 2
        assert source["dmarc_pass_count"] == 8
        assert source["dmarc_fail_count"] == 2
        assert source["spf"] == "fail"
        assert source["dkim"] == "mixed"
        assert source["dmarc"] == "mixed"

    def test_domain_isolation(self, db_session, summarizer):
        """Stats for one domain should not include data from another."""
        _seed_domain_and_reports(db_session, "example.com")
        _seed_domain_and_reports(db_session, "other.org")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(db_session, domain_id="example.com")
        assert stats["total_emails"] == 8  # Only example.com's data

    def test_domain_stats_respect_workspace_scope(self, db_session, summarizer):
        alpha = _workspace(db_session, "alpha-domain-stats")
        beta = _workspace(db_session, "beta-domain-stats")
        _seed_domain_and_reports(db_session, "alpha-only.example", workspace_id=alpha.id)
        _seed_domain_and_reports(db_session, "beta-only.example", workspace_id=beta.id)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(
            db_session,
            domain_id="alpha-only.example",
            workspace_id=alpha.id,
        )

        assert stats["domain"] == "alpha-only.example"
        assert stats["total_emails"] == 8
        assert stats["reports_processed"] == 1

    def test_domain_stats_return_empty_for_domain_outside_workspace(self, db_session, summarizer):
        alpha = _workspace(db_session, "alpha-empty-domain")
        beta = _workspace(db_session, "beta-empty-domain")
        _seed_domain_and_reports(db_session, "beta-only.example", workspace_id=beta.id)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(
            db_session,
            domain_id="beta-only.example",
            workspace_id=alpha.id,
        )

        assert stats["domain"] == "beta-only.example"
        assert stats["total_emails"] == 0
        assert stats["reports_processed"] == 0

    def test_domain_trend_isolation(self, db_session, summarizer):
        _seed_recent_trend_records(db_session, "example.com")
        _seed_recent_trend_records(db_session, "other.org")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(
            db_session, domain_id="example.com", period_days=7
        )
        assert [point["total"] for point in stats["compliance_trend"]] == [10, 5]

    def test_domain_change_summary_isolated_to_domain(self, db_session, summarizer):
        _seed_new_source_records(db_session, "example.com")
        _seed_new_source_records(db_session, "other.org")
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(
            db_session, domain_id="example.com", period_days=7
        )
        new_sources = [item for item in stats["change_summary"] if item["type"] == "new_source"]

        assert len(new_sources) == 1
        assert new_sources[0]["domain"] == "example.com"
        assert new_sources[0]["source_ip"] == "203.0.113.21"


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

    def test_period_days_uses_separate_cache_files(self, db_session, summarizer):
        _seed_recent_trend_records(db_session)
        db_session.commit()

        stats_7_days = summarizer.calculate_summary_statistics(db_session, period_days=7)
        stats_1_day = summarizer.calculate_summary_statistics(db_session, period_days=1)

        assert len(stats_7_days["compliance_trend"]) == 2
        assert len(stats_1_day["compliance_trend"]) == 1

    def test_windowed_cache_keys_use_separate_cache_files(self, db_session, summarizer):
        _seed_recent_trend_records(db_session)
        db_session.commit()

        stats = summarizer.calculate_summary_statistics(
            db_session,
            period_days=7,
            start_ts=0,
            end_ts=9_999_999_999,
            cache_key="last_7_days",
        )

        assert summarizer.get_cached_summary(period_days=7, cache_key="last_7_days") == stats
        assert summarizer.get_cached_summary(period_days=7, cache_key="custom_june") is None

    def test_cache_key_preserves_period_days_in_filename(self, summarizer):
        seven_day_cache = summarizer._get_cache_filename(period_days=7, cache_key="shared_window")
        thirty_day_cache = summarizer._get_cache_filename(period_days=30, cache_key="shared_window")

        assert seven_day_cache != thirty_day_cache
        assert "7d_shared_window" in seven_day_cache
        assert "30d_shared_window" in thirty_day_cache

    def test_old_cache_without_change_summary_is_refreshed(self, db_session, summarizer):
        _seed_new_source_records(db_session)
        db_session.commit()
        summarizer.save_summary({"total_domains": 99}, period_days=7)

        stats = summarizer.calculate_summary_statistics(db_session, period_days=7)

        assert stats["total_domains"] == 1
        assert "change_summary" in stats
