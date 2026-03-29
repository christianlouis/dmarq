from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord


class TestDomainModel:
    """Tests for the Domain ORM model."""

    def test_create_domain(self, db_session: Session):
        domain = Domain(
            name="example.com",
            description="Test domain",
            active=True,
            dmarc_policy="quarantine",
        )
        db_session.add(domain)
        db_session.commit()
        db_session.refresh(domain)

        assert domain.id is not None
        assert domain.name == "example.com"
        assert domain.description == "Test domain"
        assert domain.active is True
        assert domain.dmarc_policy == "quarantine"

    def test_domain_reports_relationship(self, db_session: Session):
        domain = Domain(name="example.com", active=True)
        db_session.add(domain)
        db_session.commit()

        report = DMARCReport(
            domain_id=domain.id,
            report_id="report1",
            org_name="Google",
            begin_date=1597449600,
            end_date=1597535999,
            source_email="noreply@google.com",
        )
        db_session.add(report)
        db_session.commit()

        fetched = db_session.query(Domain).filter_by(name="example.com").first()
        assert fetched is not None
        assert len(fetched.reports) == 1
        assert fetched.reports[0].report_id == "report1"


class TestDMARCReportModel:
    """Tests for the DMARCReport ORM model."""

    def test_create_report(self, db_session: Session):
        domain = Domain(name="example.com", active=True)
        db_session.add(domain)
        db_session.commit()

        report = DMARCReport(
            domain_id=domain.id,
            report_id="123456789",
            org_name="Google",
            begin_date=1597449600,
            end_date=1597535999,
            source_email="noreply@google.com",
            policy="none",
        )
        db_session.add(report)
        db_session.commit()
        db_session.refresh(report)

        assert report.id is not None
        assert report.domain_id == domain.id
        assert report.report_id == "123456789"
        assert report.org_name == "Google"
        assert report.policy == "none"

    def test_report_records_relationship(self, db_session: Session):
        domain = Domain(name="example.com", active=True)
        db_session.add(domain)
        db_session.commit()

        report = DMARCReport(
            domain_id=domain.id,
            report_id="123456789",
            org_name="Google",
            begin_date=1597449600,
            end_date=1597535999,
            source_email="noreply@google.com",
        )
        db_session.add(report)
        db_session.commit()

        record = ReportRecord(
            report_id=report.id,
            source_ip="203.0.113.1",
            count=2,
            disposition="none",
            dkim="pass",
            spf="fail",
            header_from="example.com",
        )
        db_session.add(record)
        db_session.commit()

        fetched = db_session.query(DMARCReport).filter_by(report_id="123456789").first()
        assert fetched is not None
        assert len(fetched.records) == 1
        assert fetched.records[0].source_ip == "203.0.113.1"
