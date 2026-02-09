from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from sqlalchemy.orm import Session


class TestDomainModel:
    """Tests for the Domain model"""

    def test_create_domain(self, db_session: Session):
        """Test creating a domain in the database"""
        domain = Domain(
            name="example.com", description="Test domain", active=True, dmarc_policy="quarantine"
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
        """Test the relationship between domains and DMARC reports"""
        # Create a domain
        domain = Domain(name="example.com", active=True)
        db_session.add(domain)
        db_session.commit()

        # Create reports for the domain
        report1 = DMARCReport(
            domain_id=domain.id,
            report_id="report1",
            org_name="Google",
            begin_date=1597449600,
            end_date=1597535999,
            source_email="noreply-dmarc-support@google.com",
        )

        report2 = DMARCReport(
            domain_id=domain.id,
            report_id="report2",
            org_name="Microsoft",
            begin_date=1597536000,
            end_date=1597622399,
            source_email="dmarc@microsoft.com",
        )

        db_session.add_all([report1, report2])
        db_session.commit()

        # Query the domain and check its reports
        domain = db_session.query(Domain).filter_by(name="example.com").first()
        assert domain is not None
        assert len(domain.reports) == 2
        assert domain.reports[0].report_id in ["report1", "report2"]
        assert domain.reports[1].report_id in ["report1", "report2"]


class TestDMARCReportModel:
    """Tests for the DMARCReport model"""

    def test_create_report(self, db_session: Session):
        """Test creating a DMARC report in the database"""
        # Create a domain first
        domain = Domain(name="example.com", active=True)
        db_session.add(domain)
        db_session.commit()

        # Create a report
        report = DMARCReport(
            domain_id=domain.id,
            report_id="123456789",
            org_name="Google",
            begin_date=1597449600,
            end_date=1597535999,
            source_email="noreply-dmarc-support@google.com",
            policy="none",
            adkim="r",
            aspf="r",
            percentage=100,
        )

        db_session.add(report)
        db_session.commit()
        db_session.refresh(report)

        assert report.id is not None
        assert report.domain_id == domain.id
        assert report.report_id == "123456789"
        assert report.org_name == "Google"
        assert report.begin_date == 1597449600
        assert report.policy == "none"

    def test_report_records_relationship(self, db_session: Session):
        """Test the relationship between reports and records"""
        # Create domain and report
        domain = Domain(name="example.com", active=True)
        db_session.add(domain)
        db_session.commit()

        report = DMARCReport(
            domain_id=domain.id,
            report_id="123456789",
            org_name="Google",
            begin_date=1597449600,
            end_date=1597535999,
            source_email="noreply-dmarc-support@google.com",
        )
        db_session.add(report)
        db_session.commit()

        # Create records for the report
        record1 = ReportRecord(
            report_id=report.id,
            source_ip="203.0.113.1",
            count=2,
            disposition="none",
            dkim="pass",
            spf="fail",
            header_from="example.com",
            envelope_from=None,
        )

        record2 = ReportRecord(
            report_id=report.id,
            source_ip="203.0.113.2",
            count=5,
            disposition="none",
            dkim="pass",
            spf="pass",
            header_from="example.com",
            envelope_from=None,
        )

        db_session.add_all([record1, record2])
        db_session.commit()

        # Query the report and check its records
        report = db_session.query(DMARCReport).filter_by(report_id="123456789").first()
        assert report is not None
        assert len(report.records) == 2
        assert report.records[0].source_ip in ["203.0.113.1", "203.0.113.2"]
        assert report.records[1].source_ip in ["203.0.113.1", "203.0.113.2"]
