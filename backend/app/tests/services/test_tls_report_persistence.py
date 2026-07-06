from datetime import datetime
from importlib import import_module

import_module("app.models.dns_cache")
import_module("app.models.mail_source_backfill")

# Import all models to ensure SQLAlchemy's mapper registries are properly populated
import_module("app.models.mail_source_import")
import_module("app.models.organization")
import_module("app.models.webhook")
import_module("app.models.workspace_access")
from app.models.domain import Domain
from app.models.report import TLSReport, TLSReportFailure
from app.services.tls_report_persistence import tls_report_to_dict


def test_tls_report_to_dict_fully_populated():
    """Test that a fully populated TLSReport serializes correctly."""
    domain = Domain(name="example.com")
    now = datetime(2023, 1, 1, 12, 0, 0)

    failure = TLSReportFailure(
        result_type="certificate-expired",
        failed_session_count=5,
        sending_mta_ip="192.0.2.1",
        receiving_mx_hostname="mx.example.com",
        receiving_mx_helo="mx.example.com",
        receiving_ip="198.51.100.1",
        failure_reason_code="tls",
        additional_information="Expired cert",
    )

    report = TLSReport(
        id=1,
        report_id="test-report-1",
        domain=domain,
        org_name="Test Org",
        contact_info="test@example.com",
        policy_domain="example.com",
        policy_type="sts",
        begin_date=now,
        end_date=now,
        total_successful_sessions=10,
        total_failure_sessions=5,
        processed_at=now,
        failures=[failure],
    )

    result = tls_report_to_dict(report)

    assert result == {
        "id": 1,
        "report_id": "test-report-1",
        "domain": "example.com",
        "org_name": "Test Org",
        "contact_info": "test@example.com",
        "policy_domain": "example.com",
        "policy_type": "sts",
        "begin_date": "2023-01-01T12:00:00",
        "end_date": "2023-01-01T12:00:00",
        "total_successful_sessions": 10,
        "total_failure_sessions": 5,
        "processed_at": "2023-01-01T12:00:00",
        "failures": [
            {
                "result_type": "certificate-expired",
                "failed_session_count": 5,
                "sending_mta_ip": "192.0.2.1",
                "receiving_mx_hostname": "mx.example.com",
                "receiving_mx_helo": "mx.example.com",
                "receiving_ip": "198.51.100.1",
                "failure_reason_code": "tls",
                "additional_information": "Expired cert",
            }
        ],
    }


def test_tls_report_to_dict_sparse():
    """Test that a sparse TLSReport (missing optional fields) serializes correctly."""
    report = TLSReport(
        id=2,
        report_id="test-report-2",
        domain=None,
        org_name=None,
        contact_info=None,
        policy_domain="sparse.example.com",
        policy_type=None,
        begin_date=None,
        end_date=None,
        total_successful_sessions=0,
        total_failure_sessions=0,
        processed_at=None,
        failures=[],
    )

    result = tls_report_to_dict(report)

    assert result == {
        "id": 2,
        "report_id": "test-report-2",
        "domain": "sparse.example.com",
        "org_name": None,
        "contact_info": None,
        "policy_domain": "sparse.example.com",
        "policy_type": None,
        "begin_date": None,
        "end_date": None,
        "total_successful_sessions": 0,
        "total_failure_sessions": 0,
        "processed_at": None,
        "failures": [],
    }
