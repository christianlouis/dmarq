import gzip
import io
import json
import zipfile

import pytest

from app.services.tls_report_parser import TLSReportParser

SAMPLE_TLS_REPORT = {
    "organization-name": "Example Reporter",
    "date-range": {
        "start-datetime": "2026-05-20T00:00:00Z",
        "end-datetime": "2026-05-20T23:59:59Z",
    },
    "contact-info": "tlsrpt@example-reporter.test",
    "report-id": "tls-report-20260520",
    "policies": [
        {
            "policy": {
                "policy-type": "sts",
                "policy-string": ["version: STSv1", "mode: enforce"],
                "policy-domain": "Example.com.",
                "mx-host": ["mx.example.com"],
            },
            "summary": {
                "total-successful-session-count": 125,
                "total-failure-session-count": 7,
            },
            "failure-details": [
                {
                    "result-type": "certificate-expired",
                    "sending-mta-ip": "203.0.113.9",
                    "receiving-mx-hostname": "MX.EXAMPLE.COM",
                    "failed-session-count": 7,
                    "failure-reason-code": "tls",
                    "additional-information": "certificate expired",
                }
            ],
        }
    ],
}


def sample_tls_report_bytes(report=None):
    return json.dumps(report or SAMPLE_TLS_REPORT).encode("utf-8")


def test_parse_tls_report_json_normalizes_policy_and_failures():
    parsed = TLSReportParser.parse_file(sample_tls_report_bytes(), "tls-report.json")

    assert parsed["report_id"] == "tls-report-20260520"
    assert parsed["org_name"] == "Example Reporter"
    assert parsed["begin_date"].isoformat() == "2026-05-20T00:00:00"
    assert parsed["policies"][0]["policy_domain"] == "example.com"
    assert parsed["policies"][0]["policy_type"] == "sts"
    assert parsed["policies"][0]["total_failure_sessions"] == 7
    assert parsed["policies"][0]["failures"][0]["result_type"] == "certificate-expired"
    assert parsed["policies"][0]["failures"][0]["receiving_mx_hostname"] == "mx.example.com"


def test_parse_tls_report_gzip():
    compressed = gzip.compress(sample_tls_report_bytes())

    parsed = TLSReportParser.parse_file(compressed, "tls-report.json.gz")

    assert parsed["report_id"] == "tls-report-20260520"
    assert parsed["policies"][0]["total_successful_sessions"] == 125


def test_parse_tls_report_zip():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("nested/tls-report.json", sample_tls_report_bytes())

    parsed = TLSReportParser.parse_file(archive.getvalue(), "tls-report.zip")

    assert parsed["policies"][0]["policy_domain"] == "example.com"


def test_parse_tls_report_rejects_zip_without_json_file():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("nested/readme.txt", "not a TLS report")

    with pytest.raises(ValueError, match="Could not extract JSON content"):
        TLSReportParser.parse_file(archive.getvalue(), "tls-report.zip")


def test_parse_tls_report_rejects_bad_zip_file():
    with pytest.raises(ValueError, match="Could not extract JSON content"):
        TLSReportParser.parse_file(b"not a zip file", "tls-report.zip")


def test_parse_tls_report_generates_stable_id_when_missing():
    report = dict(SAMPLE_TLS_REPORT)
    report.pop("report-id")

    parsed = TLSReportParser.parse_file(sample_tls_report_bytes(report), "tls-report.json")

    assert parsed["report_id"].startswith("tlsrpt-")
    assert len(parsed["report_id"]) == 31


def test_parse_tls_report_rejects_missing_policies():
    with pytest.raises(ValueError, match="policy-domain"):
        TLSReportParser.parse_file(b'{"policies":[]}', "tls-report.json")


def test_parse_tls_report_rejects_invalid_extension():
    with pytest.raises(ValueError, match="Invalid TLS report file type"):
        TLSReportParser.parse_file(sample_tls_report_bytes(), "tls-report.txt")
