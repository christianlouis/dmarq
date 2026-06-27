import json
from types import SimpleNamespace

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints import tls_reports as tls_endpoint
from app.models.domain import Domain
from app.models.report import TLSReport, TLSReportFailure
from app.models.workspace import Workspace
from app.services.tls_report_parser import TLSReportParser
from app.services.tls_report_persistence import (
    save_tls_report,
    summarize_tls_reports,
    tls_report_exists,
)
from app.tests.test_tls_report_parser import SAMPLE_TLS_REPORT, sample_tls_report_bytes


def test_upload_tls_report_persists_policy_and_failure_details(authed_client, db_session):
    response = authed_client.post(
        "/api/v1/tls-reports/upload",
        files={"file": ("tls-report.json", sample_tls_report_bytes(), "application/json")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["policies_created"] == 1
    assert data["policies_skipped"] == 0
    assert "message bodies" in data["privacy"]["not_stored"]

    report = db_session.query(TLSReport).one()
    assert report.policy_domain == "example.com"
    assert report.total_failure_sessions == 7
    assert db_session.query(Domain).filter(Domain.name == "example.com").count() == 1
    failure = db_session.query(TLSReportFailure).one()
    assert failure.result_type == "certificate-expired"
    assert failure.failed_session_count == 7


def test_upload_tls_report_marks_duplicates_without_double_counting(authed_client, db_session):
    files = {"file": ("tls-report.json", sample_tls_report_bytes(), "application/json")}
    assert authed_client.post("/api/v1/tls-reports/upload", files=files).status_code == 200

    response = authed_client.post(
        "/api/v1/tls-reports/upload",
        files={"file": ("tls-report.json", sample_tls_report_bytes(), "application/json")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["duplicate"] is True
    assert data["policies_created"] == 0
    assert data["policies_skipped"] == 1
    assert db_session.query(TLSReport).count() == 1


def test_tls_report_summary_groups_failures_and_domains(authed_client):
    authed_client.post(
        "/api/v1/tls-reports/upload",
        files={"file": ("tls-report.json", sample_tls_report_bytes(), "application/json")},
    )

    response = authed_client.get("/api/v1/tls-reports/summary?domain=example.com&days=30")

    assert response.status_code == 200
    data = response.json()
    assert data["totals"]["reports"] == 1
    assert data["totals"]["failed_sessions"] == 7
    assert data["top_failures"][0]["result_type"] == "certificate-expired"
    assert data["top_failures"][0]["affected_domains"] == ["example.com"]
    assert data["affected_domains"][0]["failure_rate"] > 0
    assert "sender or recipient addresses" in data["privacy"]["not_stored"]


def test_tls_reports_respect_selected_workspace_header(authed_client, db_session):
    selected_workspace = Workspace(
        slug="selected-tls",
        name="Selected TLS",
        active=True,
    )
    db_session.add(selected_workspace)
    db_session.flush()
    selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}
    selected_report = json.loads(json.dumps(SAMPLE_TLS_REPORT))
    selected_report["policies"][0]["policy"]["policy-domain"] = "Selected.example."
    selected_report["policies"][0]["policy"]["mx-host"] = ["mx.selected.example"]
    selected_bytes = sample_tls_report_bytes(selected_report)

    default_upload = authed_client.post(
        "/api/v1/tls-reports/upload",
        files={"file": ("tls-report.json", sample_tls_report_bytes(), "application/json")},
    )
    selected_upload = authed_client.post(
        "/api/v1/tls-reports/upload",
        headers=selected_header,
        files={"file": ("tls-report.json", selected_bytes, "application/json")},
    )

    assert default_upload.status_code == 200
    assert selected_upload.status_code == 200
    assert db_session.query(TLSReport).count() == 2

    default_list = authed_client.get("/api/v1/tls-reports?domain=example.com")
    selected_list = authed_client.get(
        "/api/v1/tls-reports?domain=selected.example",
        headers=selected_header,
    )
    default_summary = authed_client.get("/api/v1/tls-reports/summary?domain=example.com")
    selected_summary = authed_client.get(
        "/api/v1/tls-reports/summary?domain=selected.example",
        headers=selected_header,
    )

    assert default_list.status_code == 200
    assert default_list.json()["total"] == 1
    assert selected_list.status_code == 200
    assert selected_list.json()["total"] == 1
    assert selected_list.json()["reports"][0]["domain"] == "selected.example"
    assert default_summary.status_code == 200
    assert default_summary.json()["totals"]["reports"] == 1
    assert selected_summary.status_code == 200
    assert selected_summary.json()["totals"]["reports"] == 1


def test_list_tls_reports_filters_by_domain(authed_client, db_session):
    parsed = TLSReportParser.parse_file(sample_tls_report_bytes(), "tls-report.json")
    second = dict(parsed)
    second["report_id"] = "tls-report-second"
    second["policies"] = [dict(parsed["policies"][0], policy_domain="example.net")]
    save_tls_report(db_session, parsed)
    save_tls_report(db_session, second)
    db_session.commit()

    response = authed_client.get("/api/v1/tls-reports?domain=example.net")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["reports"][0]["policy_domain"] == "example.net"


def test_demo_mode_tls_endpoints_return_synthetic_data(authed_client, monkeypatch):
    monkeypatch.setattr(
        tls_endpoint,
        "get_settings",
        lambda: SimpleNamespace(DEMO_MODE=True),
    )

    list_response = authed_client.get("/api/v1/tls-reports?domain=dmarq.org&page_size=5")
    assert list_response.status_code == 200
    list_data = list_response.json()
    assert list_data["total"] > 0
    assert len(list_data["reports"]) <= 5
    assert list_data["privacy"]["not_stored"]

    summary_response = authed_client.get("/api/v1/tls-reports/summary?domain=dmarq.org&days=14")
    assert summary_response.status_code == 200
    summary_data = summary_response.json()
    assert summary_data["totals"]["reports"] > 0
    assert summary_data["top_failures"]


def test_tls_report_summary_empty_response_includes_privacy_controls(authed_client):
    response = authed_client.get("/api/v1/tls-reports/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["totals"]["reports"] == 0
    assert data["top_failures"] == []
    assert "raw uploaded attachments" in data["privacy"]["not_stored"]


def test_tls_report_persistence_helpers(db_session):
    parsed = TLSReportParser.parse_file(sample_tls_report_bytes(), "tls-report.json")

    result = save_tls_report(db_session, parsed)
    db_session.commit()

    assert result["created"] == 1
    assert tls_report_exists(db_session, "tls-report-20260520", "example.com")
    summary = summarize_tls_reports(db_session, domain="example.com")
    assert summary["totals"]["successful_sessions"] == 125


def test_upload_tls_report_rejects_invalid_file_type(authed_client):
    response = authed_client.post(
        "/api/v1/tls-reports/upload",
        files={"file": ("tls-report.txt", sample_tls_report_bytes(), "text/plain")},
    )

    assert response.status_code == 400


def test_validate_upload_rejects_missing_name_and_large_file():
    missing_name = type("Upload", (), {"filename": ""})()
    too_large = type("Upload", (), {"filename": "report.json"})()

    try:
        tls_endpoint._validate_upload(missing_name, b"content")
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("Expected missing filename to be rejected")

    try:
        tls_endpoint._validate_upload(
            too_large,
            b"x" * (tls_endpoint.MAX_TLS_REPORT_SIZE + 1),
        )
    except HTTPException as exc:
        assert exc.status_code == 413
    else:
        raise AssertionError("Expected large file to be rejected")


def test_tls_report_html_page_renders():
    from app.core.logto import SESSION_COOKIE, create_session_token  # noqa: PLC0415
    from app.main import app as main_app  # noqa: PLC0415

    cookies = {SESSION_COOKIE: create_session_token(user_id=1)}
    with TestClient(main_app) as client:
        response = client.get("/tls-reports", cookies=cookies)

    assert response.status_code == 200
    assert "TLS Reports" in response.text
