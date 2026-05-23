import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.api.api_v1.endpoints import forensics as forensics_endpoint
from app.models.report import ForensicReport
from app.services.forensic_parser import ForensicParser
from app.services.forensic_persistence import (
    forensic_report_exists,
    forensic_report_to_dict,
    save_forensic_report,
)
from app.tests.test_forensic_parser import SAMPLE_FORENSIC_EMAIL


def test_upload_forensic_report_persists_redacted_metadata(authed_client, db_session):
    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["domain"] == "example.com"
    assert db_session.query(ForensicReport).count() == 1
    report = db_session.query(ForensicReport).one()
    assert report.original_mail_from == "al***@example.com"
    assert "original-message@example.com" not in report.original_message_id
    assert not report.original_message_id.startswith("<")


def test_upload_forensic_report_rejects_duplicates(authed_client):
    files = {"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")}
    assert authed_client.post("/api/v1/forensics/upload", files=files).status_code == 200

    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )

    assert response.status_code == 409


def test_list_and_detail_forensic_reports(authed_client):
    authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )

    list_response = authed_client.get("/api/v1/forensics?domain=example.com")
    assert list_response.status_code == 200
    list_data = list_response.json()
    assert list_data["total"] == 1
    item = list_data["reports"][0]
    assert item["source_ip"] == "203.0.113.8"
    assert item["auth_failure"] == "dkim"
    assert item["original_message_id"] != "<original-message@example.com>"

    detail_response = authed_client.get(f"/api/v1/forensics/{item['id']}")
    assert detail_response.status_code == 200
    assert detail_response.json()["reported_domain"] == "example.com"


def test_upload_forensic_report_rejects_aggregate_xml(authed_client):
    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.xml", b"<feedback />", "application/xml")},
    )

    assert response.status_code == 400


def test_upload_forensic_report_rejects_empty_file(authed_client):
    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", b"", "message/rfc822")},
    )

    assert response.status_code == 400


def test_validate_upload_rejects_missing_name_and_large_file():
    missing_name = type("Upload", (), {"filename": ""})()
    too_large = type("Upload", (), {"filename": "report.eml"})()

    with pytest.raises(HTTPException) as missing:
        forensics_endpoint._validate_upload(missing_name, b"content")
    assert missing.value.status_code == 400

    with pytest.raises(HTTPException) as large:
        forensics_endpoint._validate_upload(
            too_large,
            b"x" * (forensics_endpoint.MAX_FORENSIC_REPORT_SIZE + 1),
        )
    assert large.value.status_code == 413


def test_upload_forensic_report_rejects_invalid_email(authed_client):
    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", b"Subject: hello\r\n\r\nbody", "message/rfc822")},
    )

    assert response.status_code == 400


def test_upload_forensic_report_handles_save_duplicate_race(authed_client, monkeypatch):
    parsed = ForensicParser.parse_bytes(SAMPLE_FORENSIC_EMAIL)
    row = ForensicReport(report_id=parsed["report_id"], reported_domain=parsed["reported_domain"])
    monkeypatch.setattr(forensics_endpoint, "forensic_report_exists", lambda *_args: False)
    monkeypatch.setattr(
        forensics_endpoint,
        "save_forensic_report",
        lambda *_args: (row, False),
    )

    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )

    assert response.status_code == 409


def test_upload_forensic_report_unexpected_error_returns_500(authed_client, monkeypatch):
    monkeypatch.setattr(
        forensics_endpoint.ForensicParser,
        "parse_bytes",
        lambda _content: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )

    assert response.status_code == 500


def test_forensic_detail_returns_404(authed_client):
    response = authed_client.get("/api/v1/forensics/999")

    assert response.status_code == 404


def test_save_forensic_report_duplicate_and_invalid_domain_paths(db_session):
    parsed = ForensicParser.parse_bytes(SAMPLE_FORENSIC_EMAIL)
    parsed["feedback_headers"] = {"identity_alignment": "dkim"}
    first, created = save_forensic_report(db_session, parsed)
    second, duplicate_created = save_forensic_report(db_session, parsed)

    assert created is True
    assert duplicate_created is False
    assert first.id == second.id
    assert forensic_report_exists(db_session, parsed["report_id"]) is True
    assert forensic_report_exists(db_session, "") is False
    assert forensic_report_to_dict(first)["feedback_headers"] == {"identity_alignment": "dkim"}

    first.feedback_headers = "{not-json"
    assert forensic_report_to_dict(first)["feedback_headers"] == {}

    missing_id = dict(parsed)
    missing_id["report_id"] = " "
    with pytest.raises(ValueError, match="report_id"):
        save_forensic_report(db_session, missing_id)

    invalid = dict(parsed)
    invalid["report_id"] = "ruf-invalid-domain"
    invalid["reported_domain"] = "bad domain"
    row, invalid_created = save_forensic_report(db_session, invalid)
    assert invalid_created is True
    assert row.domain_id is None


def test_save_forensic_report_reraises_unexpected_integrity_errors(db_session, monkeypatch):
    parsed = ForensicParser.parse_bytes(SAMPLE_FORENSIC_EMAIL)
    parsed["report_id"] = "ruf-race-without-existing-row"
    parsed["reported_domain"] = ""

    def raise_integrity_error():
        raise IntegrityError("insert", {}, Exception("unique"))

    monkeypatch.setattr(db_session, "flush", raise_integrity_error)

    with pytest.raises(IntegrityError):
        save_forensic_report(db_session, parsed)
