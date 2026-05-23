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


def test_upload_forensic_report_rejects_invalid_email(authed_client):
    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", b"Subject: hello\r\n\r\nbody", "message/rfc822")},
    )

    assert response.status_code == 400


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

    invalid = dict(parsed)
    invalid["report_id"] = "ruf-invalid-domain"
    invalid["reported_domain"] = "bad domain"
    row, invalid_created = save_forensic_report(db_session, invalid)
    assert invalid_created is True
    assert row.domain_id is None
