from app.models.report import ForensicReport
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
