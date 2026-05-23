import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.api.api_v1.endpoints import forensics as forensics_endpoint
from app.models.report import ForensicReport
from app.services.forensic_parser import ForensicParser
from app.services.forensic_persistence import (
    forensic_report_exists,
    forensic_report_to_dict,
    save_forensic_report,
)
from app.services.forensic_redaction import ForensicRedactionPolicy
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


def test_list_forensic_reports_filters_failure_fields(authed_client, db_session):
    first = ForensicParser.parse_bytes(SAMPLE_FORENSIC_EMAIL)
    second = dict(first)
    second.update(
        {
            "report_id": "ruf-spf-filter-test",
            "reported_domain": "example.net",
            "source_ip": "198.51.100.77",
            "auth_failure": "spf",
            "delivery_result": "none",
        }
    )
    save_forensic_report(db_session, first)
    save_forensic_report(db_session, second)
    db_session.commit()

    response = authed_client.get(
        "/api/v1/forensics?auth_failure=spf&delivery_result=none&source_ip=198.51.100.77"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["reports"][0]["report_id"] == "ruf-spf-filter-test"


def test_forensic_analysis_groups_failure_samples(authed_client, db_session):
    dkim = ForensicParser.parse_bytes(SAMPLE_FORENSIC_EMAIL)
    spf = dict(dkim)
    spf.update(
        {
            "report_id": "ruf-spf-analysis-test",
            "reported_domain": "example.com",
            "source_ip": "198.51.100.23",
            "auth_failure": "spf",
            "delivery_result": "quarantine",
            "authentication_results": (
                "mx.example.net; dkim=pass header.d=example.com; "
                "spf=fail smtp.mailfrom=example.com; dmarc=fail"
            ),
        }
    )
    save_forensic_report(db_session, dkim)
    save_forensic_report(db_session, spf)
    db_session.commit()

    response = authed_client.get("/api/v1/forensics/analysis?domain=example.com")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["priority_counts"]["high"] == 2
    assert data["failure_counts"]["dkim"] == 1
    assert data["failure_counts"]["spf"] == 1
    assert data["groups"][0]["priority"] == "high"
    assert "redacted headers and metadata only" in data["samples"][0]["privacy_note"]
    assert any("SPF" in action for action in data["samples"][0]["recommendations"])


def test_forensic_report_responses_include_sample_analysis(authed_client):
    authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )

    list_response = authed_client.get("/api/v1/forensics")

    assert list_response.status_code == 200
    item = list_response.json()["reports"][0]
    assert item["analysis"]["priority"] == "high"
    assert "DKIM" in item["analysis"]["diagnosis"]
    assert item["original_subject"] not in item["analysis"]["signals"]


def test_forensic_api_applies_configured_redaction_policy(authed_client, db_session):
    authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )
    authed_client.put("/api/v1/settings/forensics.redaction_mode", json={"value": "strict"})

    list_response = authed_client.get("/api/v1/forensics?domain=example.com")

    assert list_response.status_code == 200
    item = list_response.json()["reports"][0]
    assert item["original_mail_from"] == "[redacted-email]"
    assert item["source_email"] == "DMARC Reporter <[redacted-email]>"
    stored = db_session.query(ForensicReport).one()
    assert stored.original_mail_from == "al***@example.com"


def test_upload_forensic_report_uses_configured_redaction_policy(authed_client, db_session):
    authed_client.put("/api/v1/settings/forensics.redaction_mode", json={"value": "domain_only"})

    response = authed_client.post(
        "/api/v1/forensics/upload",
        files={"file": ("report.eml", SAMPLE_FORENSIC_EMAIL, "message/rfc822")},
    )

    assert response.status_code == 200
    report = db_session.query(ForensicReport).one()
    assert report.original_mail_from == "***@example.com"


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


def test_forensic_html_pages_render():
    from app.core.logto import SESSION_COOKIE, create_session_token  # noqa: PLC0415
    from app.main import app as main_app  # noqa: PLC0415

    cookies = {SESSION_COOKIE: create_session_token(user_id=1)}
    with TestClient(main_app) as c:
        list_response = c.get("/forensics", cookies=cookies)
        detail_response = c.get("/forensics/123", cookies=cookies)

    assert list_response.status_code == 200
    assert "Forensic Reports" in list_response.text
    assert "Authentication Failures" in list_response.text
    assert detail_response.status_code == 200
    assert "Forensic Investigation" in detail_response.text
    assert "Failure Sample Analysis" in detail_response.text


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
    strict = forensic_report_to_dict(
        first,
        redaction_policy=ForensicRedactionPolicy(mode="strict"),
    )
    assert strict["original_mail_from"] == "[redacted-email]"

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
