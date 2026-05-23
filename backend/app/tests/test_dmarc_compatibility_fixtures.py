import base64
import email
import gzip
import io
import zipfile
from email import encoders as email_encoders
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.models.report import DMARCReport
from app.services.dmarc_parser import DMARCParser
from app.services.gmail_client import GmailClient
from app.services.imap_client import IMAPClient
from app.tests.test_data import DMARC_COMPATIBILITY_FIXTURES, load_dmarc_fixture


def _fixture_id(fixture: dict) -> str:
    return fixture["id"]


def _fixture_bytes(fixture: dict) -> bytes:
    return load_dmarc_fixture(fixture["filename"]).encode("utf-8")


def _zip_xml(xml_content: bytes, filename: str = "report.xml") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(filename, xml_content)
    return buf.getvalue()


def _make_mime_attachment(filename: str, content: bytes, content_type: str) -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = "DMARC aggregate report"
    msg["From"] = "reports@example.test"
    msg["To"] = "dmarc@example.test"
    msg.attach(MIMEText("DMARC report attached.", "plain"))

    part = MIMEApplication(content, Name=filename)
    part["Content-Disposition"] = f'attachment; filename="{filename}"'
    part.set_type(content_type)
    msg.attach(part)
    return msg.as_bytes()


def _make_gmail_raw_attachment(filename: str, content: bytes) -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = "DMARC aggregate report"
    msg["From"] = "reports@example.test"
    msg["To"] = "dmarc@example.test"
    msg.attach(MIMEText("DMARC report attached.", "plain"))

    part = MIMEBase("application", "zip")
    part.set_payload(content)
    email_encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(part)
    return msg.as_bytes()


def _make_imap_client(db_session) -> IMAPClient:
    with patch("app.services.imap_client.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            IMAP_SERVER="imap.example.test",
            IMAP_PORT=993,
            IMAP_USERNAME="dmarc@example.test",
            IMAP_PASSWORD="password",
        )
        return IMAPClient(db=db_session)


def _make_gmail_client(db_session) -> GmailClient:
    with patch("app.services.gmail_client.Credentials") as mock_credentials_class:
        credentials = MagicMock()
        credentials.token = "access-token"
        credentials.refresh_token = "refresh-token"
        credentials.expired = False
        mock_credentials_class.return_value = credentials
        return GmailClient(
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            db=db_session,
        )


def _assert_expected_report(report: dict, fixture: dict) -> None:
    assert report["domain"] == fixture["domain"]
    assert report["report_id"] == fixture["report_id"]
    assert report["variant"] == fixture["variant"]
    assert report["summary"]["total_count"] == fixture["total_count"]

    for key, value in fixture.get("policy", {}).items():
        assert report["policy"][key] == value


def _assert_persisted_report(db_session, fixture: dict) -> DMARCReport:
    db_session.flush()
    report = db_session.query(DMARCReport).filter_by(report_id=fixture["report_id"]).one()
    assert report.domain.name == fixture["domain"]
    assert report.report_variant == fixture["variant"]
    assert sum(record.count for record in report.records) == fixture["total_count"]
    return report


@pytest.mark.parametrize("fixture", DMARC_COMPATIBILITY_FIXTURES, ids=_fixture_id)
def test_aggregate_compatibility_fixtures_parse_xml_zip_and_gzip(fixture):
    xml_bytes = _fixture_bytes(fixture)

    xml_report = DMARCParser.parse_file(xml_bytes, fixture["filename"])
    zip_report = DMARCParser.parse_file(_zip_xml(xml_bytes), fixture["filename"] + ".zip")
    gzip_report = DMARCParser.parse_file(gzip.compress(xml_bytes), fixture["filename"] + ".gz")

    for report in (xml_report, zip_report, gzip_report):
        _assert_expected_report(report, fixture)


@pytest.mark.parametrize("fixture", DMARC_COMPATIBILITY_FIXTURES, ids=_fixture_id)
def test_aggregate_compatibility_fixtures_import_via_upload(
    client: TestClient, db_session, fixture
):
    zip_bytes = _zip_xml(_fixture_bytes(fixture), fixture["filename"])

    response = client.post(
        "/api/v1/reports/upload",
        files={"file": (fixture["filename"] + ".zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 200
    _assert_persisted_report(db_session, fixture)

    reports = client.get(f"/api/v1/domains/{fixture['domain']}/reports")
    assert reports.status_code == 200
    assert reports.json()["reports"][0]["id"] == fixture["report_id"]

    export = client.get(f"/api/v1/domains/{fixture['domain']}/reports/export")
    assert export.status_code == 200
    assert fixture["report_id"] in export.text
    assert "report_variant" in export.text


@pytest.mark.parametrize("fixture", DMARC_COMPATIBILITY_FIXTURES, ids=_fixture_id)
def test_aggregate_compatibility_fixtures_import_via_imap(db_session, fixture):
    client = _make_imap_client(db_session)
    zip_bytes = _zip_xml(_fixture_bytes(fixture), fixture["filename"])
    raw_message = _make_mime_attachment(fixture["filename"] + ".zip", zip_bytes, "application/zip")
    msg = email.message_from_bytes(raw_message)
    stats = {"processed": 0, "reports_found": 0, "errors": []}

    count = client._process_attachments(msg, stats, message_id="imap-" + fixture["id"])

    assert count == 1
    assert stats["details"][0]["status"] == "imported"
    assert stats["details"][0]["report_id"] == fixture["report_id"]
    _assert_persisted_report(db_session, fixture)


@pytest.mark.parametrize("fixture", DMARC_COMPATIBILITY_FIXTURES, ids=_fixture_id)
def test_aggregate_compatibility_fixtures_import_via_gmail(db_session, fixture):
    client = _make_gmail_client(db_session)
    zip_bytes = _zip_xml(_fixture_bytes(fixture), fixture["filename"])
    raw_message = _make_gmail_raw_attachment(fixture["filename"] + ".zip", zip_bytes)
    msg = email.message_from_bytes(raw_message)
    stats = {"reports_found": 0, "errors": []}

    count = client._process_attachments(msg, stats, message_id="gmail-" + fixture["id"])

    assert count == 1
    assert stats["details"][0]["status"] == "imported"
    assert stats["details"][0]["report_id"] == fixture["report_id"]
    _assert_persisted_report(db_session, fixture)


def test_gmail_fixture_email_shape_matches_api_raw_encoding():
    """The fixture MIME shape can be decoded from Gmail's raw message payload form."""
    fixture = DMARC_COMPATIBILITY_FIXTURES[2]
    zip_bytes = _zip_xml(_fixture_bytes(fixture), fixture["filename"])
    encoded = base64.urlsafe_b64encode(
        _make_gmail_raw_attachment(fixture["filename"] + ".zip", zip_bytes)
    )

    decoded = base64.urlsafe_b64decode(encoded)
    msg = email.message_from_bytes(decoded)

    assert msg["Subject"] == "DMARC aggregate report"
    assert any(part.get_filename() == fixture["filename"] + ".zip" for part in msg.walk())
