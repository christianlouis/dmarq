import base64
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.models.report import DMARCReport

MINIMAL_DMARC_XML = b"""\
<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Webhook Test</org_name>
    <email>dmarc@example.com</email>
    <report_id>webhook-001</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>webhook.example</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>1.2.3.4</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>webhook.example</header_from>
    </identifiers>
  </record>
</feedback>
"""


def _raw_email_with_report() -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = "DMARC report"
    part = MIMEApplication(MINIMAL_DMARC_XML, _subtype="xml")
    part.add_header("Content-Disposition", "attachment", filename="report.xml")
    msg.attach(part)
    return msg.as_bytes()


def _raw_email_with_attachment(
    filename: str | None,
    content: bytes,
    subtype: str = "octet-stream",
    subject: str = "DMARC report",
) -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg.attach(MIMEText("attached"))
    part = MIMEApplication(content, _subtype=subtype)
    if filename is not None:
        part.add_header("Content-Disposition", "attachment", filename=filename)
    else:
        part.add_header("Content-Disposition", "attachment")
    msg.attach(part)
    return msg.as_bytes()


def _set_webhook_secret(monkeypatch, value="test-webhook-secret"):
    monkeypatch.setenv("WEBHOOK_SECRET", value)
    get_settings.cache_clear()
    return value


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    yield
    get_settings.cache_clear()


def test_webhook_requires_configured_secret(client: TestClient, monkeypatch):
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    get_settings.cache_clear()

    response = client.post(
        "/api/v1/webhook/email",
        json={"raw_email": base64.b64encode(_raw_email_with_report()).decode("ascii")},
    )

    assert response.status_code == 503


def test_webhook_rejects_invalid_secret(client: TestClient, monkeypatch):
    _set_webhook_secret(monkeypatch)

    response = client.post(
        "/api/v1/webhook/email",
        headers={"X-Webhook-Secret": "wrong"},
        json={"raw_email": base64.b64encode(_raw_email_with_report()).decode("ascii")},
    )

    assert response.status_code == 401


def test_webhook_imports_base64_email(client: TestClient, db_session, monkeypatch):
    secret = _set_webhook_secret(monkeypatch)

    response = client.post(
        "/api/v1/webhook/email",
        headers={"X-Webhook-Secret": secret},
        json={"raw_email": base64.b64encode(_raw_email_with_report()).decode("ascii")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["reports_found"] == 1
    assert data["imported"] == 1
    assert db_session.query(DMARCReport).count() == 1


def test_webhook_raw_email_marks_duplicate(client: TestClient, monkeypatch):
    secret = _set_webhook_secret(monkeypatch)
    raw_email = _raw_email_with_report()

    first = client.post(
        "/api/v1/webhook/email/raw",
        headers={"X-Webhook-Secret": secret},
        content=raw_email,
    )
    second = client.post(
        "/api/v1/webhook/email/raw",
        headers={"X-Webhook-Secret": secret},
        content=raw_email,
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["duplicates"] == 1


def test_webhook_rejects_invalid_base64(client: TestClient, monkeypatch):
    secret = _set_webhook_secret(monkeypatch)

    response = client.post(
        "/api/v1/webhook/email",
        headers={"X-Webhook-Secret": secret},
        json={"raw_email": "not-base64"},
    )

    assert response.status_code == 400


def test_webhook_uses_payload_subject_fallback(client: TestClient, monkeypatch):
    secret = _set_webhook_secret(monkeypatch)
    raw_email = _raw_email_with_attachment("notes.txt", b"ignored")

    response = client.post(
        "/api/v1/webhook/email",
        headers={"X-Webhook-Secret": secret},
        json={
            "raw_email": base64.b64encode(raw_email).decode("ascii"),
            "subject": "Worker subject",
        },
    )

    assert response.status_code == 200
    assert response.json()["subject"] == "Worker subject"


def test_webhook_decodes_encoded_subject(client: TestClient, monkeypatch):
    secret = _set_webhook_secret(monkeypatch)
    raw_email = _raw_email_with_attachment(
        "notes.txt",
        b"ignored",
        subject=Header("DMARC r\u00e9sum\u00e9", "utf-8").encode(),
    )

    response = client.post(
        "/api/v1/webhook/email/raw",
        headers={"X-Webhook-Secret": secret},
        content=raw_email,
    )

    assert response.status_code == 200
    assert response.json()["subject"] == "DMARC r\u00e9sum\u00e9"


@pytest.mark.parametrize(
    "filename,content", [(None, b"ignored"), ("notes.txt", b"ignored"), ("empty.xml", b"")]
)
def test_webhook_ignores_non_report_attachments(client: TestClient, monkeypatch, filename, content):
    secret = _set_webhook_secret(monkeypatch)

    response = client.post(
        "/api/v1/webhook/email/raw",
        headers={"X-Webhook-Secret": secret},
        content=_raw_email_with_attachment(filename, content),
    )

    assert response.status_code == 200
    assert response.json()["reports_found"] == 0


def test_webhook_records_attachment_errors(client: TestClient, monkeypatch):
    secret = _set_webhook_secret(monkeypatch)

    response = client.post(
        "/api/v1/webhook/email/raw",
        headers={"X-Webhook-Secret": secret},
        content=_raw_email_with_attachment("bad.xml", b"not xml", "xml"),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["reports_found"] == 0
    assert data["errors"] == ["bad.xml"]


def test_webhook_rolls_back_on_unhandled_processing_error(
    client: TestClient, db_session, monkeypatch
):
    secret = _set_webhook_secret(monkeypatch)

    with patch(
        "app.api.api_v1.endpoints.webhook.email.message_from_bytes",
        side_effect=RuntimeError("parse failed"),
    ):
        response = client.post(
            "/api/v1/webhook/email/raw",
            headers={"X-Webhook-Secret": secret},
            content=b"bad",
        )

    assert response.status_code == 400
    assert db_session.is_active


def test_webhook_preserves_http_exceptions(client: TestClient, monkeypatch):
    secret = _set_webhook_secret(monkeypatch)

    with patch(
        "app.api.api_v1.endpoints.webhook._process_email_attachments",
        side_effect=HTTPException(status_code=418, detail="teapot"),
    ):
        response = client.post(
            "/api/v1/webhook/email/raw",
            headers={"X-Webhook-Secret": secret},
            content=b"Subject: DMARC\r\n\r\nbody",
        )

    assert response.status_code == 418
