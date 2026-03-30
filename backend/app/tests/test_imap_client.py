"""
Tests for IMAPClient service.

Covers connection testing, mailbox listing, email processing, attachment parsing,
and report fetching with mocked IMAP connections.
"""

import email
import imaplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from unittest.mock import MagicMock, patch
from zipfile import ZipFile

import pytest

from app.services.imap_client import IMAPClient
from app.services.report_store import ReportStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_DMARC_XML = b"""\
<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Test Org</org_name>
    <email>noreply@example.com</email>
    <report_id>abc-123</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
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
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
"""


def _make_zip_content(xml_bytes: bytes, filename: str = "report.xml") -> bytes:
    buf = BytesIO()
    with ZipFile(buf, "w") as zf:
        zf.writestr(filename, xml_bytes)
    return buf.getvalue()


def _make_email_with_attachment(
    filename: str = "dmarc-report.xml",
    content: bytes = MINIMAL_DMARC_XML,
    content_type: str = "application/xml",
    subject: str = "DMARC Report",
    from_addr: str = "noreply@example.com",
) -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg.attach(MIMEText("DMARC report attached."))
    part = MIMEApplication(content, Name=filename)
    part["Content-Disposition"] = f'attachment; filename="{filename}"'
    part.set_type(content_type)
    msg.attach(part)
    return msg.as_bytes()


# ---------------------------------------------------------------------------
# TestIMAPClientInit
# ---------------------------------------------------------------------------


class TestIMAPClientInit:
    def test_default_construction_with_missing_credentials(self):
        """Client can be instantiated even without configured settings."""
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER=None,
                IMAP_PORT=993,
                IMAP_USERNAME=None,
                IMAP_PASSWORD=None,
            )
            client = IMAPClient()
        assert client.server is None
        assert client.username is None

    def test_explicit_credentials_override_settings(self):
        """Explicit constructor arguments take precedence over settings."""
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="default.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="default@example.com",
                IMAP_PASSWORD="default-password",
            )
            client = IMAPClient(
                server="custom.example.com",
                port=143,
                username="user@example.com",
                password="secret",
                delete_emails=True,
            )
        assert client.server == "custom.example.com"
        assert client.port == 143
        assert client.username == "user@example.com"
        assert client.password == "secret"
        assert client.delete_emails is True

    def test_report_store_assigned(self):
        """IMAPClient stores a reference to the ReportStore singleton."""
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="imap.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="u",
                IMAP_PASSWORD="p",
            )
            client = IMAPClient()
        assert client.report_store is ReportStore.get_instance()


# ---------------------------------------------------------------------------
# TestListMailboxes
# ---------------------------------------------------------------------------


class TestListMailboxes:
    def _make_client(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="imap.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="u",
                IMAP_PASSWORD="p",
            )
            return IMAPClient()

    def test_parses_standard_mailbox_entry(self):
        client = self._make_client()
        raw = [b'(\\HasNoChildren) "/" INBOX']
        result = client._list_mailboxes(raw)
        assert "INBOX" in result

    def test_skips_non_bytes_entries(self):
        client = self._make_client()
        result = client._list_mailboxes(["not bytes", None])  # type: ignore[list-item]
        assert result == []

    def test_handles_malformed_bytes(self):
        client = self._make_client()
        # bytes that can't be decoded normally should be silently skipped
        result = client._list_mailboxes([b"short"])
        # Should not raise; may return empty or partial result
        assert isinstance(result, list)

    def test_multiple_mailboxes(self):
        client = self._make_client()
        raw = [
            b'(\\HasNoChildren) "/" INBOX',
            b'(\\HasNoChildren) "/" Sent',
            b'(\\HasNoChildren) "/" Trash',
        ]
        result = client._list_mailboxes(raw)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# TestTestConnection
# ---------------------------------------------------------------------------


class TestTestConnection:
    def _make_client(self, server="imap.example.com", username="u", password="p"):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER=server,
                IMAP_PORT=993,
                IMAP_USERNAME=username,
                IMAP_PASSWORD=password,
            )
            return IMAPClient()

    def test_returns_false_when_missing_credentials(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER=None,
                IMAP_PORT=993,
                IMAP_USERNAME=None,
                IMAP_PASSWORD=None,
            )
            client = IMAPClient()
        success, message, stats = client.test_connection()
        assert success is False
        assert "not fully configured" in message
        assert stats == {}

    def test_successful_connection(self):
        client = self._make_client()
        mock_mail = MagicMock()
        mock_mail.login.return_value = None
        mock_mail.list.return_value = ("OK", [b'(\\HasNoChildren) "/" INBOX'])
        mock_mail.select.return_value = ("OK", [b"10"])
        mock_mail.search.return_value = ("OK", [b"1 2 3"])

        with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
            success, message, stats = client.test_connection()

        assert success is True
        assert "successful" in message.lower()
        assert stats["message_count"] == 10
        assert "INBOX" in stats["available_mailboxes"]

    def test_connection_exception_returns_false(self):
        client = self._make_client()
        with patch("imaplib.IMAP4_SSL", side_effect=ConnectionRefusedError("refused")):
            success, message, stats = client.test_connection()
        assert success is False
        assert stats == {}

    def test_list_status_not_ok_returns_empty_mailboxes(self):
        client = self._make_client()
        mock_mail = MagicMock()
        mock_mail.login.return_value = None
        mock_mail.list.return_value = ("NO", [])
        mock_mail.select.return_value = ("OK", [b"0"])
        mock_mail.search.return_value = ("OK", [b""])

        with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
            success, message, stats = client.test_connection()

        assert success is True
        assert stats["available_mailboxes"] == []

    def test_select_not_ok_skips_message_count(self):
        client = self._make_client()
        mock_mail = MagicMock()
        mock_mail.login.return_value = None
        mock_mail.list.return_value = ("OK", [])
        mock_mail.select.return_value = ("NO", [])
        mock_mail.search.return_value = ("OK", [b""])

        with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
            success, message, stats = client.test_connection()

        assert success is True
        assert stats["message_count"] == 0


# ---------------------------------------------------------------------------
# TestIsDmarcReportEmail
# ---------------------------------------------------------------------------


class TestIsDmarcReportEmail:
    def _make_client(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="imap.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="u",
                IMAP_PASSWORD="p",
            )
            return IMAPClient()

    def _make_msg(self, subject="", from_addr="", has_xml_attachment=False):
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = from_addr
        if has_xml_attachment:
            part = MIMEApplication(b"<xml/>", Name="report.xml")
            part["Content-Disposition"] = 'attachment; filename="report.xml"'
            msg.attach(part)
        return msg

    def test_dmarc_keyword_in_subject(self):
        client = self._make_client()
        msg = self._make_msg(subject="DMARC Aggregate Report for example.com")
        assert client._is_dmarc_report_email(msg) is True

    def test_no_keywords_no_attachments(self):
        client = self._make_client()
        msg = self._make_msg(subject="Hello World", from_addr="friend@example.com")
        assert client._is_dmarc_report_email(msg) is False

    def test_dmarc_sender_matches(self):
        client = self._make_client()
        msg = self._make_msg(
            subject="Weekly report", from_addr="noreply@google.com"
        )
        assert client._is_dmarc_report_email(msg) is True

    def test_xml_attachment_matches(self):
        client = self._make_client()
        msg = self._make_msg(has_xml_attachment=True)
        assert client._is_dmarc_report_email(msg) is True


# ---------------------------------------------------------------------------
# TestDecodeEmailHeader
# ---------------------------------------------------------------------------


class TestDecodeEmailHeader:
    def _make_client(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="imap.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="u",
                IMAP_PASSWORD="p",
            )
            return IMAPClient()

    def test_plain_ascii_header(self):
        client = self._make_client()
        assert client._decode_email_header("Hello World") == "Hello World"

    def test_encoded_utf8_header(self):
        client = self._make_client()
        # "=?utf-8?b?..." encoded header
        encoded = "=?utf-8?b?RFNIQVJDIG9yZyBuYW1l?="
        result = client._decode_email_header(encoded)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# TestHasDmarcAttachments
# ---------------------------------------------------------------------------


class TestHasDmarcAttachments:
    def _make_client(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="imap.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="u",
                IMAP_PASSWORD="p",
            )
            return IMAPClient()

    @pytest.mark.parametrize(
        "filename",
        ["report.xml", "dmarc.zip", "report.gz", "report.gzip"],
    )
    def test_dmarc_filename_extensions(self, filename):
        client = self._make_client()
        msg = MIMEMultipart()
        part = MIMEApplication(b"data", Name=filename)
        part["Content-Disposition"] = f'attachment; filename="{filename}"'
        msg.attach(part)
        assert client._has_dmarc_attachments(msg) is True

    @pytest.mark.parametrize(
        "content_type",
        [
            "application/zip",
            "application/gzip",
            "application/x-gzip",
            "application/xml",
            "text/xml",
        ],
    )
    def test_dmarc_content_types(self, content_type):
        client = self._make_client()
        msg = MIMEMultipart()
        part = MIMEApplication(b"data")
        part["Content-Disposition"] = "attachment"
        part.set_type(content_type)
        msg.attach(part)
        assert client._has_dmarc_attachments(msg) is True

    def test_no_attachments_returns_false(self):
        client = self._make_client()
        msg = MIMEText("plain text body")
        assert client._has_dmarc_attachments(msg) is False


# ---------------------------------------------------------------------------
# TestProcessAttachments
# ---------------------------------------------------------------------------


class TestProcessAttachments:
    def _make_client(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="imap.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="u",
                IMAP_PASSWORD="p",
            )
            return IMAPClient()

    def test_processes_xml_attachment(self):
        client = self._make_client()
        msg = email.message_from_bytes(
            _make_email_with_attachment("report.xml", MINIMAL_DMARC_XML, "application/xml")
        )
        count = client._process_attachments(msg)
        assert count == 1

    def test_processes_zip_attachment(self):
        client = self._make_client()
        zip_content = _make_zip_content(MINIMAL_DMARC_XML, "report.xml")
        msg = email.message_from_bytes(
            _make_email_with_attachment("report.zip", zip_content, "application/zip")
        )
        count = client._process_attachments(msg)
        assert count == 1

    def test_bad_attachment_does_not_raise(self):
        client = self._make_client()
        msg = email.message_from_bytes(
            _make_email_with_attachment("report.xml", b"not xml at all")
        )
        # Should not raise; just returns 0
        count = client._process_attachments(msg)
        assert count == 0

    def test_no_attachments_returns_zero(self):
        client = self._make_client()
        msg = MIMEText("Just text, no attachments.")
        count = client._process_attachments(msg)
        assert count == 0


# ---------------------------------------------------------------------------
# TestProcessSingleEmail
# ---------------------------------------------------------------------------


class TestProcessSingleEmail:
    def _make_client(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER="imap.example.com",
                IMAP_PORT=993,
                IMAP_USERNAME="u",
                IMAP_PASSWORD="p",
            )
            return IMAPClient()

    def test_processes_valid_dmarc_email(self):
        client = self._make_client()
        raw = _make_email_with_attachment(
            "report.xml",
            MINIMAL_DMARC_XML,
            "application/xml",
            subject="DMARC Report",
        )
        mock_mail = MagicMock()
        mock_mail.fetch.return_value = ("OK", [(b"1", raw)])
        mock_mail.store.return_value = ("OK", None)

        stats = {"processed": 0, "reports_found": 0, "errors": []}
        client._process_single_email(mock_mail, b"1", stats)

        assert stats["processed"] == 1
        assert stats["reports_found"] == 1

    def test_fetch_error_skips_email(self):
        client = self._make_client()
        mock_mail = MagicMock()
        mock_mail.fetch.return_value = ("NO", [])

        stats = {"processed": 0, "reports_found": 0, "errors": []}
        client._process_single_email(mock_mail, b"1", stats)

        assert stats["processed"] == 0

    def test_exception_adds_to_errors(self):
        client = self._make_client()
        mock_mail = MagicMock()
        mock_mail.fetch.side_effect = RuntimeError("unexpected error")

        stats = {"processed": 0, "reports_found": 0, "errors": []}
        client._process_single_email(mock_mail, b"1", stats)

        assert len(stats["errors"]) == 1

    def test_marks_deleted_when_flag_set(self):
        client = self._make_client()
        client.delete_emails = True
        raw = _make_email_with_attachment(
            "report.xml",
            MINIMAL_DMARC_XML,
            "application/xml",
            subject="DMARC Report",
        )
        mock_mail = MagicMock()
        mock_mail.fetch.return_value = ("OK", [(b"1", raw)])
        mock_mail.store.return_value = ("OK", None)

        stats = {"processed": 0, "reports_found": 0, "errors": []}
        client._process_single_email(mock_mail, b"1", stats)

        # store should have been called twice: once for \\Seen, once for \\Deleted
        assert mock_mail.store.call_count >= 2


# ---------------------------------------------------------------------------
# TestFetchReports
# ---------------------------------------------------------------------------


class TestFetchReports:
    def _make_client(self, server="imap.example.com", username="u", password="p"):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER=server,
                IMAP_PORT=993,
                IMAP_USERNAME=username,
                IMAP_PASSWORD=password,
            )
            return IMAPClient()

    def test_returns_error_when_no_credentials(self):
        with patch("app.services.imap_client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                IMAP_SERVER=None,
                IMAP_PORT=993,
                IMAP_USERNAME=None,
                IMAP_PASSWORD=None,
            )
            client = IMAPClient()
        result = client.fetch_reports()
        assert result["success"] is False

    def test_search_failure_returns_error(self):
        client = self._make_client()
        mock_mail = MagicMock()
        mock_mail.login.return_value = None
        mock_mail.select.return_value = ("OK", [b"0"])
        mock_mail.search.return_value = ("NO", [])

        with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
            result = client.fetch_reports(days=7)

        assert result["success"] is False

    def test_successful_fetch_with_email(self):
        client = self._make_client()
        raw = _make_email_with_attachment(
            "report.xml",
            MINIMAL_DMARC_XML,
            "application/xml",
            subject="DMARC Report",
        )
        mock_mail = MagicMock()
        mock_mail.login.return_value = None
        mock_mail.select.return_value = ("OK", [b"1"])
        mock_mail.search.return_value = ("OK", [b"1"])
        mock_mail.fetch.return_value = ("OK", [(b"1", raw)])
        mock_mail.store.return_value = ("OK", None)
        mock_mail.logout.return_value = None

        with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
            result = client.fetch_reports(days=7)

        assert result["success"] is True
        assert result["reports_found"] >= 1

    def test_connection_error_returns_failure(self):
        client = self._make_client()
        with patch("imaplib.IMAP4_SSL", side_effect=imaplib.IMAP4.error("connection error")):
            result = client.fetch_reports(days=7)
        assert result["success"] is False

    def test_delete_emails_calls_expunge(self):
        client = self._make_client()
        client.delete_emails = True
        mock_mail = MagicMock()
        mock_mail.login.return_value = None
        mock_mail.select.return_value = ("OK", [b"0"])
        mock_mail.search.return_value = ("OK", [b""])
        mock_mail.logout.return_value = None

        with patch("imaplib.IMAP4_SSL", return_value=mock_mail):
            result = client.fetch_reports(days=3)

        mock_mail.expunge.assert_called_once()
        assert result["success"] is True
