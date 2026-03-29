"""
Unit tests for app.services.gmail_client.GmailClient.

All external I/O (httpx, google-auth, googleapiclient) is mocked so these
tests never make real network calls.
"""

import base64
import email as email_mod
import json
from email import encoders as email_encoders
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from app.services.gmail_client import GmailClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(
    access_token: str = "acc",
    refresh_token: str = "ref",
    already_ingested: Optional[list] = None,
) -> GmailClient:
    """Instantiate a GmailClient with real Credentials mocked out."""
    with patch("app.services.gmail_client.Credentials") as mock_creds_class:
        mock_creds = MagicMock()
        mock_creds.token = access_token
        mock_creds.refresh_token = refresh_token
        mock_creds.expired = False
        mock_creds_class.return_value = mock_creds
        client = GmailClient(
            client_id="cid",
            client_secret="csec",
            access_token=access_token,
            refresh_token=refresh_token,
            already_ingested_ids=already_ingested or [],
        )
        # Expose the mock so tests can manipulate it
        client._mock_creds = mock_creds  # type: ignore[attr-defined]
        return client


def _make_raw_email(attachments: list) -> bytes:
    """Build a raw MIME email whose attachments are described by *attachments*.

    Each item in *attachments* is a dict with keys:
        filename: str
        content: bytes
        disposition: str  (default "attachment")
    """
    msg = MIMEMultipart()
    msg["Subject"] = "DMARC aggregate report"
    msg["From"] = "noreply@example.com"
    msg["To"] = "user@gmail.com"
    msg.attach(MIMEText("See attached DMARC report.", "plain"))

    for att in attachments:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(att["content"])
        email_encoders.encode_base64(part)
        disposition = att.get("disposition", "attachment")
        part.add_header(
            "Content-Disposition",
            disposition,
            filename=att["filename"],
        )
        msg.attach(part)

    return msg.as_bytes()


def _b64_raw(raw_bytes: bytes) -> str:
    """URL-safe base64-encode bytes (as Gmail API returns them)."""
    return base64.urlsafe_b64encode(raw_bytes).decode()


# ===========================================================================
# __init__ / basic construction
# ===========================================================================


class TestGmailClientInit:
    def test_init_stores_tokens(self):
        client = _make_client(access_token="my-acc", refresh_token="my-ref")
        assert client._initial_access_token == "my-acc"
        assert client.client_id == "cid"
        assert client.client_secret == "csec"

    def test_init_already_ingested_defaults_to_empty(self):
        client = _make_client()
        assert client.already_ingested_ids == []

    def test_init_already_ingested_is_copied(self):
        ids = ["a", "b"]
        client = _make_client(already_ingested=ids)
        assert client.already_ingested_ids == ["a", "b"]
        # Mutating the original should not affect the client
        ids.append("c")
        assert "c" not in client.already_ingested_ids


# ===========================================================================
# get_refreshed_tokens
# ===========================================================================


class TestGetRefreshedTokens:
    def test_returns_none_when_token_unchanged(self):
        client = _make_client(access_token="original")
        # credentials.token == _initial_access_token → no refresh happened
        client._mock_creds.token = "original"
        assert client.get_refreshed_tokens() is None

    def test_returns_new_access_token_when_changed(self):
        client = _make_client(access_token="original")
        client._mock_creds.token = "new-token"
        client._mock_creds.refresh_token = None
        result = client.get_refreshed_tokens()
        assert result is not None
        assert result["access_token"] == "new-token"
        assert "refresh_token" not in result

    def test_returns_both_tokens_when_refresh_token_present(self):
        client = _make_client(access_token="original")
        client._mock_creds.token = "new-token"
        client._mock_creds.refresh_token = "new-refresh"
        result = client.get_refreshed_tokens()
        assert result is not None
        assert result["access_token"] == "new-token"
        assert result["refresh_token"] == "new-refresh"

    def test_returns_none_when_token_is_none(self):
        client = _make_client(access_token="original")
        client._mock_creds.token = None
        assert client.get_refreshed_tokens() is None


# ===========================================================================
# build_authorization_url (already partly covered; extend for completeness)
# ===========================================================================


class TestBuildAuthorizationUrl:
    def test_includes_all_required_params(self):
        url = GmailClient.build_authorization_url(
            client_id="cid",
            redirect_uri="https://example.com/cb",
            state="99",
        )
        assert "client_id=cid" in url
        assert "response_type=code" in url
        assert "gmail.readonly" in url
        assert "access_type=offline" in url
        assert "prompt=consent" in url
        assert "state=99" in url

    def test_state_omitted_when_none(self):
        url = GmailClient.build_authorization_url(
            client_id="cid",
            redirect_uri="https://example.com/cb",
        )
        assert "state=" not in url


# ===========================================================================
# exchange_code_for_tokens
# ===========================================================================


class TestExchangeCodeForTokens:
    def test_success_returns_json(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"access_token": "acc", "refresh_token": "ref"}

        with patch("app.services.gmail_client.httpx.post", return_value=mock_resp):
            result = GmailClient.exchange_code_for_tokens(
                client_id="cid",
                client_secret="csec",
                code="auth-code",
                redirect_uri="https://example.com/cb",
            )

        assert result["access_token"] == "acc"
        assert result["refresh_token"] == "ref"

    def test_non_200_raises_value_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = '{"error": "invalid_grant"}'

        with patch("app.services.gmail_client.httpx.post", return_value=mock_resp):
            with pytest.raises(ValueError, match="400"):
                GmailClient.exchange_code_for_tokens(
                    client_id="cid",
                    client_secret="csec",
                    code="bad-code",
                    redirect_uri="https://example.com/cb",
                )


# ===========================================================================
# get_gmail_email
# ===========================================================================


class TestGetGmailEmail:
    def test_returns_email_on_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"email": "user@gmail.com"}

        with patch("app.services.gmail_client.httpx.get", return_value=mock_resp):
            result = GmailClient.get_gmail_email("valid-token")

        assert result == "user@gmail.com"

    def test_returns_none_on_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("app.services.gmail_client.httpx.get", return_value=mock_resp):
            result = GmailClient.get_gmail_email("expired-token")

        assert result is None

    def test_returns_none_on_exception(self):
        with patch(
            "app.services.gmail_client.httpx.get", side_effect=Exception("network error")
        ):
            result = GmailClient.get_gmail_email("some-token")

        assert result is None


# ===========================================================================
# _build_service
# ===========================================================================


class TestBuildService:
    def test_returns_service_when_not_expired(self):
        client = _make_client()
        client._mock_creds.expired = False

        mock_service = MagicMock()
        with patch("app.services.gmail_client.build", return_value=mock_service):
            svc = client._build_service()

        assert svc is mock_service

    def test_refreshes_token_when_expired(self):
        client = _make_client()
        client._mock_creds.expired = True
        client._mock_creds.refresh_token = "ref"

        mock_service = MagicMock()
        with patch("app.services.gmail_client.build", return_value=mock_service), patch(
            "app.services.gmail_client.Request"
        ):
            svc = client._build_service()

        client._mock_creds.refresh.assert_called_once()
        assert svc is mock_service

    def test_raises_when_refresh_fails(self):
        client = _make_client()
        client._mock_creds.expired = True
        client._mock_creds.refresh_token = "ref"
        client._mock_creds.refresh.side_effect = Exception("refresh failed")

        with patch("app.services.gmail_client.Request"), patch(
            "app.services.gmail_client.build"
        ):
            with pytest.raises(Exception, match="refresh failed"):
                client._build_service()


# ===========================================================================
# _list_dmarc_message_ids
# ===========================================================================


class TestListDmarcMessageIds:
    def test_returns_empty_when_no_messages(self):
        client = _make_client()
        service = MagicMock()
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": []
        }
        ids = client._list_dmarc_message_ids(service)
        assert ids == []

    def test_returns_ids_from_single_page(self):
        client = _make_client()
        service = MagicMock()
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "id1"}, {"id": "id2"}]
        }
        ids = client._list_dmarc_message_ids(service)
        assert ids == ["id1", "id2"]

    def test_follows_next_page_token(self):
        client = _make_client()
        # First page has a nextPageToken; second page has none
        service = MagicMock()
        execute = service.users.return_value.messages.return_value.list.return_value.execute
        execute.side_effect = [
            {"messages": [{"id": "id1"}], "nextPageToken": "page2"},
            {"messages": [{"id": "id2"}]},
        ]
        ids = client._list_dmarc_message_ids(service)
        assert ids == ["id1", "id2"]
        # list() should have been called twice
        assert service.users.return_value.messages.return_value.list.call_count == 2

    def test_raises_on_http_error(self):
        from googleapiclient.errors import HttpError

        client = _make_client()
        service = MagicMock()
        execute = service.users.return_value.messages.return_value.list.return_value.execute
        fake_error = HttpError(MagicMock(status=403), b"forbidden")
        execute.side_effect = fake_error
        with pytest.raises(HttpError):
            client._list_dmarc_message_ids(service)


# ===========================================================================
# _decode_part_filename
# ===========================================================================


class TestDecodePartFilename:
    def test_plain_ascii_filename(self):
        part = MagicMock()
        part.get_filename.return_value = "report.xml"
        assert GmailClient._decode_part_filename(part) == "report.xml"

    def test_none_filename_returns_empty(self):
        part = MagicMock()
        part.get_filename.return_value = None
        assert GmailClient._decode_part_filename(part) == ""

    def test_rfc2047_encoded_filename(self):
        # Build an RFC 2047 encoded filename
        encoded = "=?utf-8?b?cmVwb3J0LnhtbA==?="  # base64("report.xml")
        part = MagicMock()
        part.get_filename.return_value = encoded
        result = GmailClient._decode_part_filename(part)
        assert result == "report.xml"


# ===========================================================================
# _is_dmarc_attachment
# ===========================================================================


class TestIsDmarcAttachment:
    @pytest.mark.parametrize(
        "filename",
        [
            "report.xml",
            "report.XML",  # case-insensitive
            "report.zip",
            "report.gz",
            "report.gzip",
            "Report.ZIP",
        ],
    )
    def test_dmarc_extensions_return_true(self, filename):
        assert GmailClient._is_dmarc_attachment(filename) is True

    @pytest.mark.parametrize(
        "filename",
        ["report.txt", "image.png", "report.pdf", "report.tar", ""],
    )
    def test_non_dmarc_extensions_return_false(self, filename):
        assert GmailClient._is_dmarc_attachment(filename) is False


# ===========================================================================
# _process_message
# ===========================================================================


class TestProcessMessage:
    def test_fetches_and_processes_message(self):
        """Happy path: message fetched, attachments processed."""
        client = _make_client()
        raw_email = _make_raw_email(
            [{"filename": "report.xml", "content": b"<xml/>"}]
        )
        raw_b64 = _b64_raw(raw_email)

        service = MagicMock()
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "raw": raw_b64
        }

        stats = {"reports_found": 0, "errors": []}
        with patch.object(client, "_process_attachments", return_value=0) as mock_proc:
            count = client._process_message(service, "msg1", stats)

        mock_proc.assert_called_once()
        assert count == 0  # our mock returns 0

    def test_http_error_recorded_and_returns_zero(self):
        from googleapiclient.errors import HttpError

        client = _make_client()
        service = MagicMock()
        fake_error = HttpError(MagicMock(status=404), b"not found")
        service.users.return_value.messages.return_value.get.return_value.execute.side_effect = (
            fake_error
        )

        stats = {"reports_found": 0, "errors": []}
        count = client._process_message(service, "bad-id", stats)

        assert count == 0
        assert len(stats["errors"]) == 1
        assert "bad-id" in stats["errors"][0]


# ===========================================================================
# _process_attachments
# ===========================================================================


class TestProcessAttachments:
    def test_no_attachments_returns_zero(self):
        client = _make_client()
        msg = email_mod.message_from_bytes(
            b"From: a@b.com\r\nTo: c@d.com\r\n\r\nHello"
        )
        stats = {"reports_found": 0, "errors": []}
        count = client._process_attachments(msg, stats)
        assert count == 0

    def test_non_dmarc_attachment_skipped(self):
        """An inline or non-DMARC file should not count as a report."""
        client = _make_client()
        raw = _make_raw_email(
            [{"filename": "photo.png", "content": b"\x89PNG"}]
        )
        msg = email_mod.message_from_bytes(raw)
        stats = {"reports_found": 0, "errors": []}
        count = client._process_attachments(msg, stats)
        assert count == 0
        assert stats["reports_found"] == 0

    def test_dmarc_xml_attachment_is_parsed(self):
        """A .xml attachment is parsed via DMARCParser and counts as a report."""
        client = _make_client()
        raw = _make_raw_email(
            [{"filename": "report.xml", "content": b"<xml_content/>"}]
        )
        msg = email_mod.message_from_bytes(raw)
        stats = {"reports_found": 0, "errors": []}

        mock_report = {"domain": "example.com", "records": []}
        with patch("app.services.gmail_client.DMARCParser") as mock_parser_class:
            mock_parser = MagicMock()
            mock_parser.parse.return_value = [mock_report]
            mock_parser_class.return_value = mock_parser
            # Also mock report_store.add_report to avoid real persistence
            with patch.object(client.report_store, "add_report"):
                count = client._process_attachments(msg, stats)

        assert count == 1
        assert stats["reports_found"] == 1

    def test_dmarc_attachment_with_empty_content_skipped(self):
        """A DMARC-named attachment with truly empty payload is skipped gracefully."""
        client = _make_client()
        # Build an attachment with empty bytes – base64 of b"" is b""
        raw = _make_raw_email(
            [{"filename": "report.zip", "content": b""}]
        )
        msg = email_mod.message_from_bytes(raw)
        stats = {"reports_found": 0, "errors": []}
        count = client._process_attachments(msg, stats)
        # Empty payload → `get_payload(decode=True)` returns b"" which is
        # falsy, so the attachment is skipped
        assert count == 0

    def test_parse_exception_adds_error_and_continues(self):
        """A parse error should be recorded in stats but not raise."""
        client = _make_client()
        raw = _make_raw_email(
            [
                {"filename": "bad.xml", "content": b"corrupt"},
                {"filename": "good.xml", "content": b"<xml/>"},
            ]
        )
        msg = email_mod.message_from_bytes(raw)
        stats = {"reports_found": 0, "errors": []}

        good_report = {"domain": "example.com", "records": []}
        call_count = 0

        def parse_side_effect(content, filename):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("bad xml")
            return [good_report]

        with patch("app.services.gmail_client.DMARCParser") as mock_parser_class:
            mock_parser = MagicMock()
            mock_parser.parse.side_effect = parse_side_effect
            mock_parser_class.return_value = mock_parser
            with patch.object(client.report_store, "add_report"):
                count = client._process_attachments(msg, stats)

        assert len(stats["errors"]) == 1
        assert "bad.xml" in stats["errors"][0]
        assert count == 1  # second attachment still parsed


# ===========================================================================
# fetch_reports
# ===========================================================================


class TestFetchReports:
    def test_returns_failure_when_build_service_raises(self):
        client = _make_client()
        with patch.object(
            client, "_build_service", side_effect=Exception("auth error")
        ):
            result = client.fetch_reports()

        assert result["success"] is False
        assert "auth error" in result.get("error", "")

    def test_returns_failure_when_list_messages_raises(self):
        client = _make_client()
        mock_service = MagicMock()
        with patch.object(client, "_build_service", return_value=mock_service), patch.object(
            client, "_list_dmarc_message_ids", side_effect=Exception("list error")
        ):
            result = client.fetch_reports()

        assert result["success"] is False

    def test_returns_success_with_no_messages(self):
        client = _make_client()
        mock_service = MagicMock()
        with patch.object(client, "_build_service", return_value=mock_service), patch.object(
            client, "_list_dmarc_message_ids", return_value=[]
        ):
            result = client.fetch_reports()

        assert result["success"] is True
        assert result["processed"] == 0

    def test_skips_already_ingested_messages(self):
        client = _make_client(already_ingested=["id1"])
        mock_service = MagicMock()
        with patch.object(client, "_build_service", return_value=mock_service), patch.object(
            client, "_list_dmarc_message_ids", return_value=["id1", "id2"]
        ), patch.object(client, "_process_message", return_value=0) as mock_proc:
            result = client.fetch_reports()

        # Only id2 should be processed; id1 is already ingested
        assert mock_proc.call_count == 1
        call_args = mock_proc.call_args_list[0][0]
        assert call_args[1] == "id2"
        assert result["processed"] == 1

    def test_tracks_new_ingested_ids(self):
        client = _make_client()
        mock_service = MagicMock()
        with patch.object(client, "_build_service", return_value=mock_service), patch.object(
            client, "_list_dmarc_message_ids", return_value=["id1", "id2"]
        ), patch.object(client, "_process_message", return_value=0):
            result = client.fetch_reports()

        assert "id1" in result["new_ingested_ids"]
        assert "id2" in result["new_ingested_ids"]

    def test_reports_new_domains(self):
        """fetch_reports should report domains that appear after ingestion."""
        from app.services.report_store import ReportStore

        client = _make_client()
        mock_service = MagicMock()

        def _process_side_effect(service, msg_id, stats):
            # Simulate adding a domain to the report store
            ReportStore.get_instance().add_report(
                {
                    "org_name": "Test Org",
                    "report_id": "r1",
                    "begin_date": "2024-01-01",
                    "end_date": "2024-01-02",
                    "domain": "newdomain.example",
                    "records": [],
                }
            )
            stats["reports_found"] += 1
            return 1

        with patch.object(client, "_build_service", return_value=mock_service), patch.object(
            client, "_list_dmarc_message_ids", return_value=["id1"]
        ), patch.object(client, "_process_message", side_effect=_process_side_effect):
            result = client.fetch_reports()

        assert "newdomain.example" in result["new_domains"]


# ===========================================================================
# load_ingested_ids / dump_ingested_ids (already tested in TestGmailClientHelpers
# in test_mail_sources.py; add a few edge-cases here)
# ===========================================================================


class TestIngestedIdHelpers:
    def test_load_non_list_json_returns_no_error(self):
        # Valid JSON but not a list – should gracefully not raise
        result = GmailClient.load_ingested_ids('{"key": "value"}')
        assert result is not None  # no crash

    def test_dump_preserves_order(self):
        ids = ["z", "a", "m"]
        dumped = GmailClient.dump_ingested_ids(ids)
        assert json.loads(dumped) == ["z", "a", "m"]
