"""Unit tests for app.services.microsoft_graph_client.MicrosoftGraphClient."""

import base64
import zipfile
from email.message import EmailMessage
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from io import BytesIO
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from app.models.delivery_event import DeliveryEvent
from app.models.domain import Domain
from app.models.report import DMARCReport
from app.models.workspace import Workspace
from app.services import microsoft_graph_client
from app.services.dsn_parser import MAX_DSN_BYTES
from app.services.mail_connector import initial_import_stats
from app.services.microsoft_graph_client import (
    M365_APPLICATION_SCOPE,
    M365_SCOPES,
    MicrosoftGraphClient,
    MicrosoftGraphError,
    m365_application_configuration_error,
    m365_source_can_authenticate,
)
from app.tests.test_data import SAMPLE_XML
from app.tests.test_delivery_events import _dsn_bytes


def _zip_xml(xml: str = SAMPLE_XML, name: str = "report.xml") -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, xml.encode("utf-8"))
    return buf.getvalue()


def _make_client(db=None, already_ingested=None) -> MicrosoftGraphClient:
    return MicrosoftGraphClient(
        tenant_id="organizations",
        client_id="client-id",
        client_secret="client-secret",
        access_token="access-token",
        refresh_token="refresh-token",
        mailbox=None,
        folder="INBOX",
        already_ingested_ids=already_ingested or [],
        db=db,
    )


def test_raw_mime_download_stops_at_size_limit(monkeypatch):
    client = _make_client()
    response = SimpleNamespace(
        status_code=200,
        iter_bytes=lambda: iter((b"x" * MAX_DSN_BYTES, b"overflow")),
        close=lambda: None,
    )

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def build_request(self, method, url, **kwargs):
            return (method, url, kwargs)

        def send(self, _request, *, stream):
            assert stream is True
            return response

    transport = FakeClient()
    monkeypatch.setattr("app.services.microsoft_graph_client.httpx.Client", lambda **_kw: transport)

    with pytest.raises(MicrosoftGraphError, match="safe size limit"):
        client._request_bytes("/messages/oversized/$value")


class TestMicrosoftGraphOAuthHelpers:
    def test_application_configuration_requires_tenant_credentials_and_mailbox(self):
        source = SimpleNamespace(
            m365_auth_mode="application",
            m365_tenant_id="common",
            m365_client_id="",
            m365_client_secret="",
            m365_mailbox="",
        )

        assert "tenant-specific" in m365_application_configuration_error(source)
        assert m365_source_can_authenticate(source) is False

        source.m365_tenant_id = "tenant.example"
        source.m365_client_id = "client-id"
        source.m365_client_secret = "client-secret"
        source.m365_mailbox = "dmarc-reports@example.com"

        assert m365_application_configuration_error(source) is None
        assert m365_source_can_authenticate(source) is True

    def test_application_client_credentials_read_explicit_mailbox(self, monkeypatch):
        seen = {}

        def fake_post(url, data=None, timeout=None):
            seen["token_url"] = url
            seen["token_data"] = data
            return httpx.Response(200, json={"access_token": "application-token"})

        def fake_request(method, url, headers=None, params=None, timeout=None):
            seen["graph_url"] = url
            seen["authorization"] = headers["Authorization"]
            return httpx.Response(200, json={"value": []})

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.post", fake_post)
        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = MicrosoftGraphClient(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
            access_token="",
            refresh_token="",
            auth_mode="application",
            mailbox="dmarc-reports@example.com",
            folder="INBOX",
        )

        result = client.test_connection()

        assert result["success"] is True
        assert seen["token_url"].endswith("/tenant-id/oauth2/v2.0/token")
        assert seen["token_data"] == {
            "client_id": "client-id",
            "client_secret": "client-secret",
            "grant_type": "client_credentials",
            "scope": M365_APPLICATION_SCOPE,
        }
        assert seen["graph_url"].endswith(
            "/users/dmarc-reports%40example.com/mailFolders/inbox/messages"
        )
        assert seen["authorization"] == "Bearer application-token"
        assert client.get_refreshed_tokens() == {"access_token": "application-token"}

    def test_application_client_never_falls_back_to_me(self):
        client = MicrosoftGraphClient(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
            access_token="",
            refresh_token="",
            auth_mode="application",
            mailbox="",
        )

        try:
            client.test_connection()
        except MicrosoftGraphError as exc:
            assert "explicit target mailbox" in str(exc)
        else:
            raise AssertionError("application access must require a target mailbox")

    def test_application_client_reacquires_token_after_401(self, monkeypatch):
        token_values = iter(["token-1", "token-2"])
        seen_authorization = []

        def fake_post(url, data=None, timeout=None):
            return httpx.Response(200, json={"access_token": next(token_values)})

        def fake_request(method, url, headers=None, params=None, timeout=None):
            seen_authorization.append(headers["Authorization"])
            if len(seen_authorization) == 1:
                return httpx.Response(401, json={"error": {"code": "InvalidToken"}})
            return httpx.Response(200, json={"value": []})

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.post", fake_post)
        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = MicrosoftGraphClient(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
            access_token="",
            refresh_token="",
            auth_mode="application",
            mailbox="dmarc-reports@example.com",
        )

        assert client.test_connection()["success"] is True
        assert seen_authorization == ["Bearer token-1", "Bearer token-2"]
        assert client.get_refreshed_tokens() == {"access_token": "token-2"}

    def test_connector_contract_uses_read_only_scopes_and_safe_context(self):
        client = MicrosoftGraphClient(
            tenant_id="organizations",
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            mailbox="shared@example.com",
            folder="DMARC Reports",
            folder_id="folder-id",
        )

        context = client.import_context(days=45)
        stats = initial_import_stats(context)

        assert M365_SCOPES == [
            "offline_access",
            "https://graph.microsoft.com/User.Read",
            "https://graph.microsoft.com/Mail.Read",
            "https://graph.microsoft.com/Mail.Read.Shared",
        ]
        assert callable(client.search_messages)
        assert callable(client.iter_attachments)
        assert callable(client.fetch_reports)
        assert stats["source_type"] == "M365_GRAPH"
        assert stats["target_mailbox"] == "shared@example.com"
        assert stats["target_folder"] == "DMARC Reports"
        assert stats["search_window_days"] == 45
        assert stats["forensic_reports_found"] == 0
        assert stats["duplicate_forensic_reports"] == 0
        assert "client-secret" not in str(stats)

    def test_build_authorization_url_includes_required_scopes(self):
        url = MicrosoftGraphClient.build_authorization_url(
            tenant_id="organizations",
            client_id="client-id",
            redirect_uri="https://example.com/callback",
            state="42",
        )

        assert url.startswith("https://login.microsoftonline.com/organizations/")
        params = parse_qs(urlparse(url).query)
        assert params["client_id"] == ["client-id"]
        assert params["response_type"] == ["code"]
        assert params["scope"] == [" ".join(M365_SCOPES)]
        assert params["state"] == ["42"]

    def test_exchange_code_for_tokens_posts_to_tenant_endpoint(self, monkeypatch):
        def fake_post(url, data=None, timeout=None):
            assert url.endswith("/contoso-tenant/oauth2/v2.0/token")
            assert data["grant_type"] == "authorization_code"
            assert data["code"] == "code"
            return httpx.Response(200, json={"access_token": "access"})

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.post", fake_post)

        result = MicrosoftGraphClient.exchange_code_for_tokens(
            tenant_id="contoso-tenant",
            client_id="client-id",
            client_secret="client-secret",
            code="code",
            redirect_uri="https://example.com/callback",
        )

        assert result == {"access_token": "access"}

    def test_exchange_code_for_tokens_raises_on_failure(self, monkeypatch):
        def fake_post(url, data=None, timeout=None):
            return httpx.Response(400, text="bad request")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.post", fake_post)

        try:
            MicrosoftGraphClient.exchange_code_for_tokens(
                tenant_id="organizations",
                client_id="client-id",
                client_secret="client-secret",
                code="bad",
                redirect_uri="https://example.com/callback",
            )
        except Exception as exc:
            assert "token exchange failed" in str(exc).lower()
        else:
            raise AssertionError("expected token exchange failure")

    def test_get_account_email_prefers_mail_then_user_principal_name(self, monkeypatch):
        def fake_get(url, headers=None, params=None, timeout=None):
            assert url.endswith("/me")
            assert params == {"$select": "mail,userPrincipalName"}
            return httpx.Response(
                200,
                json={"mail": "", "userPrincipalName": "dmarc@example.com"},
            )

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.get", fake_get)

        assert MicrosoftGraphClient.get_account_email("access") == "dmarc@example.com"

    def test_get_account_email_returns_none_on_error(self, monkeypatch):
        def fake_get(url, headers=None, params=None, timeout=None):
            raise RuntimeError("network down")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.get", fake_get)

        assert MicrosoftGraphClient.get_account_email("access") is None

    def test_ingested_id_helpers_tolerate_bad_json(self):
        assert MicrosoftGraphClient.load_ingested_ids(None) == []
        assert MicrosoftGraphClient.load_ingested_ids('["a", 2]') == ["a", "2"]
        assert MicrosoftGraphClient.load_ingested_ids("{bad") == []
        assert MicrosoftGraphClient.dump_ingested_ids(["a"]) == '["a"]'


class TestMicrosoftGraphFetchReports:
    def test_retry_message_fetches_one_encoded_graph_message(self, monkeypatch):
        client = _make_client()
        requests = []

        def fetch(method, path, params=None):
            requests.append((method, path, params))
            return {"id": "message/one"}

        monkeypatch.setattr(client, "_request", fetch)
        monkeypatch.setattr(client, "_process_message", lambda _message, _stats: 0)

        result = client.retry_message("message/one")

        assert result["success"] is True
        assert result["processed"] == 1
        assert result["new_ingested_ids"] == ["message/one"]
        assert requests == [
            (
                "GET",
                "/me/messages/message%2Fone",
                {"$select": "id,subject,from,hasAttachments,receivedDateTime"},
            )
        ]

    def test_retry_message_returns_failure_without_marking_graph_id_ingested(self, monkeypatch):
        client = _make_client()

        def fail(*_args, **_kwargs):
            raise MicrosoftGraphError("unavailable")

        monkeypatch.setattr(client, "_request", fail)

        result = client.retry_message("message-one")

        assert result["success"] is False
        assert result["new_ingested_ids"] == []
        assert result["errors"]

    def test_test_connection_reads_shared_mailbox(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            assert url.endswith("/users/shared%40example.com/mailFolders/inbox/messages")
            assert params == {"$top": 1, "$select": "id"}
            return httpx.Response(200, json={"value": [{"id": "message-1"}]})

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = MicrosoftGraphClient(
            tenant_id="organizations",
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            mailbox="shared@example.com",
            folder="INBOX",
        )

        result = client.test_connection()

        assert result["success"] is True
        assert result["message_count"] == 1
        assert result["target_mailbox"] == "shared@example.com"
        assert result["target_folder"] == "INBOX"

    def test_list_mail_folders_reads_shared_mailbox(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            assert params == {
                "$top": 100,
                "$select": "id,displayName,parentFolderId,childFolderCount",
            }
            if url.endswith("/users/shared%40example.com/mailFolders"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {"id": "inbox-id", "displayName": "Inbox", "childFolderCount": 1},
                            {"id": "dmarc-id", "displayName": "DMARC Reports"},
                        ]
                    },
                )
            if url.endswith("/users/shared%40example.com/mailFolders/inbox-id/childFolders"):
                return httpx.Response(
                    200,
                    json={"value": [{"id": "nested-id", "displayName": "Nested DMARC"}]},
                )
            raise AssertionError(f"Unexpected Graph request: {method} {url}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = MicrosoftGraphClient(
            tenant_id="organizations",
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            mailbox="shared@example.com",
        )

        assert client.list_mail_folders() == [
            {"id": "inbox-id", "display_name": "Inbox", "path": "Inbox", "parent_folder_id": ""},
            {
                "id": "nested-id",
                "display_name": "Nested DMARC",
                "path": "Inbox / Nested DMARC",
                "parent_folder_id": "",
            },
            {
                "id": "dmarc-id",
                "display_name": "DMARC Reports",
                "path": "DMARC Reports",
                "parent_folder_id": "",
            },
        ]

    def test_fetch_reports_uses_selected_folder_id_and_records_context(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/users/shared%40example.com/mailFolders/folder-id/messages"):
                assert "$filter" in params
                assert params["$filter"].startswith("receivedDateTime ge ")
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-1",
                                "subject": "DMARC aggregate report",
                                "from": {"emailAddress": {"address": "reports@example.net"}},
                                "hasAttachments": True,
                            }
                        ]
                    },
                )
            if url.endswith("/users/shared%40example.com/messages/message-1/attachments"):
                return httpx.Response(200, json={"value": []})
            raise AssertionError(f"Unexpected Graph request: {method} {url}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = MicrosoftGraphClient(
            tenant_id="organizations",
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            mailbox="shared@example.com",
            folder="DMARC Reports",
            folder_id="folder-id",
        )

        result = client.fetch_reports()

        assert result["processed"] == 1
        assert result["target_mailbox"] == "shared@example.com"
        assert result["target_folder"] == "DMARC Reports"
        assert result["search_window_days"] == 7

    def test_fetch_reports_applies_requested_search_window(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            assert url.endswith("/me/mailFolders/inbox/messages")
            assert params["$top"] == 100
            assert params["$select"] == "id,subject,from,hasAttachments,receivedDateTime"
            assert params["$orderby"] == "receivedDateTime desc"
            assert params["$filter"].startswith("receivedDateTime ge ")
            return httpx.Response(200, json={"value": []})

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client()

        result = client.fetch_reports(days=30)

        assert result["success"] is True
        assert result["search_window_days"] == 30
        assert result["processed"] == 0

    def test_fetch_reports_resumes_from_graph_next_link_and_returns_next_cursor(self, monkeypatch):
        seen = []

        def fake_request(method, url, headers=None, params=None, timeout=None):
            seen.append((url, params))
            assert method == "GET"
            assert url == "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=page1"
            assert params is None
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "message-1",
                            "subject": "DMARC aggregate report",
                            "from": {"emailAddress": {"address": "reports@example.net"}},
                            "hasAttachments": True,
                        }
                    ],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=page2",
                },
            )

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client()
        monkeypatch.setattr(client, "_list_attachments", lambda _message_id: [])

        result = client.fetch_reports(
            days=30,
            page_cursor="https://graph.microsoft.com/v1.0/me/messages?$skiptoken=page1",
            max_pages=1,
        )

        assert result["success"] is True
        assert result["processed"] == 1
        assert (
            result["page_cursor"] == "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=page2"
        )
        assert len(seen) == 1

    def test_request_retries_graph_throttling(self, monkeypatch):
        responses = [
            httpx.Response(
                429,
                headers={"Retry-After": "0"},
                json={"error": {"code": "TooManyRequests", "message": "slow down"}},
            ),
            httpx.Response(200, json={"value": []}),
        ]
        sleeps = []

        def fake_request(method, url, headers=None, params=None, timeout=None):
            return responses.pop(0)

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = MicrosoftGraphClient(
            tenant_id="organizations",
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            sleep=sleeps.append,
        )

        result = client.fetch_reports()

        assert result["success"] is True
        assert sleeps == [0.0]
        assert responses == []

    def test_fetch_reports_imports_zip_attachment(self, monkeypatch, db_session):
        attachment_bytes = _zip_xml()

        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-1",
                                "subject": "DMARC aggregate report",
                                "from": {"emailAddress": {"address": "reports@example.net"}},
                                "hasAttachments": True,
                                "receivedDateTime": "2026-05-23T00:00:00Z",
                            }
                        ]
                    },
                )
            if url.endswith("/me/messages/message-1/attachments"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "@odata.type": "#microsoft.graph.fileAttachment",
                                "name": "report.zip",
                                "contentBytes": base64.b64encode(attachment_bytes).decode(),
                            }
                        ]
                    },
                )
            raise AssertionError(f"Unexpected Graph request: {method} {url}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client(db=db_session)

        result = client.fetch_reports()

        assert result["success"] is True
        assert result["processed"] == 1
        assert result["reports_found"] == 1
        assert result["new_ingested_ids"] == ["message-1"]
        assert db_session.query(DMARCReport).count() == 1

    def test_fetch_reports_imports_file_inside_nested_item_attachment(
        self, monkeypatch, db_session
    ):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-nested",
                                "subject": "DMARC aggregate report",
                                "from": {"emailAddress": {"address": "reports@example.net"}},
                                "hasAttachments": True,
                            }
                        ]
                    },
                )
            if url.endswith("/me/messages/message-nested/attachments"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "attached-message",
                                "@odata.type": "#microsoft.graph.itemAttachment",
                                "name": "forwarded-report.eml",
                                "item": {
                                    "attachments": [
                                        {
                                            "@odata.type": "#microsoft.graph.fileAttachment",
                                            "name": "report.xml",
                                            "contentBytes": base64.b64encode(
                                                SAMPLE_XML.encode()
                                            ).decode(),
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                )
            raise AssertionError(f"Unexpected Graph request: {method} {url} {params}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        result = _make_client(db=db_session).fetch_reports()

        assert result["reports_found"] == 1
        assert result["new_ingested_ids"] == ["message-nested"]
        assert db_session.query(DMARCReport).count() == 1

    def test_fetch_reports_imports_report_from_nested_mime_attachment(
        self, monkeypatch, db_session
    ):
        nested = EmailMessage()
        nested["Subject"] = "Forwarded DMARC report"
        nested.set_content("Attached report")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        outer = nested.as_bytes()

        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-mime",
                                "subject": "DMARC aggregate report",
                                "hasAttachments": True,
                            }
                        ]
                    },
                )
            if url.endswith("/me/messages/message-mime/attachments"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "@odata.type": "#microsoft.graph.fileAttachment",
                                "name": "forwarded.eml",
                                "contentType": "message/rfc822",
                                "contentBytes": base64.b64encode(outer).decode(),
                            }
                        ]
                    },
                )
            raise AssertionError(f"Unexpected Graph request: {method} {url} {params}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        result = _make_client(db=db_session).fetch_reports()

        assert result["reports_found"] == 1
        assert result["new_ingested_ids"] == ["message-mime"]
        assert db_session.query(DMARCReport).count() == 1

    def test_nested_rfc822_wrapper_is_not_traversed_twice(self, db_session):
        nested = EmailMessage()
        nested.set_content("Attached report")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        outer = EmailMessage()
        outer.set_content("Forwarded message")
        outer.add_attachment(nested, filename="forwarded.eml")
        stats = {"details": [], "errors": [], "reports_found": 0}

        result = _make_client(db=db_session)._process_attachments(
            "message-rfc822",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(outer.as_bytes()).decode(),
                }
            ],
            stats,
        )

        assert result == 1
        assert stats.get("duplicate_reports", 0) == 0
        assert db_session.query(DMARCReport).count() == 1

    def test_base64_octet_stream_eml_leaf_is_decoded(self, db_session):
        nested = EmailMessage()
        nested.set_content("Attached report")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        encoded = EmailMessage()
        encoded.set_type("application/octet-stream")
        encoded["Content-Disposition"] = 'attachment; filename="forwarded.eml"'
        encoded["Content-Transfer-Encoding"] = "base64"
        encoded.set_payload(base64.b64encode(nested.as_bytes()).decode("ascii"))
        stats = initial_import_stats(_make_client(db=db_session).import_context())

        found = _make_client(db=db_session)._process_attachments(
            "message-octet",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(encoded.as_bytes()).decode("ascii"),
                }
            ],
            stats,
        )

        assert found == 1
        assert stats["errors"] == []

    def test_mime_part_rfc822_accepts_message_payload(self):
        nested = EmailMessage()
        nested.set_content("Forwarded message")

        attachment = MicrosoftGraphClient._mime_part_attachment(MIMEMessage(nested))

        assert attachment is not None
        assert base64.b64decode(attachment["contentBytes"]) == nested.as_bytes()

    def test_mime_part_rfc822_accepts_a_single_message_payload(self):
        nested = EmailMessage()
        nested.set_content("Forwarded message")
        part = EmailMessage()
        part.set_type("message/rfc822")
        part.set_payload(nested)

        attachment = MicrosoftGraphClient._mime_part_attachment(part)

        assert attachment is not None
        assert base64.b64decode(attachment["contentBytes"]) == nested.as_bytes()

    def test_mime_part_rfc822_decodes_a_raw_payload(self):
        part = EmailMessage()
        part.set_type("message/rfc822")
        part.set_payload("Subject: forwarded report\n\nbody")

        attachment = MicrosoftGraphClient._mime_part_attachment(part)

        assert attachment is not None
        assert base64.b64decode(attachment["contentBytes"]) == b"Subject: forwarded report\n\nbody"

    def test_base64_rfc822_leaf_is_decoded_before_serialization(self, db_session):
        nested = EmailMessage()
        nested.set_content("Attached report")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        encoded = base64.b64encode(nested.as_bytes())
        raw = (
            b'Content-Type: multipart/mixed; boundary="rfc822-boundary"\n'
            b"MIME-Version: 1.0\n\n"
            b"--rfc822-boundary\n"
            b"Content-Type: message/rfc822\n"
            b'Content-Disposition: attachment; filename="forwarded.eml"\n'
            b"Content-Transfer-Encoding: base64\n\n" + encoded + b"\n--rfc822-boundary--\n"
        )
        stats = initial_import_stats(_make_client(db=db_session).import_context())

        found = _make_client(db=db_session)._process_attachments(
            "message-rfc822-base64",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(raw).decode(),
                }
            ],
            stats,
        )

        assert found == 1
        assert stats["errors"] == []

    def test_nested_alternative_body_with_valid_report_is_neutral(self, db_session):
        alternative = EmailMessage()
        alternative.set_content("Plain body")
        alternative.add_alternative("<p>HTML body</p>", subtype="html")
        outer = EmailMessage()
        outer.set_content("Forwarded message")
        outer.add_attachment(alternative, filename="body.eml")
        outer.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        stats = initial_import_stats(_make_client(db=db_session).import_context())

        found = _make_client(db=db_session)._process_attachments(
            "message-alternative",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(outer.as_bytes()).decode("ascii"),
                }
            ],
            stats,
        )

        assert found == 1
        assert stats["errors"] == []

    def test_named_nested_unsupported_attachment_is_counted(self):
        message = EmailMessage()
        message.set_content("Forwarded message")
        message.add_attachment(b"notes", maintype="text", subtype="plain", filename="notes.txt")
        stats = {"details": [], "errors": []}

        result = _make_client()._process_attachments(
            "message-notes",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(message.as_bytes()).decode(),
                }
            ],
            stats,
        )

        assert result == 0
        assert stats["skipped_attachments"] == 1
        assert stats["details"][-1]["reason"] == "unsupported_attachment"

    def test_item_attachment_uses_bounded_mime_value_fallback(self, monkeypatch, db_session):
        nested = EmailMessage()
        nested.set_content("Attached report")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        client = _make_client(db=db_session)
        monkeypatch.setattr(client, "_get_nested_attachments", lambda *_args: [])
        monkeypatch.setattr(client, "_request_bytes", lambda _path: nested.as_bytes())
        stats = initial_import_stats(client.import_context())

        result = client._process_item_attachment(
            "message-fallback",
            {"id": "item-1", "name": "forwarded.eml"},
            stats,
            depth=0,
            attachment_count=[0],
        )

        assert result == (1, False)
        assert stats["reports_found"] == 1

    def test_item_attachment_uses_message_mime_after_item_value_failure(
        self, monkeypatch, db_session
    ):
        client = _make_client(db=db_session)
        nested = EmailMessage()
        nested.set_content("Attached report")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        paths = []

        monkeypatch.setattr(client, "_get_nested_attachments", lambda *_args: [])

        def fetch(path):
            paths.append(path)
            if path.endswith("/attachments/item-1/$value"):
                raise MicrosoftGraphError("item MIME unavailable")
            return nested.as_bytes()

        monkeypatch.setattr(client, "_request_bytes", fetch)
        stats = initial_import_stats(client.import_context())

        result = client._process_item_attachment(
            "message-fallback",
            {"id": "item-1", "name": "forwarded.eml"},
            stats,
            depth=0,
            attachment_count=[0],
        )

        assert result == (1, False)
        assert paths[-1].endswith("/messages/message-fallback/$value")

    def test_item_attachment_keeps_message_retryable_when_both_mime_reads_fail(self, monkeypatch):
        client = _make_client()
        monkeypatch.setattr(client, "_get_nested_attachments", lambda *_args: [])

        def fail_read(_path):
            raise MicrosoftGraphError("MIME endpoint unavailable")

        monkeypatch.setattr(client, "_request_bytes", fail_read)
        stats = initial_import_stats(client.import_context())

        result = client._process_item_attachment(
            "message-fallback-failure",
            {"id": "item-1", "name": "forwarded.eml"},
            stats,
            depth=0,
            attachment_count=[0],
        )

        assert result == (0, True)
        assert stats["details"][-1]["reason"] == "nested_attachment_fetch_failed"
        assert "raw MIME fallback failed" in stats["errors"][-1]

    def test_item_attachment_without_id_is_reported_as_retryable(self):
        client = _make_client()
        stats = initial_import_stats(client.import_context())

        found = client._process_attachments(
            "message-item-without-id",
            [
                {
                    "@odata.type": "#microsoft.graph.itemAttachment",
                    "name": "forwarded.eml",
                    "item": {"attachments": []},
                }
            ],
            stats,
        )

        assert found == -1
        assert stats["details"][-1]["reason"] == "unsupported_attachment_type"

    def test_non_file_attachment_with_report_name_is_skipped(self):
        client = _make_client()
        stats = initial_import_stats(client.import_context())

        found = client._process_attachments(
            "message-unsupported-type",
            [
                {
                    "@odata.type": "#microsoft.graph.referenceAttachment",
                    "name": "report.zip",
                }
            ],
            stats,
        )

        assert found == 0
        assert stats["details"][-1]["reason"] == "unsupported_attachment_type"

    def test_nested_mime_leaves_are_not_counted_twice(self):
        nested = EmailMessage()
        nested.set_content("Attached notes")
        for index in range(50):
            nested.add_attachment(
                b"notes", maintype="text", subtype="plain", filename=f"note-{index}.txt"
            )
        client = _make_client()
        stats = initial_import_stats(client.import_context())

        found = client._process_attachments(
            "message-count",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(nested.as_bytes()).decode(),
                }
            ],
            stats,
        )

        assert found == 0
        assert stats["skipped_attachments"] == 50

    def test_nested_mime_nonmultipart_container_is_neutral(self):
        message = EmailMessage()
        message.set_content("A forwarded-message body without attachments")

        assert MicrosoftGraphClient._nested_mime_attachments(message) == []

    def test_nested_mime_attachment_count_is_bounded(self):
        message = EmailMessage()
        message.set_content("A message with too many parts")
        for index in range(101):
            message.add_attachment(
                b"notes", maintype="text", subtype="plain", filename=f"note-{index}.txt"
            )

        with pytest.raises(ValueError, match="attachment count exceeds"):
            MicrosoftGraphClient._nested_mime_attachments(message)

    def test_presentation_multipart_wrappers_leave_a_valid_sibling_report_eligible(self):
        presentation = EmailMessage()
        presentation.set_content("Plain body")
        presentation.add_alternative("<p>HTML body</p>", subtype="html")
        for _ in range(2):
            wrapper = MIMEMultipart("related")
            wrapper.attach(presentation)
            presentation = wrapper
        outer = EmailMessage()
        outer.make_mixed()
        outer.attach(presentation)
        outer.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        client = _make_client()
        stats = initial_import_stats(client.import_context())

        found = client._process_attachments(
            "message-presentation",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(outer.as_bytes()).decode(),
                }
            ],
            stats,
        )

        assert found == 1
        assert stats["errors"] == []

    def test_nested_message_attachments_include_outer_depth(self):
        report = EmailMessage()
        report.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        deep = report
        for _ in range(2):
            wrapper = EmailMessage()
            wrapper.set_content("Forwarded report")
            wrapper.add_attachment(deep, filename="nested.eml")
            deep = wrapper
        client = _make_client()
        stats = initial_import_stats(client.import_context())

        found = client._process_attachments(
            "message-depth",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(deep.as_bytes()).decode(),
                }
            ],
            stats,
        )

        assert found == -1
        assert stats["details"][-1]["reason"] == "attachment_depth_exceeded"

    def test_malformed_header_bearing_multipart_stays_retryable(self):
        client = _make_client()
        stats = initial_import_stats(client.import_context())
        malformed = b"Content-Type: multipart/mixed; boundary=missing\n\nbody without delimiter"

        found = client._process_attachments(
            "message-malformed-multipart",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(malformed).decode(),
                }
            ],
            stats,
        )

        assert found == -1
        assert stats["details"][-1]["reason"] == "parse_failed"

    def test_plain_body_only_mime_stays_neutral(self):
        plain = EmailMessage()
        plain.set_content("Forwarded message without a report")
        client = _make_client()
        stats = initial_import_stats(client.import_context())

        found = client._process_attachments(
            "message-plain-body",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(plain.as_bytes()).decode(),
                }
            ],
            stats,
        )

        assert found == 0
        assert stats["errors"] == []

    def test_nested_mime_partial_failure_keeps_valid_report_retryable(self, db_session):
        nested = EmailMessage()
        nested.set_content("Attached reports")
        nested.add_attachment(
            b"not a DMARC report", maintype="application", subtype="zip", filename="bad.zip"
        )
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="good.zip"
        )
        attachment = {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "forwarded.eml",
            "contentType": "message/rfc822",
            "contentBytes": base64.b64encode(nested.as_bytes()).decode(),
        }
        client = _make_client(db=db_session)

        first_stats = initial_import_stats(client.import_context())
        second_stats = initial_import_stats(client.import_context())
        assert client._process_attachments("message-partial", [attachment], first_stats) == -1
        assert first_stats["reports_found"] == 1
        assert db_session.query(DMARCReport).count() == 1
        assert client._process_attachments("message-partial", [attachment], second_stats) == -1
        assert second_stats["duplicate_reports"] == 1

    def test_nested_mime_duplicate_only_is_successful(self, db_session):
        nested = EmailMessage()
        nested.set_content("Attached report")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="report.zip"
        )
        attachment = {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "forwarded.eml",
            "contentType": "message/rfc822",
            "contentBytes": base64.b64encode(nested.as_bytes()).decode(),
        }
        client = _make_client(db=db_session)
        first_stats = initial_import_stats(client.import_context())
        duplicate_stats = initial_import_stats(client.import_context())

        assert client._process_attachments("message-duplicate", [attachment], first_stats) == 1
        assert client._process_attachments("message-duplicate", [attachment], duplicate_stats) == 0
        assert duplicate_stats["errors"] == []
        assert duplicate_stats["duplicate_reports"] == 1

    def test_nested_mime_savepoint_keeps_session_usable_after_flush_failure(
        self, db_session, monkeypatch
    ):
        nested = EmailMessage()
        nested.set_content("Attached reports")
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="first.zip"
        )
        nested.add_attachment(
            _zip_xml(), maintype="application", subtype="zip", filename="second.zip"
        )
        client = _make_client(db=db_session)
        original_save = microsoft_graph_client.save_parsed_report
        calls = 0

        def fail_first_save(*args, **kwargs):
            nonlocal calls
            calls += 1
            saved = original_save(*args, **kwargs)
            if calls == 1:
                db = args[0]
                db.add(Domain(name=args[1]["domain"]))
                db.flush()
            return saved

        monkeypatch.setattr(microsoft_graph_client, "save_parsed_report", fail_first_save)
        stats = initial_import_stats(client.import_context())
        found = client._process_attachments(
            "message-savepoint",
            [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "forwarded.eml",
                    "contentType": "message/rfc822",
                    "contentBytes": base64.b64encode(nested.as_bytes()).decode(),
                }
            ],
            stats,
        )

        assert found == -1
        assert calls == 2
        assert stats["reports_found"] == 1
        assert db_session.query(DMARCReport).count() == 1
        assert db_session.query(Domain).filter_by(name="example.com").count() == 1

    def test_malformed_mime_attachment_keeps_message_retryable(self):
        client = _make_client()
        stats = {"details": [], "errors": []}
        content = base64.b64encode(b"not an email").decode()

        assert (
            client._process_attachments(
                "message",
                [
                    {
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": "broken.eml",
                        "contentType": "message/rfc822",
                        "contentBytes": content,
                    }
                ],
                stats,
            )
            == -1
        )
        assert stats["details"][0]["reason"] == "parse_failed"

    def test_nested_attachment_fetch_failure_keeps_message_retryable(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-nested-failure",
                                "subject": "DMARC aggregate report",
                                "hasAttachments": True,
                            }
                        ]
                    },
                )
            if url.endswith("/me/messages/message-nested-failure/attachments"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "attached-message",
                                "@odata.type": "#microsoft.graph.itemAttachment",
                                "name": "forwarded-report.eml",
                            }
                        ]
                    },
                )
            if url.endswith("/me/messages/message-nested-failure/attachments/attached-message"):
                return httpx.Response(
                    503,
                    json={"error": {"code": "ServerError", "message": "temporary failure"}},
                )
            raise AssertionError(f"Unexpected Graph request: {method} {url} {params}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        result = _make_client().fetch_reports()

        assert result["new_ingested_ids"] == []
        assert result["details"][0]["reason"] == "nested_attachment_fetch_failed"

    def test_attachment_count_limit_is_bounded(self):
        client = _make_client()
        stats = {"details": [], "errors": []}
        attachments = [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": f"report-{index}.xml",
                "contentBytes": base64.b64encode(b"bad").decode(),
            }
            for index in range(101)
        ]

        assert client._process_attachments("message", attachments, stats) == -1
        assert any(
            detail.get("reason") == "attachment_limit_exceeded" for detail in stats["details"]
        )

    def test_attachment_size_limit_is_bounded(self):
        client = _make_client()
        stats = {"details": [], "errors": []}
        oversized = base64.b64encode(b"x" * (MAX_DSN_BYTES + 1)).decode()

        assert (
            client._process_attachments(
                "message",
                [
                    {
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": "oversized.xml",
                        "contentBytes": oversized,
                    }
                ],
                stats,
            )
            == -1
        )
        assert stats["details"][0]["reason"] == "parse_failed"

    def test_fetch_reports_skips_already_ingested_message(self, monkeypatch, db_session):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-1",
                                "subject": "DMARC aggregate report",
                                "from": {"emailAddress": {"address": "reports@example.net"}},
                                "hasAttachments": True,
                            }
                        ]
                    },
                )
            raise AssertionError("Already-ingested messages should not fetch attachments")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client(db=db_session, already_ingested=["message-1"])

        result = client.fetch_reports()

        assert result["success"] is True
        assert result["processed"] == 0
        assert result["reports_found"] == 0
        assert result["new_ingested_ids"] == []

    def test_fetch_reports_handles_empty_message_id_and_plain_messages_path(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            assert url.endswith("/me/messages")
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "",
                            "subject": "DMARC aggregate report",
                            "from": {"emailAddress": {"address": "reports@example.net"}},
                            "hasAttachments": True,
                        }
                    ]
                },
            )

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = MicrosoftGraphClient(
            tenant_id="organizations",
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            folder="",
        )
        client.folder = ""

        result = client.fetch_reports()

        assert result["success"] is True
        assert result["processed"] == 0

    def test_fetch_reports_keeps_message_retryable_when_attachments_fail(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-1",
                                "subject": "DMARC aggregate report",
                                "from": {"emailAddress": {"address": "reports@example.net"}},
                                "hasAttachments": True,
                            }
                        ]
                    },
                )
            if url.endswith("/me/messages/message-1/attachments"):
                return httpx.Response(
                    500,
                    json={"error": {"code": "ServerError", "message": "temporary failure"}},
                )
            raise AssertionError(f"Unexpected Graph request: {method} {url}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client()

        result = client.fetch_reports()

        assert result["success"] is True
        assert result["processed"] == 1
        assert result["new_ingested_ids"] == []
        assert result["details"][0]["reason"] == "attachment_fetch_failed"

    def test_fetch_reports_records_attachment_outcomes(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "message-1",
                                "subject": "DMARC aggregate report",
                                "from": {"emailAddress": {"address": "reports@example.net"}},
                                "hasAttachments": True,
                            }
                        ]
                    },
                )
            if url.endswith("/me/messages/message-1/attachments"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "@odata.type": "#microsoft.graph.fileAttachment",
                                "name": "notes.txt",
                                "contentBytes": base64.b64encode(b"not dmarc").decode(),
                            },
                            {
                                "@odata.type": "#microsoft.graph.itemAttachment",
                                "name": "report.xml",
                                "contentBytes": base64.b64encode(SAMPLE_XML.encode()).decode(),
                            },
                            {
                                "@odata.type": "#microsoft.graph.fileAttachment",
                                "name": "empty.xml",
                                "contentBytes": "",
                            },
                            {
                                "@odata.type": "#microsoft.graph.fileAttachment",
                                "name": "bad.xml",
                                "contentBytes": base64.b64encode(b"<not-dmarc>").decode(),
                            },
                        ]
                    },
                )
            raise AssertionError(f"Unexpected Graph request: {method} {url}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client()

        result = client.fetch_reports()

        assert result["success"] is True
        assert result["processed"] == 1
        assert result["reports_found"] == 0
        assert result["errors"]
        reasons = {detail.get("reason") for detail in result["details"]}
        assert {
            "unsupported_attachment",
            "unsupported_attachment_type",
            "empty_attachment",
            "parse_failed",
        }.issubset(reasons)

    def test_fetch_reports_refreshes_token_after_unauthorized(self, monkeypatch):
        calls = {"messages": 0}

        def fake_post(url, data=None, timeout=None):
            assert url.endswith("/organizations/oauth2/v2.0/token")
            assert data["grant_type"] == "refresh_token"
            return httpx.Response(
                200,
                json={"access_token": "new-access", "refresh_token": "new-refresh"},
            )

        def fake_request(method, url, headers=None, params=None, timeout=None):
            if url.endswith("/me/mailFolders/inbox/messages"):
                calls["messages"] += 1
                if calls["messages"] == 1:
                    return httpx.Response(
                        401,
                        json={
                            "error": {
                                "code": "InvalidAuthenticationToken",
                                "message": "Access token has expired.",
                            }
                        },
                    )
                assert headers["Authorization"] == "Bearer new-access"
                return httpx.Response(200, json={"value": []})
            raise AssertionError(f"Unexpected Graph request: {method} {url}")

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.post", fake_post)
        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client()

        result = client.fetch_reports()

        assert result["success"] is True
        assert calls["messages"] == 2
        assert client.get_refreshed_tokens() == {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
        }

    def test_fetch_reports_uses_generic_list_error(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            return httpx.Response(
                429,
                json={"error": {"code": "TooManyRequests", "message": "Request is throttled."}},
            )

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client()

        result = client.fetch_reports()

        assert result["success"] is False
        assert result["error"] == "Failed to list Microsoft Graph messages."
        assert "TooManyRequests" not in str(result)


def test_microsoft_graph_processes_dsn_as_delivery_evidence(db_session, monkeypatch):
    workspace = Workspace(slug="m365-dsn", name="M365 DSN")
    db_session.add(workspace)
    db_session.commit()
    client = _make_client(db=db_session)
    client.workspace_id = workspace.id
    monkeypatch.setattr(client, "_request_bytes", lambda _url: _dsn_bytes())
    stats = {"errors": [], "details": []}

    imported = client._process_message(
        {"id": "m365-dsn-1", "subject": "Delivery Status Notification (Failure)"},
        stats,
    )

    assert imported == 1
    assert stats["delivery_events_found"] == 1
    assert db_session.query(DeliveryEvent).one().source_system == "m365_dsn"
