"""Unit tests for app.services.microsoft_graph_client.MicrosoftGraphClient."""

import base64
import zipfile
from io import BytesIO

import httpx

from app.models.report import DMARCReport
from app.services.mail_connector import initial_import_stats
from app.services.microsoft_graph_client import M365_SCOPES, MicrosoftGraphClient
from app.tests.test_data import SAMPLE_XML


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


class TestMicrosoftGraphOAuthHelpers:
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
        assert "client_id=client-id" in url
        assert "response_type=code" in url
        assert "offline_access" in url
        assert "User.Read" in url
        assert "Mail.Read" in url
        assert "Mail.Read.Shared" in url
        assert "state=42" in url

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

    def test_fetch_reports_surfaces_throttling_error(self, monkeypatch):
        def fake_request(method, url, headers=None, params=None, timeout=None):
            return httpx.Response(
                429,
                json={"error": {"code": "TooManyRequests", "message": "Request is throttled."}},
            )

        monkeypatch.setattr("app.services.microsoft_graph_client.httpx.request", fake_request)
        client = _make_client()

        result = client.fetch_reports()

        assert result["success"] is False
        assert "TooManyRequests" in result["error"]
