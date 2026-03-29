"""
Tests for MailSource model and mail-sources API endpoints.
"""

import asyncio
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.mail_source import MailSource


class TestMailSourceModel:
    """Unit tests for the MailSource ORM model."""

    def test_create_mail_source(self, db_session: Session):
        source = MailSource(
            name="Test IMAP",
            method="IMAP",
            server="imap.example.com",
            port=993,
            username="user@example.com",
            password="secret",
            use_ssl=True,
            folder="INBOX",
            polling_interval=60,
            enabled=True,
        )
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        assert source.id is not None
        assert source.name == "Test IMAP"
        assert source.method == "IMAP"
        assert source.server == "imap.example.com"
        assert source.port == 993
        assert source.username == "user@example.com"
        assert source.password == "secret"
        assert source.use_ssl is True
        assert source.folder == "INBOX"
        assert source.polling_interval == 60
        assert source.enabled is True
        assert source.last_checked is None

    def test_default_values(self, db_session: Session):
        source = MailSource(name="Minimal", method="IMAP")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        assert source.folder == "INBOX"  # model default
        assert source.enabled is True
        assert source.last_checked is None

    def test_repr(self, db_session: Session):
        source = MailSource(name="Demo", method="POP3")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        rep = repr(source)
        assert "Demo" in rep
        assert "POP3" in rep

    def test_multiple_sources(self, db_session: Session):
        for i in range(3):
            db_session.add(MailSource(name=f"Source {i}", method="IMAP"))
        db_session.commit()

        all_sources = db_session.query(MailSource).all()
        assert len(all_sources) == 3


class TestMailSourcesAPI:
    """Integration tests for /api/v1/mail-sources endpoints (no auth)."""

    def test_list_requires_auth(self, client: TestClient):
        resp = client.get("/api/v1/mail-sources")
        # Without auth, expect 401 or 403
        assert resp.status_code in (401, 403)

    def test_create_requires_auth(self, client: TestClient):
        resp = client.post("/api/v1/mail-sources", json={"name": "x", "method": "IMAP"})
        assert resp.status_code in (401, 403)

    def test_model_create_and_list(self, client: TestClient, db_session: Session):
        """Create a mail source directly in DB and verify it's retrievable."""
        source = MailSource(
            name="Direct DB Source",
            method="IMAP",
            server="imap.example.com",
            port=993,
            username="user@example.com",
            password="secret",
            use_ssl=True,
            folder="INBOX",
            polling_interval=60,
            enabled=True,
        )
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        assert source.id is not None
        fetched = db_session.query(MailSource).filter_by(name="Direct DB Source").first()
        assert fetched is not None
        assert fetched.server == "imap.example.com"

    def test_toggle_enabled(self, db_session: Session):
        source = MailSource(name="Toggle Test", method="IMAP", enabled=True)
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        # Simulate toggle
        source.enabled = not source.enabled
        db_session.commit()
        db_session.refresh(source)

        assert source.enabled is False

        source.enabled = not source.enabled
        db_session.commit()
        db_session.refresh(source)

        assert source.enabled is True

    def test_delete_source(self, db_session: Session):
        source = MailSource(name="To Delete", method="IMAP")
        db_session.add(source)
        db_session.commit()
        sid = source.id

        db_session.delete(source)
        db_session.commit()

        fetched = db_session.query(MailSource).filter_by(id=sid).first()
        assert fetched is None

    def test_query_enabled_sources(self, db_session: Session):
        db_session.add(MailSource(name="Enabled A", method="IMAP", enabled=True))
        db_session.add(MailSource(name="Enabled B", method="IMAP", enabled=True))
        db_session.add(MailSource(name="Disabled", method="IMAP", enabled=False))
        db_session.commit()

        enabled = db_session.query(MailSource).filter(MailSource.enabled).all()
        assert len(enabled) == 2
        names = {s.name for s in enabled}
        assert "Enabled A" in names
        assert "Enabled B" in names
        assert "Disabled" not in names


# ---------------------------------------------------------------------------
# Authenticated HTTP API tests (uses authed_client fixture from conftest)
# ---------------------------------------------------------------------------


class TestMailSourcesAPIAuthed:
    """HTTP-level tests using the authed_client fixture (auth dependency bypassed)."""

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def test_list_empty(self, authed_client: TestClient):
        resp = authed_client.get("/api/v1/mail-sources")
        assert resp.status_code == 200
        assert resp.json() == []

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def test_create_imap_source(self, authed_client: TestClient):
        payload = {
            "name": "My IMAP",
            "method": "IMAP",
            "server": "imap.example.com",
            "port": 993,
            "username": "user@example.com",
            "password": "s3cr3t",
            "use_ssl": True,
            "folder": "INBOX",
            "polling_interval": 60,
            "enabled": True,
        }
        resp = authed_client.post("/api/v1/mail-sources", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My IMAP"
        assert data["method"] == "IMAP"
        assert data["server"] == "imap.example.com"
        assert data["password"] == "**redacted**"
        assert data["id"] is not None

    def test_create_normalizes_method_to_uppercase(self, authed_client: TestClient):
        payload = {"name": "lowercase method", "method": "imap"}
        resp = authed_client.post("/api/v1/mail-sources", json=payload)
        assert resp.status_code == 201
        assert resp.json()["method"] == "IMAP"

    # ------------------------------------------------------------------
    # Get single
    # ------------------------------------------------------------------

    def test_get_existing_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Get Test", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == source_id
        assert resp.json()["name"] == "Get Test"

    def test_get_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.get("/api/v1/mail-sources/99999")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def test_update_name(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Original", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        update_resp = authed_client.put(
            f"/api/v1/mail-sources/{source_id}", json={"name": "Updated"}
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["name"] == "Updated"

    def test_update_method_normalizes_uppercase(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "MethodTest", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        update_resp = authed_client.put(
            f"/api/v1/mail-sources/{source_id}", json={"method": "pop3"}
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["method"] == "POP3"

    def test_update_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.put("/api/v1/mail-sources/99999", json={"name": "x"})
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def test_delete_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Delete Me", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        del_resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}")
        assert del_resp.status_code == 204

        # Verify gone
        get_resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert get_resp.status_code == 404

    def test_delete_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.delete("/api/v1/mail-sources/99999")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # List after creates
    # ------------------------------------------------------------------

    def test_list_multiple_sources(self, authed_client: TestClient):
        for i in range(3):
            authed_client.post(
                "/api/v1/mail-sources", json={"name": f"Source {i}", "method": "IMAP"}
            )
        resp = authed_client.get("/api/v1/mail-sources")
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    # ------------------------------------------------------------------
    # Toggle
    # ------------------------------------------------------------------

    def test_toggle_disables_then_enables(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Toggle", "method": "IMAP", "enabled": True}
        )
        source_id = create_resp.json()["id"]

        toggle_resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/toggle")
        assert toggle_resp.status_code == 200
        assert toggle_resp.json()["enabled"] is False

        toggle_resp2 = authed_client.post(f"/api/v1/mail-sources/{source_id}/toggle")
        assert toggle_resp2.status_code == 200
        assert toggle_resp2.json()["enabled"] is True

    def test_toggle_nonexistent_returns_404(self, authed_client: TestClient):
        resp = authed_client.post("/api/v1/mail-sources/99999/toggle")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Test stored source
    # ------------------------------------------------------------------

    def test_test_stored_imap_source_success(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "IMAP Test",
                "method": "IMAP",
                "server": "imap.example.com",
                "username": "u",
                "password": "p",
            },
        )
        source_id = create_resp.json()["id"]

        mock_stats = {
            "message_count": 10,
            "unread_count": 2,
            "dmarc_count": 1,
            "available_mailboxes": ["INBOX"],
        }
        mock_client = MagicMock()
        mock_client.test_connection.return_value = (True, "Connection successful", mock_stats)

        with patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_client):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["message"] == "Connection successful"
        assert data["message_count"] == 10

    def test_test_stored_imap_source_failure(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP Fail", "method": "IMAP", "server": "bad.host"},
        )
        source_id = create_resp.json()["id"]

        mock_client = MagicMock()
        mock_client.test_connection.return_value = (
            False,
            "Connection failed. Check server address and credentials.",
            {},
        )

        with patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_client):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False

    def test_test_stored_non_imap_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "POP3 Source", "method": "POP3"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "not yet implemented" in data["message"]

    def test_test_stored_nonexistent_returns_404(self, authed_client: TestClient):
        resp = authed_client.post("/api/v1/mail-sources/99999/test")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Ad-hoc test connection
    # ------------------------------------------------------------------

    def test_adhoc_imap_success(self, authed_client: TestClient):
        payload = {
            "server": "imap.example.com",
            "port": 993,
            "username": "user@example.com",
            "password": "secret",
            "ssl": True,
            "method": "IMAP",
        }
        mock_stats = {
            "message_count": 5,
            "unread_count": 1,
            "dmarc_count": 0,
            "available_mailboxes": ["INBOX"],
        }
        mock_client = MagicMock()
        mock_client.test_connection.return_value = (True, "Connection successful", mock_stats)

        with patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_client):
            resp = authed_client.post("/api/v1/mail-sources/test-connection", json=payload)

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["message_count"] == 5

    def test_adhoc_non_imap_returns_not_implemented(self, authed_client: TestClient):
        payload = {
            "server": "pop3.example.com",
            "port": 110,
            "username": "u",
            "password": "p",
            "ssl": False,
            "method": "POP3",
        }
        resp = authed_client.post("/api/v1/mail-sources/test-connection", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "not yet implemented" in data["message"]

    def test_adhoc_gmail_api_returns_not_implemented(self, authed_client: TestClient):
        payload = {"method": "GMAIL_API"}
        resp = authed_client.post("/api/v1/mail-sources/test-connection", json=payload)
        assert resp.status_code == 200
        assert resp.json()["success"] is False
        assert "not yet implemented" in resp.json()["message"]


# ---------------------------------------------------------------------------
# Gmail API-specific tests
# ---------------------------------------------------------------------------


class TestGmailAPIMailSource:
    """Tests for GMAIL_API mail source creation, OAuth flow, and fetching."""

    def test_create_gmail_api_source(self, authed_client: TestClient):
        payload = {
            "name": "My Gmail",
            "method": "GMAIL_API",
            "gmail_client_id": "123-abc.apps.googleusercontent.com",
            "gmail_client_secret": "GOCSPX-secret",
            "polling_interval": 30,
            "enabled": True,
        }
        resp = authed_client.post("/api/v1/mail-sources", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["method"] == "GMAIL_API"
        assert data["gmail_client_id"] == "123-abc.apps.googleusercontent.com"
        # Secret should be redacted in response
        assert data["gmail_client_secret"] == "**redacted**"
        assert data["gmail_connected"] is False
        assert data["gmail_email"] is None

    def test_gmail_source_test_no_token(self, authed_client: TestClient):
        """Test a GMAIL_API source that has no OAuth tokens yet."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Unauthed Gmail", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "not yet authorised" in data["message"].lower() or "oauth" in data["message"].lower()

    def test_gmail_source_test_with_valid_token(self, authed_client: TestClient):
        """Test a GMAIL_API source that has valid OAuth tokens (mocked)."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Authed Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "my-client-id",
                "gmail_client_secret": "my-secret",
            },
        )
        source_id = create_resp.json()["id"]

        # Use the authed_client's DB override — patch the ORM object instead
        mock_service = MagicMock()
        mock_service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "test@gmail.com"
        }
        mock_gmail_client = MagicMock()
        mock_gmail_client._build_service.return_value = mock_service

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient",
            return_value=mock_gmail_client,
        ):
            # First set the access token directly
            with patch(
                "app.api.api_v1.endpoints.mail_sources._get_source_or_404"
            ) as mock_get:
                mock_source = MagicMock()
                mock_source.method = "GMAIL_API"
                mock_source.gmail_access_token = "valid-token"
                mock_source.gmail_email = "test@gmail.com"
                mock_source.gmail_client_id = "my-client-id"
                mock_source.gmail_client_secret = "my-secret"
                mock_source.gmail_refresh_token = "refresh-token"
                mock_get.return_value = mock_source

                resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "valid" in data["message"].lower()

    def test_gmail_authorize_url_no_client_id(self, authed_client: TestClient):
        """Requesting authorize-url without a client_id returns 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "No Client ID Gmail", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/authorize-url")
        assert resp.status_code == 400

    def test_gmail_authorize_url_wrong_method(self, authed_client: TestClient):
        """Requesting authorize-url on a non-GMAIL_API source returns 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP Source", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/authorize-url")
        assert resp.status_code == 400

    def test_gmail_authorize_url_returns_google_url(self, authed_client: TestClient):
        """A GMAIL_API source with client_id returns a valid Google auth URL."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Ready Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "123-abc.apps.googleusercontent.com",
            },
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/authorize-url")
        assert resp.status_code == 200
        data = resp.json()
        assert "authorization_url" in data
        _parsed = urlparse(data["authorization_url"])
        assert _parsed.hostname == "accounts.google.com"
        assert parse_qs(_parsed.query).get("client_id") == ["123-abc.apps.googleusercontent.com"]
        assert "gmail.readonly" in data["authorization_url"]

    def test_gmail_disconnect_clears_tokens(self, authed_client: TestClient):
        """DELETE /gmail/connection clears stored OAuth tokens."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Disconnect Test", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}/gmail/connection")
        assert resp.status_code == 204

    def test_gmail_disconnect_wrong_method_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP2", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]
        resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}/gmail/connection")
        assert resp.status_code == 400

    def test_gmail_fetch_no_token_returns_400(self, authed_client: TestClient):
        """Fetch without OAuth tokens returns 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "No Token Gmail", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")
        assert resp.status_code == 400

    def test_gmail_fetch_wrong_method_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP3", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]
        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")
        assert resp.status_code == 400

    def test_gmail_fetch_with_mocked_client(self, authed_client: TestClient):
        """Fetch with valid token (mocked GmailClient) returns success summary."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Fetch Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "cid",
                "gmail_client_secret": "csec",
            },
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": True,
            "processed": 3,
            "reports_found": 2,
            "new_domains": ["example.com"],
            "errors": [],
            "new_ingested_ids": ["id1", "id2", "id3"],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = None

        with patch(
            "app.api.api_v1.endpoints.mail_sources._get_source_or_404"
        ) as mock_get, patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client
        ):
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_refresh_token = "refresh"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = "[]"
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["processed"] == 3
        assert data["reports_found"] == 2
        assert data["new_domains"] == ["example.com"]


# ---------------------------------------------------------------------------
# GmailClient unit tests
# ---------------------------------------------------------------------------


class TestGmailClientHelpers:
    """Unit tests for GmailClient static helpers."""

    def test_load_ingested_ids_empty_string(self):
        from app.services.gmail_client import GmailClient

        assert GmailClient.load_ingested_ids("") == []

    def test_load_ingested_ids_none(self):
        from app.services.gmail_client import GmailClient

        assert GmailClient.load_ingested_ids(None) == []

    def test_load_ingested_ids_valid_json(self):
        from app.services.gmail_client import GmailClient

        result = GmailClient.load_ingested_ids('["id1", "id2"]')
        assert result == ["id1", "id2"]

    def test_load_ingested_ids_invalid_json(self):
        from app.services.gmail_client import GmailClient

        assert GmailClient.load_ingested_ids("not-json") == []

    def test_dump_ingested_ids(self):
        from app.services.gmail_client import GmailClient

        result = GmailClient.dump_ingested_ids(["id1", "id2"])
        assert '"id1"' in result
        assert '"id2"' in result

    def test_build_authorization_url(self):
        from app.services.gmail_client import GmailClient

        url = GmailClient.build_authorization_url(
            client_id="test-client-id",
            redirect_uri="https://example.com/callback",
            state="42",
        )
        assert urlparse(url).hostname == "accounts.google.com"
        assert "test-client-id" in url
        assert "gmail.readonly" in url
        assert "offline" in url
        assert "consent" in url

    def test_build_authorization_url_no_state(self):
        from app.services.gmail_client import GmailClient

        url = GmailClient.build_authorization_url(
            client_id="cid",
            redirect_uri="https://example.com/cb",
        )
        assert "state=" not in url


# ---------------------------------------------------------------------------
# _sanitize_for_log helper
# ---------------------------------------------------------------------------


class TestSanitizeForLog:
    """Unit tests for the _sanitize_for_log helper."""

    def test_strips_newline(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert "\n" not in _sanitize_for_log("hello\nworld")

    def test_strips_carriage_return(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert "\r" not in _sanitize_for_log("foo\rbar")

    def test_integer_is_safe(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert _sanitize_for_log(42) == "42"

    def test_normal_string_unchanged(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert _sanitize_for_log("example.com") == "example.com"


# ---------------------------------------------------------------------------
# Source-to-response helper (password masking)
# ---------------------------------------------------------------------------


class TestSourceToResponse:
    """Tests for the _source_to_response password-masking helper."""

    def test_password_is_redacted_when_set(self, db_session: Session):
        from app.api.api_v1.endpoints.mail_sources import _source_to_response

        source = MailSource(name="Redact Test", method="IMAP", password="plaintext")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        response = _source_to_response(source)
        assert response.password == "**redacted**"

    def test_password_is_none_when_not_set(self, db_session: Session):
        from app.api.api_v1.endpoints.mail_sources import _source_to_response

        source = MailSource(name="No Password", method="IMAP")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        response = _source_to_response(source)
        assert response.password is None


# ---------------------------------------------------------------------------
# HTML page route – mail_sources_page
# ---------------------------------------------------------------------------


def test_mail_sources_page_template_response():
    """Verify mail_sources_page uses the new-style TemplateResponse(request, name) API.

    Regression test for the 500 error caused by the old-style
    ``TemplateResponse("mail_sources.html", {"request": request})`` call, which
    passed a dict as the template name and triggered
    ``TypeError: unhashable type: 'dict'`` in Jinja2's LRU cache.
    """
    from app.main import mail_sources_page  # module-level route function

    mock_request = MagicMock()
    with patch("app.main.templates") as mock_templates:
        mock_response = MagicMock()
        mock_templates.TemplateResponse.return_value = mock_response

        result = asyncio.run(mail_sources_page(mock_request))

    mock_templates.TemplateResponse.assert_called_once_with(mock_request, "mail_sources.html")
    assert result is mock_response


# ---------------------------------------------------------------------------
# Gmail OAuth2 GET callback tests
# ---------------------------------------------------------------------------


class TestGmailCallbackGet:
    """Tests for the browser-redirect GET /gmail/callback endpoint."""

    def test_callback_error_param_returns_html_400(self, authed_client: TestClient):
        """Google reports an error – return a user-facing HTML error page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB Error", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(
            f"/api/v1/mail-sources/{source_id}/gmail/callback?error=access_denied",
        )
        assert resp.status_code == 400
        assert "authorisation failed" in resp.text.lower() or "failed" in resp.text.lower()

    def test_callback_missing_code_returns_html_400(self, authed_client: TestClient):
        """No code in the redirect – return a user-facing HTML error page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB NoCode", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/callback")
        assert resp.status_code == 400

    def test_callback_unknown_source_returns_html_404(self, authed_client: TestClient):
        """Source ID does not exist – return a user-facing HTML 404 page."""
        resp = authed_client.get("/api/v1/mail-sources/99999/gmail/callback?code=xyz")
        assert resp.status_code == 404

    def test_callback_non_gmail_source_returns_html_404(self, authed_client: TestClient):
        """Source is not a GMAIL_API source – return HTML 404."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP CB", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(
            f"/api/v1/mail-sources/{source_id}/gmail/callback?code=xyz"
        )
        assert resp.status_code == 404

    def test_callback_token_exchange_error_returns_html_400(self, authed_client: TestClient):
        """Token exchange raises ValueError – return a user-facing HTML error page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB TokenErr", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            side_effect=ValueError("bad token"),
        ):
            resp = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc"
            )

        assert resp.status_code == 400
        assert "token exchange failed" in resp.text.lower() or "failed" in resp.text.lower()

    def test_callback_no_access_token_returns_html_400(self, authed_client: TestClient):
        """Exchange succeeds but Google returns no access token – HTML 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB NoAccess", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            return_value={},  # empty – no access_token key
        ):
            resp = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc"
            )

        assert resp.status_code == 400

    def test_callback_success_saves_tokens_and_returns_html(self, authed_client: TestClient):
        """Successful callback stores tokens and returns a success HTML page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB Success", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            return_value={"access_token": "acc", "refresh_token": "ref"},
        ), patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.get_gmail_email",
            return_value="user@gmail.com",
        ):
            resp = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc"
            )

        assert resp.status_code == 200
        assert "connected successfully" in resp.text.lower() or "gmail" in resp.text.lower()

        # Tokens should have been persisted
        get_resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert get_resp.json()["gmail_connected"] is True
        assert get_resp.json()["gmail_email"] == "user@gmail.com"

    def test_callback_success_without_email(self, authed_client: TestClient):
        """Successful callback where get_gmail_email returns None still saves token."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB NoEmail", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            return_value={"access_token": "acc"},  # no refresh token
        ), patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.get_gmail_email",
            return_value=None,
        ):
            resp = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc"
            )

        assert resp.status_code == 200
        get_resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert get_resp.json()["gmail_connected"] is True


# ---------------------------------------------------------------------------
# Gmail OAuth2 POST callback tests
# ---------------------------------------------------------------------------


class TestGmailCallbackPost:
    """Tests for the JSON/programmatic POST /gmail/callback endpoint."""

    def test_post_callback_wrong_method_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP CB Post", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/gmail/callback",
            json={"code": "abc", "redirect_uri": "https://example.com/cb"},
        )
        assert resp.status_code == 400

    def test_post_callback_token_exchange_error_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Post TokenErr", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            side_effect=ValueError("bad exchange"),
        ):
            resp = authed_client.post(
                f"/api/v1/mail-sources/{source_id}/gmail/callback",
                json={"code": "abc", "redirect_uri": "https://example.com/cb"},
            )

        assert resp.status_code == 400

    def test_post_callback_no_access_token_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Post NoAccess", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            return_value={},
        ):
            resp = authed_client.post(
                f"/api/v1/mail-sources/{source_id}/gmail/callback",
                json={"code": "abc", "redirect_uri": "https://example.com/cb"},
            )

        assert resp.status_code == 400

    def test_post_callback_success_returns_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Post Success", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            return_value={"access_token": "acc", "refresh_token": "ref"},
        ), patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.get_gmail_email",
            return_value="user@gmail.com",
        ):
            resp = authed_client.post(
                f"/api/v1/mail-sources/{source_id}/gmail/callback",
                json={"code": "abc", "redirect_uri": "https://example.com/cb"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["gmail_connected"] is True
        assert data["gmail_email"] == "user@gmail.com"

    def test_post_callback_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.post(
            "/api/v1/mail-sources/99999/gmail/callback",
            json={"code": "abc", "redirect_uri": "https://example.com/cb"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Additional Gmail fetch tests
# ---------------------------------------------------------------------------


class TestGmailFetchExtra:
    """Extra fetch tests covering error and token-refresh branches."""

    def test_gmail_fetch_with_errors_returns_error_count(self, authed_client: TestClient):
        """Fetch that produces errors returns error_count rather than raw messages."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch Errors", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": False,
            "processed": 1,
            "reports_found": 0,
            "new_domains": [],
            "errors": ["failed to decode attachment A", "failed to decode attachment B"],
            "new_ingested_ids": [],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = None

        with patch(
            "app.api.api_v1.endpoints.mail_sources._get_source_or_404"
        ) as mock_get, patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client
        ):
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_refresh_token = "ref"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = "[]"
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        data = resp.json()
        assert data["error_count"] == 2
        # Raw error strings must NOT appear in the response
        assert "errors" not in data or isinstance(data.get("errors"), int)
        assert "failed to decode attachment A" not in str(data)

    def test_gmail_fetch_with_refreshed_tokens_saves_them(self, authed_client: TestClient):
        """Fetch that returns refreshed tokens persists the new tokens."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch Refresh", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "errors": [],
            "new_ingested_ids": [],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = {
            "access_token": "new_access",
            "refresh_token": "new_refresh",
        }

        with patch(
            "app.api.api_v1.endpoints.mail_sources._get_source_or_404"
        ) as mock_get, patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client
        ):
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "old_tok"
            mock_source.gmail_refresh_token = "old_ref"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = "[]"
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        # Tokens should have been updated on the source object
        assert mock_source.gmail_access_token == "new_access"
        assert mock_source.gmail_refresh_token == "new_refresh"

    def test_gmail_fetch_ingested_ids_are_merged(self, authed_client: TestClient):
        """New ingested IDs are merged with existing ones without duplicates."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch IDs", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": True,
            "processed": 2,
            "reports_found": 2,
            "new_domains": ["domain.example"],
            "errors": [],
            "new_ingested_ids": ["id2", "id3"],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = None

        with patch(
            "app.api.api_v1.endpoints.mail_sources._get_source_or_404"
        ) as mock_get, patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client
        ) as mock_gmail_class:
            # Configure the class-level static helpers used inside the endpoint
            mock_gmail_class.load_ingested_ids.return_value = ["id1"]
            mock_gmail_class.dump_ingested_ids.return_value = '["id1","id2","id3"]'

            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_refresh_token = "ref"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = '["id1"]'  # pre-existing ID
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        # dump_ingested_ids should have been called with all 3 IDs merged
        args, _ = mock_gmail_class.dump_ingested_ids.call_args
        merged_ids = args[0]
        assert "id1" in merged_ids
        assert "id2" in merged_ids
        assert "id3" in merged_ids


# ---------------------------------------------------------------------------
# Gmail test-connection exception branch
# ---------------------------------------------------------------------------


class TestGmailTestConnectionFailure:
    """Tests for the Gmail API test failure (exception) branch."""

    def test_gmail_test_with_exception_returns_generic_message(self, authed_client: TestClient):
        """When _build_service().execute() raises, return a generic error without the stack trace."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Gmail Exc Test", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_service = MagicMock()
        mock_service.users.return_value.getProfile.return_value.execute.side_effect = (
            Exception("internal oauth error: token expired")
        )
        mock_gmail_client = MagicMock()
        mock_gmail_client._build_service.return_value = mock_service

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient",
            return_value=mock_gmail_client,
        ), patch(
            "app.api.api_v1.endpoints.mail_sources._get_source_or_404"
        ) as mock_get:
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_email = None
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_refresh_token = "ref"
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        # Stack-trace / raw exception text must NOT be exposed to callers
        assert "internal oauth error" not in data["message"]
        assert "token expired" not in data["message"]
        assert "check server logs" in data["message"].lower()


# ---------------------------------------------------------------------------
# Pytest marker to avoid warnings for test methods without assertions
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.usefixtures("_reset_report_store")
