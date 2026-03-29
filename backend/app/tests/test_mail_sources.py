"""
Tests for MailSource model and mail-sources API endpoints.
"""

from unittest.mock import MagicMock, patch

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
# Pytest marker to avoid warnings for test methods without assertions
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.usefixtures("_reset_report_store")
