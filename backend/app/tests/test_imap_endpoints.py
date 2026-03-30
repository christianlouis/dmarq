"""
Tests for the /api/v1/imap endpoints.

Covers connection testing, report fetching (foreground and background), and status.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


class TestImapTestConnection:
    """Tests for POST /api/v1/imap/test-connection"""

    def test_successful_connection(self, authed_client: TestClient):
        mock_client = MagicMock()
        mock_client.test_connection.return_value = (
            True,
            "Connection successful",
            {
                "message_count": 5,
                "unread_count": 2,
                "dmarc_count": 1,
                "available_mailboxes": ["INBOX", "Sent"],
                "server": "imap.example.com",
                "port": 993,
            },
        )

        with patch("app.api.api_v1.endpoints.imap.IMAPClient", return_value=mock_client):
            response = authed_client.post(
                "/api/v1/imap/test-connection",
                json={
                    "server": "imap.example.com",
                    "port": 993,
                    "username": "user@example.com",
                    "password": "secret",
                    "ssl": True,
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message_count"] == 5
        assert data["unread_count"] == 2
        assert "INBOX" in data["available_mailboxes"]

    def test_failed_connection(self, authed_client: TestClient):
        mock_client = MagicMock()
        mock_client.test_connection.return_value = (False, "Connection failed", {})

        with patch("app.api.api_v1.endpoints.imap.IMAPClient", return_value=mock_client):
            response = authed_client.post(
                "/api/v1/imap/test-connection",
                json={"server": "bad.example.com", "port": 993},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert data["message_count"] == 0

    def test_requires_auth(self, client: TestClient):
        """Without auth, the endpoint should return 401."""
        response = client.post(
            "/api/v1/imap/test-connection",
            json={"server": "imap.example.com", "port": 993},
        )
        assert response.status_code == 401


class TestImapFetchReports:
    """Tests for POST /api/v1/imap/fetch-reports"""

    def test_fetch_foreground_success(self, authed_client: TestClient):
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 3,
            "reports_found": 2,
            "new_domains": ["example.com"],
            "errors": [],
        }

        with patch("app.api.api_v1.endpoints.imap.IMAPClient", return_value=mock_client):
            response = authed_client.post("/api/v1/imap/fetch-reports?days=7")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["processed_emails"] == 3
        assert data["reports_found"] == 2

    def test_fetch_days_too_low(self, authed_client: TestClient):
        response = authed_client.post("/api/v1/imap/fetch-reports?days=0")
        assert response.status_code == 400

    def test_fetch_days_too_high(self, authed_client: TestClient):
        response = authed_client.post("/api/v1/imap/fetch-reports?days=400")
        assert response.status_code == 400

    def test_fetch_background_for_long_range(self, authed_client: TestClient):
        """Days > 14 should queue a background task."""
        mock_client = MagicMock()
        with patch("app.api.api_v1.endpoints.imap.IMAPClient", return_value=mock_client):
            response = authed_client.post("/api/v1/imap/fetch-reports?days=30")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "background" in data["message"].lower()

    def test_fetch_with_errors_in_result(self, authed_client: TestClient):
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 1,
            "reports_found": 0,
            "new_domains": [],
            "errors": ["Could not parse email 1"],
        }

        with patch("app.api.api_v1.endpoints.imap.IMAPClient", return_value=mock_client):
            response = authed_client.post("/api/v1/imap/fetch-reports?days=3")

        assert response.status_code == 200
        data = response.json()
        assert data["errors"] is not None

    def test_fetch_exception_returns_500(self, authed_client: TestClient):
        mock_client = MagicMock()
        mock_client.fetch_reports.side_effect = RuntimeError("unexpected")

        with patch("app.api.api_v1.endpoints.imap.IMAPClient", return_value=mock_client):
            response = authed_client.post("/api/v1/imap/fetch-reports?days=5")

        assert response.status_code == 500

    def test_requires_auth(self, client: TestClient):
        response = client.post("/api/v1/imap/fetch-reports?days=7")
        assert response.status_code == 401


class TestImapStatus:
    """Tests for GET /api/v1/imap/status"""

    def test_status_returns_200(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/imap/status")
        assert response.status_code == 200

    def test_status_response_structure(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/imap/status")
        data = response.json()
        assert "is_running" in data
        assert "timestamp" in data

    def test_requires_auth(self, client: TestClient):
        response = client.get("/api/v1/imap/status")
        assert response.status_code == 401
