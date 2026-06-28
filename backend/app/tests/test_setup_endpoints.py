"""
Tests for the /api/v1/setup endpoints.

Covers initial setup status, admin user setup, and system configuration.
"""

import pytest
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints.setup import setup_status
from app.core.security import _api_keys, add_api_key
from app.models.setting import Setting


@pytest.fixture(autouse=True)
def reset_setup_status():
    """Reset in-memory setup_status before each test to avoid state leakage."""
    original = dict(setup_status)
    setup_status["is_setup_complete"] = False
    setup_status["admin_email"] = None
    setup_status["app_name"] = "DMARQ"
    yield
    setup_status.update(original)


class TestSetupStatus:
    """Tests for GET /api/v1/setup/status"""

    def test_initial_status_not_complete(self, client: TestClient):
        response = client.get("/api/v1/setup/status")
        assert response.status_code == 200
        data = response.json()
        assert data["is_setup_complete"] is False
        assert data["app_name"] == "DMARQ"

    def test_status_after_system_setup(self, client: TestClient):
        client.post(
            "/api/v1/setup/system",
            json={"app_name": "MyApp", "base_url": "https://example.com"},
        )
        response = client.get("/api/v1/setup/status")
        data = response.json()
        assert data["is_setup_complete"] is True
        assert data["app_name"] == "MyApp"

    def test_status_reads_persisted_setup_state_after_memory_reset(
        self, client: TestClient, db_session
    ):
        db_session.add(
            Setting(
                key="setup.is_complete",
                value="true",
                description="Whether initial setup has been completed",
                value_type="boolean",
                category="setup",
            )
        )
        db_session.add(
            Setting(
                key="general.app_name",
                value="Persisted DMARQ",
                description="Application display name shown in the UI",
                value_type="string",
                category="general",
            )
        )
        db_session.commit()
        setup_status["is_setup_complete"] = False
        setup_status["app_name"] = "DMARQ"

        response = client.get("/api/v1/setup/status")

        assert response.status_code == 200
        data = response.json()
        assert data["is_setup_complete"] is True
        assert data["app_name"] == "Persisted DMARQ"


class TestSetupPage:
    """Tests for the rendered setup page."""

    def test_setup_page_renders_guided_wizard(self):
        from app.main import app as main_app

        with TestClient(main_app) as test_client:
            response = test_client.get("/setup")

        assert response.status_code == 200
        assert "First-run setup" in response.text
        assert '@submit.prevent="submitAdmin"' in response.text
        assert '@submit.prevent="submitSystem"' in response.text
        assert "/api/v1/setup/status" in response.text
        assert "/api/v1/setup/admin" in response.text
        assert "/api/v1/setup/system" in response.text
        assert "/onboarding" in response.text

    def test_onboarding_page_renders_workspace_bootstrap_flow(self):
        from unittest.mock import MagicMock, patch

        from app.main import app as main_app

        with patch("app.core.config.get_settings") as mock_get_settings:
            mock_cfg = MagicMock()
            mock_cfg.AUTH_DISABLED = True
            mock_get_settings.return_value = mock_cfg
            with TestClient(main_app) as test_client:
                response = test_client.get("/onboarding")

        assert response.status_code == 200
        assert "Workspace onboarding" in response.text
        assert "workspaceOnboarding()" in response.text
        assert "/api/v1/onboarding/preview" in response.text
        assert "/api/v1/onboarding/apply" in response.text
        assert "dmarq.selectedWorkspaceId" in response.text


class TestSetupAdmin:
    """Tests for POST /api/v1/setup/admin"""

    def test_admin_setup_succeeds_on_first_call(self, client: TestClient):
        response = client.post(
            "/api/v1/setup/admin",
            json={
                "email": "admin@example.com",
                "username": "admin",
                "password": "test-placeholder-password",
            },
        )
        assert response.status_code == 201
        assert "message" in response.json()

    def test_admin_setup_requires_auth_if_already_complete(self, client: TestClient):
        setup_status["is_setup_complete"] = True

        response = client.post(
            "/api/v1/setup/admin",
            json={
                "email": "admin2@example.com",
                "username": "admin2",
                "password": "pass",
            },
        )

        assert response.status_code == 401

    def test_admin_setup_fails_if_already_complete(self, client: TestClient):
        # Mark setup as complete
        setup_status["is_setup_complete"] = True
        api_key = "a" * 64
        add_api_key(api_key)

        try:
            response = client.post(
                "/api/v1/setup/admin",
                json={
                    "email": "admin2@example.com",
                    "username": "admin2",
                    "password": "pass",
                },
                headers={"X-API-Key": api_key},
            )
        finally:
            _api_keys.discard(api_key)

        assert response.status_code == 400
        assert "already completed" in response.json()["detail"]

    def test_admin_setup_rejects_invalid_email(self, client: TestClient):
        response = client.post(
            "/api/v1/setup/admin",
            json={
                "email": "not-an-email",
                "username": "admin",
                "password": "pass",
            },
        )
        assert response.status_code == 422


class TestSetupSystem:
    """Tests for POST /api/v1/setup/system"""

    def test_system_setup_saves_app_name(self, client: TestClient):
        response = client.post(
            "/api/v1/setup/system",
            json={"app_name": "DMARQ Custom", "base_url": "https://dmarq.example.com"},
        )
        assert response.status_code == 200
        assert "message" in response.json()
        assert setup_status["app_name"] == "DMARQ Custom"
        assert setup_status["is_setup_complete"] is True

    def test_system_setup_marks_complete(self, client: TestClient):
        assert setup_status["is_setup_complete"] is False
        client.post(
            "/api/v1/setup/system",
            json={"app_name": "Test", "base_url": "https://test.example.com"},
        )
        assert setup_status["is_setup_complete"] is True

    def test_system_setup_requires_auth_if_already_complete(self, client: TestClient):
        setup_status["is_setup_complete"] = True

        response = client.post(
            "/api/v1/setup/system",
            json={"app_name": "Changed", "base_url": "https://changed.example.com"},
        )

        assert response.status_code == 401

    def test_system_setup_requires_auth_if_persisted_complete_after_restart(
        self, client: TestClient
    ):
        first_response = client.post(
            "/api/v1/setup/system",
            json={"app_name": "DMARQ", "base_url": "https://example.com"},
        )
        assert first_response.status_code == 200
        setup_status["is_setup_complete"] = False

        response = client.post(
            "/api/v1/setup/system",
            json={"app_name": "Changed", "base_url": "https://changed.example.com"},
        )

        assert response.status_code == 401

    def test_system_setup_allows_authenticated_updates_after_complete(self, client: TestClient):
        setup_status["is_setup_complete"] = True
        api_key = "b" * 64
        add_api_key(api_key)

        try:
            response = client.post(
                "/api/v1/setup/system",
                json={"app_name": "Changed", "base_url": "https://changed.example.com"},
                headers={"X-API-Key": api_key},
            )
        finally:
            _api_keys.discard(api_key)

        assert response.status_code == 200
        assert setup_status["app_name"] == "Changed"
