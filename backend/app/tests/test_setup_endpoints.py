"""
Tests for the /api/v1/setup endpoints.

Covers initial setup status, admin user setup, and system configuration.
"""

import pytest
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints.setup import setup_status
from app.core.security import _api_keys, add_api_key


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
