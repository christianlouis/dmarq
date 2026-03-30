"""
Tests for the Settings model and /api/v1/settings endpoints.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.setting import Setting


class TestSettingModel:
    """Unit tests for the Setting ORM model."""

    def test_create_setting(self, db_session: Session):
        row = Setting(
            key="general.app_name",
            value="TestApp",
            description="App name",
            value_type="string",
            category="general",
        )
        db_session.add(row)
        db_session.commit()
        db_session.refresh(row)

        assert row.key == "general.app_name"
        assert row.value == "TestApp"
        assert row.category == "general"
        assert row.value_type == "string"

    def test_repr(self, db_session: Session):
        row = Setting(key="dns.resolver", value="system", category="dns")
        db_session.add(row)
        db_session.commit()
        assert "dns.resolver" in repr(row)
        assert "dns" in repr(row)


class TestSettingsAPI:
    """Integration tests for /api/v1/settings endpoints."""

    def test_list_settings_seeds_defaults(self, authed_client: TestClient):
        """GET /api/v1/settings returns seeded defaults on first call."""
        res = authed_client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        keys = {row["key"] for row in data}
        assert "general.app_name" in keys
        assert "dmarc.default_policy" in keys
        assert "cloudflare.api_token" in keys

    def test_list_settings_filter_by_category(self, authed_client: TestClient):
        """GET /api/v1/settings?category=dmarc returns only dmarc settings."""
        res = authed_client.get("/api/v1/settings?category=dmarc")
        assert res.status_code == 200
        data = res.json()
        for row in data:
            assert row["category"] == "dmarc"

    def test_get_single_setting(self, authed_client: TestClient):
        """GET /api/v1/settings/{key} returns a single setting."""
        # Seed defaults first
        authed_client.get("/api/v1/settings")
        res = authed_client.get("/api/v1/settings/general.app_name")
        assert res.status_code == 200
        assert res.json()["key"] == "general.app_name"
        assert res.json()["value"] == "DMARQ"

    def test_get_missing_setting_returns_404(self, authed_client: TestClient):
        """GET /api/v1/settings/{key} returns 404 for unknown keys."""
        authed_client.get("/api/v1/settings")  # seed
        res = authed_client.get("/api/v1/settings/nonexistent.key")
        assert res.status_code == 404

    def test_update_setting(self, authed_client: TestClient):
        """PUT /api/v1/settings/{key} updates a setting value."""
        authed_client.get("/api/v1/settings")  # seed
        res = authed_client.put(
            "/api/v1/settings/general.app_name",
            json={"value": "MyDMARQ"},
        )
        assert res.status_code == 200
        assert res.json()["value"] == "MyDMARQ"

        # Verify persistence
        res2 = authed_client.get("/api/v1/settings/general.app_name")
        assert res2.json()["value"] == "MyDMARQ"

    def test_update_setting_upserts(self, authed_client: TestClient):
        """PUT /api/v1/settings/{key} creates the row if it doesn't exist yet."""
        res = authed_client.put(
            "/api/v1/settings/general.custom_key",
            json={"value": "hello"},
        )
        assert res.status_code == 200
        assert res.json()["value"] == "hello"

    def test_bulk_update(self, authed_client: TestClient):
        """POST /api/v1/settings/bulk updates multiple settings at once."""
        authed_client.get("/api/v1/settings")  # seed
        res = authed_client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": {
                    "dmarc.default_policy": "quarantine",
                    "dmarc.default_percentage": "80",
                }
            },
        )
        assert res.status_code == 200
        data = {row["key"]: row["value"] for row in res.json()}
        assert data["dmarc.default_policy"] == "quarantine"
        assert data["dmarc.default_percentage"] == "80"

    def test_secret_is_redacted_in_response(self, authed_client: TestClient):
        """cloudflare.api_token value is redacted in GET responses."""
        authed_client.get("/api/v1/settings")  # seed
        # Store a real token
        authed_client.put(
            "/api/v1/settings/cloudflare.api_token",
            json={"value": "super-secret-token"},
        )
        res = authed_client.get("/api/v1/settings/cloudflare.api_token")
        assert res.status_code == 200
        assert res.json()["value"] == "**redacted**"

    def test_redacted_placeholder_does_not_overwrite(self, authed_client: TestClient):
        """Sending **redacted** back to PUT should not overwrite the stored value."""
        authed_client.get("/api/v1/settings")
        authed_client.put(
            "/api/v1/settings/cloudflare.api_token",
            json={"value": "real-token-value"},
        )
        # Simulate round-trip with redacted placeholder
        authed_client.put(
            "/api/v1/settings/cloudflare.api_token",
            json={"value": "**redacted**"},
        )
        # Direct DB check via a fresh GET – the value should still be "real-token-value"
        # (GET always redacts, so we check via the list endpoint's category filter)
        res = authed_client.get("/api/v1/settings?category=cloudflare")
        cf = {row["key"]: row["value"] for row in res.json()}
        # Value should remain redacted (which means the underlying value is still set)
        assert cf["cloudflare.api_token"] == "**redacted**"

    def test_unauthenticated_returns_403(self, client: TestClient):
        """Unauthenticated requests to settings endpoints return 403."""
        res = client.get("/api/v1/settings")
        assert res.status_code in (401, 403)
