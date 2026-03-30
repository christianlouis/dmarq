"""
Tests for the /api/v1/stats endpoints.

Covers dashboard statistics and per-domain statistics with cache refresh.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


class TestDashboardStatistics:
    """Tests for GET /api/v1/stats/dashboard"""

    def test_dashboard_returns_200(self, client: TestClient):
        response = client.get("/api/v1/stats/dashboard")
        assert response.status_code == 200

    def test_dashboard_response_contains_api_version(self, client: TestClient):
        response = client.get("/api/v1/stats/dashboard")
        data = response.json()
        assert data["api_version"] == "1.0"

    def test_dashboard_response_contains_period_days(self, client: TestClient):
        response = client.get("/api/v1/stats/dashboard")
        data = response.json()
        assert data["period_days"] == 30

    def test_dashboard_period_days_query_param(self, client: TestClient):
        response = client.get("/api/v1/stats/dashboard?period_days=7")
        assert response.status_code == 200
        data = response.json()
        assert data["period_days"] == 7

    def test_dashboard_force_refresh(self, client: TestClient):
        """force_refresh=true should trigger cache invalidation without error."""
        response = client.get("/api/v1/stats/dashboard?force_refresh=true")
        assert response.status_code == 200
        data = response.json()
        assert "api_version" in data

    def test_dashboard_force_refresh_calls_invalidate_cache(self, client: TestClient):
        """Verify StatsSummarizer.invalidate_cache is called when force_refresh is set."""
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = client.get("/api/v1/stats/dashboard?force_refresh=true")
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_called_once()

    def test_dashboard_no_force_refresh_skips_invalidate(self, client: TestClient):
        """Without force_refresh, invalidate_cache should NOT be called."""
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = client.get("/api/v1/stats/dashboard")
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_not_called()


class TestDomainStatistics:
    """Tests for GET /api/v1/stats/domain/{domain_id}"""

    def test_domain_stats_returns_200(self, client: TestClient):
        response = client.get("/api/v1/stats/domain/example.com")
        assert response.status_code == 200

    def test_domain_stats_contains_api_version(self, client: TestClient):
        response = client.get("/api/v1/stats/domain/example.com")
        data = response.json()
        assert data["api_version"] == "1.0"

    def test_domain_stats_contains_period_days(self, client: TestClient):
        response = client.get("/api/v1/stats/domain/example.com")
        data = response.json()
        assert data["period_days"] == 30

    def test_domain_stats_custom_period(self, client: TestClient):
        response = client.get("/api/v1/stats/domain/example.com?period_days=14")
        assert response.status_code == 200
        data = response.json()
        assert data["period_days"] == 14

    def test_domain_stats_force_refresh(self, client: TestClient):
        response = client.get("/api/v1/stats/domain/example.com?force_refresh=true")
        assert response.status_code == 200

    def test_domain_stats_force_refresh_calls_invalidate_with_domain(
        self, client: TestClient
    ):
        """Verify invalidate_cache is called with the domain ID."""
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = client.get(
                "/api/v1/stats/domain/example.com?force_refresh=true"
            )
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_called_once_with("example.com")

    def test_domain_stats_no_force_refresh_skips_invalidate(self, client: TestClient):
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = client.get("/api/v1/stats/domain/example.com")
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_not_called()
