"""
Tests for the /api/v1/stats endpoints.

Covers dashboard statistics and per-domain statistics with cache refresh.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints.stats import _summary_cache_key, resolve_dashboard_date_range
from app.models.workspace import Workspace


def test_summary_cache_key_includes_custom_date_bounds():
    date_range = resolve_dashboard_date_range(
        interval="custom",
        start_date="2026-06-01",
        end_date="2026-06-07",
    )

    assert _summary_cache_key(date_range) == "custom_2026-06-01_2026-06-07"


def test_summary_cache_key_partitions_open_calendar_ranges():
    date_range = resolve_dashboard_date_range(interval="week_to_date")

    assert _summary_cache_key(date_range).startswith("week_to_date_")


class TestDashboardStatistics:
    """Tests for GET /api/v1/stats/dashboard"""

    def test_dashboard_returns_200(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/dashboard")
        assert response.status_code == 200

    def test_dashboard_response_contains_api_version(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/dashboard")
        data = response.json()
        assert data["api_version"] == "1.0"

    def test_dashboard_response_contains_period_days(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/dashboard")
        data = response.json()
        assert data["period_days"] == 30

    def test_dashboard_period_days_query_param(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/dashboard?period_days=7")
        assert response.status_code == 200
        data = response.json()
        assert data["period_days"] == 7

    def test_dashboard_passes_period_days_to_summarizer(self, authed_client: TestClient):
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = authed_client.get("/api/v1/stats/dashboard?period_days=7")
            assert response.status_code == 200
            assert mock_instance.calculate_summary_statistics.call_args.kwargs["period_days"] == 7
            assert mock_instance.calculate_summary_statistics.call_args.kwargs["start_ts"]
            assert mock_instance.calculate_summary_statistics.call_args.kwargs["end_ts"]
            assert (
                mock_instance.calculate_summary_statistics.call_args.kwargs["cache_key"]
                == "last_7_days"
            )

    def test_dashboard_force_refresh(self, authed_client: TestClient):
        """force_refresh=true should trigger cache invalidation without error."""
        response = authed_client.get("/api/v1/stats/dashboard?force_refresh=true")
        assert response.status_code == 200
        data = response.json()
        assert "api_version" in data

    def test_dashboard_force_refresh_calls_invalidate_cache(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Verify StatsSummarizer.invalidate_cache is called when force_refresh is set."""
        workspace = Workspace(slug="refresh-stats", name="Refresh Stats", active=True)
        db_session.add(workspace)
        db_session.commit()
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = authed_client.get(
                "/api/v1/stats/dashboard?force_refresh=true",
                headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            )
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_called_once()
            assert mock_instance.invalidate_cache.call_args.kwargs == {"workspace_id": workspace.id}

    def test_dashboard_no_force_refresh_skips_invalidate(self, authed_client: TestClient):
        """Without force_refresh, invalidate_cache should NOT be called."""
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = authed_client.get("/api/v1/stats/dashboard")
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_not_called()

    def test_dashboard_passes_selected_workspace_to_summarizer(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = Workspace(slug="selected-stats", name="Selected Stats", active=True)
        db_session.add(workspace)
        db_session.commit()

        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = authed_client.get(
                "/api/v1/stats/dashboard",
                headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            )

        assert response.status_code == 200
        assert (
            mock_instance.calculate_summary_statistics.call_args.kwargs["workspace_id"]
            == workspace.id
        )

    def test_dashboard_rejects_invalid_selected_workspace(self, authed_client: TestClient):
        response = authed_client.get(
            "/api/v1/stats/dashboard",
            headers={"X-DMARQ-Workspace-ID": "not-an-id"},
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "X-DMARQ-Workspace-ID must be an integer"

    def test_dashboard_uses_demo_data_when_demo_mode_enabled(
        self, authed_client: TestClient, monkeypatch
    ):
        monkeypatch.setattr(
            "app.api.api_v1.endpoints.stats.get_settings",
            lambda: SimpleNamespace(DEMO_MODE=True),
        )

        response = authed_client.get("/api/v1/stats/dashboard?period_days=7&force_refresh=true")

        assert response.status_code == 200
        data = response.json()
        assert data["api_version"] == "1.0"
        assert data["period_days"] == 7
        assert data["total_domains"] == 2
        assert data["top_sources"]


class TestDomainStatistics:
    """Tests for GET /api/v1/stats/domain/{domain_id}"""

    def test_domain_stats_returns_200(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/domain/example.com")
        assert response.status_code == 200

    def test_domain_stats_contains_api_version(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/domain/example.com")
        data = response.json()
        assert data["api_version"] == "1.0"

    def test_domain_stats_contains_period_days(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/domain/example.com")
        data = response.json()
        assert data["period_days"] == 30

    def test_domain_stats_custom_period(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/domain/example.com?period_days=14")
        assert response.status_code == 200
        data = response.json()
        assert data["period_days"] == 14

    def test_domain_stats_passes_period_days_to_summarizer(self, authed_client: TestClient):
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = authed_client.get("/api/v1/stats/domain/example.com?period_days=14")
            assert response.status_code == 200
            assert mock_instance.calculate_summary_statistics.call_args.args[1] == "example.com"
            assert mock_instance.calculate_summary_statistics.call_args.kwargs["period_days"] == 14
            assert mock_instance.calculate_summary_statistics.call_args.kwargs["start_ts"]
            assert mock_instance.calculate_summary_statistics.call_args.kwargs["end_ts"]
            assert (
                mock_instance.calculate_summary_statistics.call_args.kwargs["cache_key"]
                == "last_14_days"
            )

    def test_domain_stats_force_refresh(self, authed_client: TestClient):
        response = authed_client.get("/api/v1/stats/domain/example.com?force_refresh=true")
        assert response.status_code == 200

    def test_domain_stats_force_refresh_calls_invalidate_with_domain(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Verify invalidate_cache is called with the domain ID."""
        workspace = Workspace(slug="refresh-domain-stats", name="Refresh Domain Stats", active=True)
        db_session.add(workspace)
        db_session.commit()
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = authed_client.get(
                "/api/v1/stats/domain/example.com?force_refresh=true",
                headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            )
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_called_once()
            assert mock_instance.invalidate_cache.call_args.args == ("example.com",)
            assert mock_instance.invalidate_cache.call_args.kwargs == {"workspace_id": workspace.id}

    def test_domain_stats_no_force_refresh_skips_invalidate(self, authed_client: TestClient):
        with patch("app.api.api_v1.endpoints.stats.StatsSummarizer") as MockSummarizer:
            mock_instance = MagicMock()
            mock_instance.calculate_summary_statistics.return_value = {"total": 0}
            MockSummarizer.return_value = mock_instance

            response = authed_client.get("/api/v1/stats/domain/example.com")
            assert response.status_code == 200
            mock_instance.invalidate_cache.assert_not_called()

    def test_domain_stats_uses_demo_data_when_demo_mode_enabled(
        self, authed_client: TestClient, monkeypatch
    ):
        monkeypatch.setattr(
            "app.api.api_v1.endpoints.stats.get_settings",
            lambda: SimpleNamespace(DEMO_MODE=True),
        )

        response = authed_client.get("/api/v1/stats/domain/dmarq.com?period_days=14")

        assert response.status_code == 200
        data = response.json()
        assert data["api_version"] == "1.0"
        assert data["period_days"] == 14
        assert data["domain"] == "dmarq.com"
        assert data["sources"]
