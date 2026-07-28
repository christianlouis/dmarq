"""Tests for the background health-assessment materialization worker."""

import pytest

from app.services import health_snapshot_refresh


@pytest.mark.asyncio
async def test_health_snapshot_refresh_materializes_active_domains(monkeypatch):
    """The worker refreshes domains outside a browser request and counts writes."""

    class Settings:
        HEALTH_SNAPSHOT_REFRESH_ENABLED = True
        HEALTH_SNAPSHOT_REFRESH_LIMIT = 3

    refreshed = []

    async def fake_refresh(domain_name, workspace_id):
        refreshed.append((domain_name, workspace_id))
        return domain_name != "unchanged.example"

    monkeypatch.setattr(health_snapshot_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        health_snapshot_refresh,
        "_active_domains",
        lambda limit: [
            (1, "fresh.example", 10),
            (2, "unchanged.example", 10),
            (3, "other.example", 20),
        ][:limit],
    )
    monkeypatch.setattr(health_snapshot_refresh, "_refresh_domain_snapshot", fake_refresh)

    assert await health_snapshot_refresh.refresh_health_score_snapshots() == 2
    assert refreshed == [
        ("fresh.example", 10),
        ("unchanged.example", 10),
        ("other.example", 20),
    ]
