"""Workspace preference tests for the opt-in guided dashboard."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.models.workspace import Workspace


def test_guided_dashboard_stays_disabled_when_the_deployment_flag_is_off(
    authed_client: TestClient,
    db_session,
):
    workspace = Workspace(
        slug="guidance-off",
        name="Guidance off",
        guided_mail_health_enabled=True,
    )
    db_session.add(workspace)
    db_session.commit()

    response = authed_client.get(
        "/api/v1/workspaces/guidance",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    assert response.json()["available"] is False
    assert response.json()["enabled"] is False
    assert response.json()["requested_enabled"] is True


def test_guided_dashboard_preference_can_be_opted_into_per_workspace(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    workspace = Workspace(slug="guidance-on", name="Guidance on")
    db_session.add(workspace)
    db_session.commit()
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.workspaces.get_settings",
        lambda: SimpleNamespace(GUIDED_MAIL_HEALTH_UI_ENABLED=True),
    )

    response = authed_client.put(
        "/api/v1/workspaces/guidance",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
        json={"enabled": True, "depth": "guided", "context": "watch"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "available": True,
        "enabled": True,
        "requested_enabled": True,
        "depth": "guided",
        "context": "watch",
    }
    db_session.refresh(workspace)
    assert workspace.guided_mail_health_enabled is True
