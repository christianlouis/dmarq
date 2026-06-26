from fastapi.testclient import TestClient

from app.services.demo_data import build_demo_multi_user_deployment


def test_demo_multi_user_deployment_has_saas_and_isp_scenarios():
    deployment = build_demo_multi_user_deployment()

    organizations = {org["slug"]: org for org in deployment["organizations"]}
    assert {"dmarq-foundation", "dmarq-commercial", "northstar-isp"} <= set(organizations)
    assert organizations["dmarq-foundation"]["billing_mode"] == "direct_stripe"
    assert organizations["northstar-isp"]["billing_mode"] == "provider_resale"
    assert organizations["dmarq-foundation"]["workspaces"][0]["domains"] == ["dmarq.org"]
    assert organizations["dmarq-commercial"]["workspaces"][0]["domains"] == ["dmarq.com"]
    assert any(scenario["label"] == "ISP operator" for scenario in deployment["viewer_scenarios"])


def test_operator_demo_multi_user_endpoint_returns_showcase(
    authed_client: TestClient,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.operator.get_settings",
        lambda: type("Settings", (), {"DEMO_MODE": True})(),
    )

    response = authed_client.get("/api/v1/operator/demo/multi-user")

    assert response.status_code == 200
    payload = response.json()
    assert payload["deployment"]["organizations"][0]["slug"] == "dmarq-foundation"
    assert payload["deployment"]["billing_modes"][0]["mode"] == "direct_stripe"


def test_operator_demo_multi_user_endpoint_is_hidden_outside_demo_mode(
    authed_client: TestClient,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.operator.get_settings",
        lambda: type("Settings", (), {"DEMO_MODE": False})(),
    )

    response = authed_client.get("/api/v1/operator/demo/multi-user")

    assert response.status_code == 404
