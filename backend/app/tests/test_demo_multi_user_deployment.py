from fastapi.testclient import TestClient

from app.services.demo_data import build_demo_multi_user_deployment


class _DemoSettings:
    def __init__(self, demo_mode: bool):
        self.DEMO_MODE = demo_mode


def _settings_with_demo_enabled():
    return _DemoSettings(demo_mode=True)


def _settings_with_demo_disabled():
    return _DemoSettings(demo_mode=False)


def test_demo_multi_user_deployment_has_saas_and_isp_scenarios():
    deployment = build_demo_multi_user_deployment()

    organizations = {org["slug"]: org for org in deployment["organizations"]}
    assert {
        "dmarq-foundation",
        "dmarq-commercial",
        "northstar-isp",
        "studio-self-hosted",
    } <= set(organizations)
    assert organizations["dmarq-foundation"]["billing_mode"] == "direct_stripe"
    assert organizations["northstar-isp"]["billing_mode"] == "provider_resale"
    foundation_domains = {
        domain
        for workspace in organizations["dmarq-foundation"]["workspaces"]
        for domain in workspace["domains"]
    }
    assert {"dmarq.org", "dmarq.com"} <= foundation_domains
    assert organizations["dmarq-commercial"]["workspaces"][0]["domains"] == ["dmarq.com"]
    assert any(scenario["label"] == "ISP operator" for scenario in deployment["viewer_scenarios"])


def test_demo_multi_user_deployment_includes_billing_profiles_and_entitlements():
    deployment = build_demo_multi_user_deployment()

    organizations = {org["slug"]: org for org in deployment["organizations"]}
    foundation = organizations["dmarq-foundation"]
    commercial = organizations["dmarq-commercial"]
    northstar = organizations["northstar-isp"]
    self_hosted = organizations["studio-self-hosted"]

    assert foundation["billing_profile"]["collection_model"] == "self_service_subscription"
    assert foundation["billing_profile"]["payment_rail"] == "card_on_file"
    assert foundation["entitlements"]["aggregate_messages"]["included"] == 1_000_000
    assert commercial["billing_profile"]["collection_model"] == "contract_invoice"
    assert commercial["billing_profile"]["payment_rail"] == "bank_transfer"
    assert northstar["billing_profile"]["collection_model"] == "provider_pass_through"
    assert northstar["billing_profile"]["payment_rail"] == "isp_monthly_invoice"
    assert northstar["entitlements"]["customer_workspaces"]["used"] == 42
    assert self_hosted["billing_profile"]["collection_model"] == "none"
    assert self_hosted["billing_profile"]["invoice_owner"] == "Customer"


def test_demo_multi_user_deployment_showcases_provider_customer_billing():
    deployment = build_demo_multi_user_deployment()
    northstar = next(org for org in deployment["organizations"] if org["slug"] == "northstar-isp")

    customers = northstar["provider_customers"]
    assert len(customers) >= 3
    assert {customer["billing_status"] for customer in customers} >= {
        "included",
        "billable_addon",
        "grace_period",
    }
    assert all(customer["monthly_charge_cents"] > 0 for customer in customers)
    assert all(customer["external_customer_id"].startswith("ns-cust-") for customer in customers)


def test_demo_multi_user_deployment_has_opinionated_default_and_impersonation():
    deployment = build_demo_multi_user_deployment()

    assert deployment["default_viewer"] == "single-user-multiple-domains"
    assert [level["level"] for level in deployment["zoom_levels"]] == [
        "workspace",
        "account",
        "provider",
    ]
    assert {row["domain"] for row in deployment["domain_showcase"]} == {"dmarq.org", "dmarq.com"}

    scenarios = {scenario["id"]: scenario for scenario in deployment["viewer_scenarios"]}
    assert scenarios["single-user-multiple-domains"]["visible_organizations"] == [
        "dmarq-foundation"
    ]
    assert scenarios["single-user-multiple-domains"]["default_domain"] == "dmarq.org"
    assert "self-hosted-admin" in scenarios

    users = [
        user
        for organization in deployment["organizations"]
        for user in organization["users"]
        if user.get("can_impersonate")
    ]
    assert users
    assert {user["demo_persona"] for user in users} >= {
        "single-user-multiple-domains",
        "isp-operator",
        "self-hosted-admin",
    }


def test_operator_demo_multi_user_endpoint_returns_showcase(
    authed_client: TestClient,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.operator.get_settings",
        _settings_with_demo_enabled,
    )

    response = authed_client.get("/api/v1/operator/demo/multi-user")

    assert response.status_code == 200
    payload = response.json()
    assert payload["deployment"]["organizations"][0]["slug"] == "dmarq-foundation"
    assert payload["deployment"]["billing_modes"][0]["mode"] == "direct_stripe"
    assert (
        payload["deployment"]["organizations"][0]["billing_profile"]["collection_model"]
        == "self_service_subscription"
    )


def test_operator_demo_multi_user_endpoint_is_hidden_outside_demo_mode(
    authed_client: TestClient,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.api.api_v1.endpoints.operator.get_settings",
        _settings_with_demo_disabled,
    )

    response = authed_client.get("/api/v1/operator/demo/multi-user")

    assert response.status_code == 404
