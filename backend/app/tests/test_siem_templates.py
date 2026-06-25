import json

from fastapi.testclient import TestClient

from app.services.siem_templates import (
    SIEM_EVENT_TYPES,
    SIEM_SCHEMA_VERSION,
    get_siem_templates,
    validate_siem_event,
)


def _string_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)
    elif isinstance(value, str):
        yield value


def test_siem_template_bundle_is_versioned_and_examples_match_schema():
    """Bundled SIEM examples stay aligned with the stable event envelope."""
    templates = get_siem_templates()

    assert templates["schema_version"] == SIEM_SCHEMA_VERSION
    assert templates["event_schema"]["properties"]["schema_version"]["const"] == SIEM_SCHEMA_VERSION
    assert templates["event_schema"]["properties"]["event_type"]["enum"] == SIEM_EVENT_TYPES

    examples = templates["event_examples"]
    assert {"sender_new", "compliance_drop", "alert_created"}.issubset(examples)

    for name, example in examples.items():
        assert validate_siem_event(example) == [], name
        encoded = json.dumps(list(_string_values(example))).lower()
        assert "secret" not in encoded
        assert "token" not in encoded
        assert "raw_report_xml" not in encoded


def test_siem_ingestion_examples_wrap_valid_dmarq_events():
    """SIEM-specific examples keep the normalized event intact."""
    templates = get_siem_templates()
    ingestion_examples = templates["ingestion_examples"]

    splunk_event = ingestion_examples["splunk_hec"]["event"]
    elastic_event = ingestion_examples["elastic_ecs"]["dmarq"]
    sentinel_event = ingestion_examples["microsoft_sentinel_custom_log"][0]["DmarqEvent"]

    for wrapped_event in [splunk_event, elastic_event, sentinel_event]:
        assert validate_siem_event(wrapped_event) == []
        assert wrapped_event["schema_version"] == SIEM_SCHEMA_VERSION


def test_siem_alert_schema_requires_metadata_when_alert_is_present():
    """Alert metadata is optional, but partial alert objects are not valid."""
    templates = get_siem_templates()
    alert_schema = templates["event_schema"]["properties"]["alert"]
    event = templates["event_examples"]["compliance_drop"].copy()

    assert alert_schema["type"] == ["object", "null"]
    assert alert_schema["required"] == ["title", "detail", "status"]
    assert validate_siem_event({**event, "alert": None}) == []

    errors = validate_siem_event({**event, "alert": {}})

    assert "alert.title is required when alert is present" in errors
    assert "alert.detail is required when alert is present" in errors
    assert "alert.status is required when alert is present" in errors
    assert "alert.status is not supported" not in errors

    assert (
        validate_siem_event(
            {**event, "alert": {"title": "", "detail": "", "status": "active"}}
        )
        == []
    )

    assert "alert must be an object or null" in validate_siem_event({**event, "alert": "active"})
    assert "alert.status is not supported" in validate_siem_event(
        {**event, "alert": {"title": "Title", "detail": "Detail", "status": "open"}}
    )


def test_splunk_template_requires_relay_to_add_hec_authorization():
    """DMARQ cannot send Splunk's Authorization header directly."""
    templates = get_siem_templates()
    splunk_template = templates["config_templates"]["splunk_hec"]

    assert splunk_template["delivery_model"] == "relay_required"
    assert "splunk.example:8088/services/collector/event" not in splunk_template[
        "webhook_url_pattern"
    ]
    assert splunk_template["headers"] == {}
    assert "Authorization" not in splunk_template.get("headers", {})
    assert splunk_template["headers_added_by_relay"]["Authorization"].startswith("Splunk ")

    notes = " ".join(splunk_template["notes"]).lower()
    assert "relay" in notes
    assert "cannot emit the splunk authorization header" in notes


def test_siem_templates_endpoint_returns_common_configs(authed_client: TestClient):
    """Administrators can fetch schemas, examples, and SIEM config hints."""
    response = authed_client.get("/api/v1/integrations/siem/templates")

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == SIEM_SCHEMA_VERSION
    assert set(body["config_templates"]) == {
        "splunk_hec",
        "elastic_logstash_http",
        "microsoft_sentinel",
    }
    assert body["event_examples"]["compliance_drop"]["redaction"]["pii_redacted"] is True
    assert "raw report" in " ".join(body["redaction_guidance"]).lower()


def test_siem_templates_endpoint_requires_admin_auth(client: TestClient):
    """Template endpoint follows the same admin boundary as other integrations."""
    response = client.get("/api/v1/integrations/siem/templates")

    assert response.status_code == 401
