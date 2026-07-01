import json

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.organization import Entitlement, Organization
from app.models.workspace import Workspace
from app.services.ticketing_chatops_templates import (
    TICKETING_CHATOPS_SCHEMA_VERSION,
    WORKFLOW_EVENT_TYPES,
    get_ticketing_chatops_templates,
    validate_workflow_template_bundle,
)
from app.services.webhook_events import (
    EVENT_ALERT_CREATED,
    EVENT_ALERT_RESOLVED,
    EVENT_COMPLIANCE_DROP,
    EVENT_REMEDIATION_APPROVAL_REQUIRED,
    EVENT_REMEDIATION_INVESTIGATION_REQUIRED,
    EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED,
    EVENT_REMEDIATION_SUMMARY,
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


def test_ticketing_chatops_bundle_is_versioned_and_complete():
    """Workflow templates cover every ticketing/chatops event type."""
    bundle = get_ticketing_chatops_templates()

    assert bundle["schema_version"] == TICKETING_CHATOPS_SCHEMA_VERSION
    assert sorted(bundle["event_types"]) == sorted(WORKFLOW_EVENT_TYPES)
    assert validate_workflow_template_bundle(bundle) == []
    assert bundle["event_workflow_mappings"][EVENT_COMPLIANCE_DROP]["severity"] == "high"
    assert (
        bundle["event_workflow_mappings"][EVENT_ALERT_RESOLVED]["ticket_action"]
        == "resolve_or_comment"
    )
    assert (
        bundle["event_workflow_mappings"][EVENT_REMEDIATION_APPROVAL_REQUIRED]["ticket_action"]
        == "create_or_update"
    )
    assert (
        bundle["event_workflow_mappings"][EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED]["severity"]
        == "high"
    )
    assert (
        bundle["event_workflow_mappings"][EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED]["chat_action"]
        == "notify_channel_and_thread"
    )
    assert (
        bundle["event_workflow_mappings"][EVENT_REMEDIATION_INVESTIGATION_REQUIRED][
            "summary_template"
        ]
        == "Investigate DMARQ remediation item for {domain}: {title}"
    )
    assert (
        bundle["event_workflow_mappings"][EVENT_REMEDIATION_SUMMARY]["chat_action"]
        == "include_in_summary"
    )


def test_ticketing_chatops_templates_have_no_embedded_credentials():
    """Examples must be safe to publish without leaking destination credentials."""
    bundle = get_ticketing_chatops_templates()
    encoded_values = json.dumps(list(_string_values(bundle))).lower()

    for forbidden in ["xoxb-", "ghp_", "jira_pat", "incoming_webhook", "bearer "]:
        assert forbidden not in encoded_values


def test_alert_created_and_resolved_share_dedupe_key_template():
    """Resolved alert events must correlate to the original created alert."""
    bundle = get_ticketing_chatops_templates()
    mappings = bundle["event_workflow_mappings"]
    context = {
        "domain": "example.com",
        "alert_rule": "compliance_drop",
        "event_type": "ignored-for-alert-lifecycle-dedupe",
    }

    created_key = mappings[EVENT_ALERT_CREATED]["dedupe_key_template"].format(**context)
    resolved_key = mappings[EVENT_ALERT_RESOLVED]["dedupe_key_template"].format(**context)

    assert created_key == "dmarq:alert:example.com:compliance_drop"
    assert resolved_key == created_key


def test_ticketing_chatops_validation_reports_template_drift():
    """Validator explains missing required workflow and destination fields."""
    bundle = get_ticketing_chatops_templates()
    bundle["schema_version"] = "unexpected"
    bundle["event_types"] = [EVENT_COMPLIANCE_DROP]
    bundle["event_workflow_mappings"][EVENT_COMPLIANCE_DROP].pop("dedupe_key_template")
    bundle["event_workflow_mappings"][EVENT_COMPLIANCE_DROP].pop("owner")
    bundle["event_workflow_mappings"][EVENT_COMPLIANCE_DROP].pop("ticket_action")
    bundle["payload_templates"].pop("slack")

    errors = validate_workflow_template_bundle(bundle)

    assert "schema_version must be dmarq.workflow.template.v1" in errors
    assert "event_types must match supported workflow events" in errors
    assert f"{EVENT_COMPLIANCE_DROP} is missing a dedupe key template" in errors
    assert f"{EVENT_COMPLIANCE_DROP} is missing an owner" in errors
    assert f"{EVENT_COMPLIANCE_DROP} is missing a ticket action" in errors
    assert "missing payload template: slack" in errors


def test_ticketing_chatops_templates_return_independent_copies():
    """Mutating one returned bundle does not alter future callers."""
    bundle = get_ticketing_chatops_templates()
    bundle["payload_templates"]["jira"]["operation"] = "mutated"

    fresh_bundle = get_ticketing_chatops_templates()

    assert fresh_bundle["payload_templates"]["jira"]["operation"] == "create_or_update_issue"


def test_ticketing_chatops_endpoint_returns_workflow_templates(
    authed_client: TestClient,
):
    """Administrators can fetch issue and chat message templates."""
    response = authed_client.get("/api/v1/integrations/ticketing-chatops/templates")

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == TICKETING_CHATOPS_SCHEMA_VERSION
    assert set(body["payload_templates"]) == {
        "jira",
        "github",
        "slack",
        "microsoft_teams",
    }
    assert body["payload_templates"]["jira"]["operation"] == "create_or_update_issue"
    assert body["payload_templates"]["slack"]["thread_key"] == "{dedupe_key}"


def test_ticketing_chatops_endpoint_requires_advanced_integrations_entitlement(
    authed_client: TestClient,
    db_session: Session,
):
    """Tenant-scoped ticketing/chatops templates are gated as advanced integrations."""
    organization = Organization(slug="chatops-disabled", name="ChatOps Disabled", active=True)
    workspace = Workspace(
        slug="chatops-disabled-main",
        name="ChatOps Disabled Main",
        organization=organization,
        active=True,
    )
    db_session.add_all(
        [
            organization,
            workspace,
            Entitlement(
                organization=organization,
                key="advanced_integrations",
                value="false",
                source="plan",
                active=True,
            ),
        ]
    )
    db_session.commit()

    response = authed_client.get(
        "/api/v1/integrations/ticketing-chatops/templates",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 402
    detail = response.json()["detail"]
    assert detail["code"] == "feature_not_included"
    assert detail["feature"] == "advanced_integrations"
    assert detail["can_export"] is True


def test_ticketing_chatops_endpoint_requires_admin_auth(client: TestClient):
    """Workflow templates use the same admin boundary as integration settings."""
    response = client.get("/api/v1/integrations/ticketing-chatops/templates")

    assert response.status_code == 401
