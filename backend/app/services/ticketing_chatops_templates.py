"""Ticketing and chatops integration templates."""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from app.services.webhook_events import (
    EVENT_ALERT_CREATED,
    EVENT_ALERT_RESOLVED,
    EVENT_COMPLIANCE_DROP,
    EVENT_REMEDIATION_APPROVAL_REQUIRED,
    EVENT_REMEDIATION_INVESTIGATION_REQUIRED,
    EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED,
    EVENT_REMEDIATION_SUMMARY,
    EVENT_REPORTS_MISSING,
    EVENT_SENDER_NEW,
)

TICKETING_CHATOPS_TEMPLATE_VERSION = "2026-05-23"
TICKETING_CHATOPS_SCHEMA_VERSION = "dmarq.workflow.template.v1"

WORKFLOW_EVENT_TYPES = [
    EVENT_SENDER_NEW,
    EVENT_COMPLIANCE_DROP,
    EVENT_REPORTS_MISSING,
    EVENT_ALERT_CREATED,
    EVENT_ALERT_RESOLVED,
    EVENT_REMEDIATION_APPROVAL_REQUIRED,
    EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED,
    EVENT_REMEDIATION_INVESTIGATION_REQUIRED,
    EVENT_REMEDIATION_SUMMARY,
]

EVENT_WORKFLOW_MAPPINGS: Dict[str, Dict[str, Any]] = {
    EVENT_SENDER_NEW: {
        "severity": "medium",
        "owner": "email-security",
        "ticket_action": "create_or_update",
        "chat_action": "notify_channel",
        "dedupe_key_template": "dmarq:{event_type}:{domain}:{sender_ip}",
        "summary_template": "Review new DMARC sending source for {domain}",
        "noise_control": "Open one ticket per domain and sender IP. Suppress repeats for 7 days after acknowledgement.",
    },
    EVENT_COMPLIANCE_DROP: {
        "severity": "high",
        "owner": "email-security",
        "ticket_action": "create_or_update",
        "chat_action": "notify_channel_and_thread",
        "dedupe_key_template": "dmarq:{event_type}:{domain}",
        "summary_template": "Investigate DMARC compliance drop for {domain}",
        "noise_control": "Escalate only when drop_points meets the configured alert threshold. Update the same ticket while active.",
    },
    EVENT_REPORTS_MISSING: {
        "severity": "medium",
        "owner": "mail-operations",
        "ticket_action": "create_or_update",
        "chat_action": "notify_channel",
        "dedupe_key_template": "dmarq:{event_type}:{domain}",
        "summary_template": "Restore missing DMARC aggregate reports for {domain}",
        "noise_control": "Create one ticket per domain and keep reminders to one chat update per day.",
    },
    EVENT_ALERT_CREATED: {
        "severity": "medium",
        "owner": "email-security",
        "ticket_action": "create_or_update",
        "chat_action": "notify_channel",
        "dedupe_key_template": "dmarq:alert:{domain}:{alert_rule}",
        "summary_template": "DMARQ alert: {title}",
        "noise_control": "Route by alert_rule and reuse open tickets while the alert remains active.",
    },
    EVENT_ALERT_RESOLVED: {
        "severity": "info",
        "owner": "email-security",
        "ticket_action": "resolve_or_comment",
        "chat_action": "notify_thread",
        "dedupe_key_template": "dmarq:alert:{domain}:{alert_rule}",
        "summary_template": "DMARQ alert resolved: {title}",
        "noise_control": "Resolve the linked ticket when all active signals for the dedupe key are clear.",
    },
    EVENT_REMEDIATION_APPROVAL_REQUIRED: {
        "severity": "medium",
        "owner": "email-security",
        "ticket_action": "create_or_update",
        "chat_action": "notify_channel",
        "dedupe_key_template": "{dedupe_key}",
        "summary_template": "Approve DMARQ remediation for {domain}: {title}",
        "noise_control": "Open or update one ticket per remediation dedupe key until the operator approves, rejects, or resolves it.",
    },
    EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED: {
        "severity": "high",
        "owner": "email-security",
        "ticket_action": "create_or_update",
        "chat_action": "notify_channel_and_thread",
        "dedupe_key_template": "{dedupe_key}",
        "summary_template": "Manual DMARQ remediation required for {domain}: {title}",
        "noise_control": "Escalate high-impact manual work once, then update the existing ticket while evidence changes.",
    },
    EVENT_REMEDIATION_INVESTIGATION_REQUIRED: {
        "severity": "medium",
        "owner": "email-security",
        "ticket_action": "create_or_update",
        "chat_action": "notify_channel",
        "dedupe_key_template": "{dedupe_key}",
        "summary_template": "Investigate DMARQ remediation item for {domain}: {title}",
        "noise_control": "Create one investigation ticket per dedupe key and suppress repeats until the state changes.",
    },
    EVENT_REMEDIATION_SUMMARY: {
        "severity": "info",
        "owner": "email-security",
        "ticket_action": "comment_or_summarize",
        "chat_action": "include_in_summary",
        "dedupe_key_template": "{dedupe_key}",
        "summary_template": "DMARQ remediation summary item for {domain}: {title}",
        "noise_control": "Do not create standalone tickets for summary-only items unless the severity escalates.",
    },
}

SAMPLE_CONTEXT: Dict[str, Any] = {
    "event_type": EVENT_COMPLIANCE_DROP,
    "event_id": "dmarq-compliance-drop-20260523-example-com",
    "domain": "example.com",
    "severity": "high",
    "title": "DMARC compliance dropped for example.com",
    "detail": "Compliance fell by 23.39 percentage points in the current window.",
    "alert_rule": "compliance_drop",
    "sender_ip": None,
    "message_count": 1280,
    "failed_count": 366,
    "compliance_rate": 71.41,
    "previous_compliance_rate": 94.8,
    "drop_points": 23.39,
    "domain_url": "https://dmarq.example/domains/example.com",
    "report_url": "https://dmarq.example/domains/example.com/reports",
    "dedupe_key": "dmarq:dmarq.compliance.drop:example.com",
}

JIRA_ISSUE_TEMPLATE: Dict[str, Any] = {
    "operation": "create_or_update_issue",
    "lookup": {
        "jql": 'project = EMAILSEC AND labels = "dmarq" AND "Dedupe Key" ~ "{dedupe_key}" AND statusCategory != Done'
    },
    "create": {
        "fields": {
            "project": {"key": "EMAILSEC"},
            "issuetype": {"name": "Task"},
            "summary": "[DMARQ][{severity}] {title}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": "{detail}",
                            }
                        ],
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": "Domain: {domain} | Compliance: {compliance_rate}% | Previous: {previous_compliance_rate}% | Drop: {drop_points} points",
                            }
                        ],
                    },
                ],
            },
            "labels": ["dmarq", "email-security", "{alert_rule}"],
            "priority": {"name": "High"},
            "customfield_dedupe_key": "{dedupe_key}",
        }
    },
    "update": {
        "comment": "{event_time}: {detail}",
        "fields": {"priority": {"name": "High"}},
    },
    "resolve": {
        "transition": "Done",
        "comment": "DMARQ reports this alert is resolved. Event: {event_id}",
    },
}

GITHUB_ISSUE_TEMPLATE: Dict[str, Any] = {
    "operation": "create_or_update_issue",
    "repository": "security-operations/email-auth",
    "lookup": {
        "state": "open",
        "labels": ["dmarq", "{alert_rule}", "dedupe:{dedupe_key}"],
    },
    "create": {
        "title": "[DMARQ][{severity}] {title}",
        "body": "\n".join(
            [
                "## Signal",
                "{detail}",
                "",
                "## Evidence",
                "- Domain: `{domain}`",
                "- Compliance rate: `{compliance_rate}%`",
                "- Previous compliance rate: `{previous_compliance_rate}%`",
                "- Drop: `{drop_points}` points",
                "- Failed messages: `{failed_count}` of `{message_count}`",
                "",
                "## Links",
                "- Domain: {domain_url}",
                "- Reports: {report_url}",
                "",
                "Dedupe key: `{dedupe_key}`",
            ]
        ),
        "labels": ["dmarq", "email-security", "{alert_rule}", "dedupe:{dedupe_key}"],
    },
    "update": {"comment": "{event_time}: {detail}\n\nDedupe key: `{dedupe_key}`"},
    "resolve": {"state": "closed", "comment": "Resolved by DMARQ event `{event_id}`."},
}

SLACK_MESSAGE_TEMPLATE: Dict[str, Any] = {
    "channel": "#email-security",
    "thread_key": "{dedupe_key}",
    "text": "[DMARQ][{severity}] {title}",
    "blocks": [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "DMARQ: {title}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "{detail}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": "*Domain*\n{domain}"},
                {"type": "mrkdwn", "text": "*Severity*\n{severity}"},
                {"type": "mrkdwn", "text": "*Compliance*\n{compliance_rate}%"},
                {"type": "mrkdwn", "text": "*Drop*\n{drop_points} points"},
            ],
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open domain"},
                    "url": "{domain_url}",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open reports"},
                    "url": "{report_url}",
                },
            ],
        },
    ],
}

TEAMS_MESSAGE_TEMPLATE: Dict[str, Any] = {
    "type": "message",
    "attachments": [
        {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.5",
                "body": [
                    {
                        "type": "TextBlock",
                        "size": "Medium",
                        "weight": "Bolder",
                        "text": "DMARQ: {title}",
                    },
                    {"type": "TextBlock", "wrap": True, "text": "{detail}"},
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Domain", "value": "{domain}"},
                            {"title": "Severity", "value": "{severity}"},
                            {"title": "Compliance", "value": "{compliance_rate}%"},
                            {"title": "Drop", "value": "{drop_points} points"},
                        ],
                    },
                ],
                "actions": [
                    {
                        "type": "Action.OpenUrl",
                        "title": "Open domain",
                        "url": "{domain_url}",
                    },
                    {
                        "type": "Action.OpenUrl",
                        "title": "Open reports",
                        "url": "{report_url}",
                    },
                ],
            },
        }
    ],
}

OPERATING_MODEL = [
    "Use DMARQ webhook idempotency keys or the documented dedupe_key_template as the ticket correlation key.",
    "Route ownership by event type: email-security for sender/compliance/alert signals, mail-operations for missing reports.",
    "Create or update one ticket per active signal, and close or comment when a resolved event arrives.",
    "Send chat notifications to a stable channel, then keep follow-up updates in the same thread whenever the destination supports threading.",
    "Use severity and configured thresholds to suppress low-value repeats. Do not page on every aggregate report import.",
    "Store Jira, GitHub, Slack, and Teams credentials in the receiving automation platform or secret manager, not in DMARQ payloads.",
]


def get_ticketing_chatops_templates() -> Dict[str, Any]:
    """Return a copy of the ticketing and chatops template bundle."""
    return copy.deepcopy(
        {
            "template_version": TICKETING_CHATOPS_TEMPLATE_VERSION,
            "schema_version": TICKETING_CHATOPS_SCHEMA_VERSION,
            "event_types": WORKFLOW_EVENT_TYPES,
            "event_workflow_mappings": EVENT_WORKFLOW_MAPPINGS,
            "sample_context": SAMPLE_CONTEXT,
            "payload_templates": {
                "jira": JIRA_ISSUE_TEMPLATE,
                "github": GITHUB_ISSUE_TEMPLATE,
                "slack": SLACK_MESSAGE_TEMPLATE,
                "microsoft_teams": TEAMS_MESSAGE_TEMPLATE,
            },
            "operating_model": OPERATING_MODEL,
        }
    )


def validate_workflow_template_bundle(bundle: Dict[str, Any]) -> List[str]:
    """Validate bundled templates without pulling in a schema dependency."""
    errors: List[str] = []
    if bundle.get("schema_version") != TICKETING_CHATOPS_SCHEMA_VERSION:
        errors.append("schema_version must be dmarq.workflow.template.v1")
    if sorted(bundle.get("event_types", [])) != sorted(WORKFLOW_EVENT_TYPES):
        errors.append("event_types must match supported workflow events")

    mappings = bundle.get("event_workflow_mappings") or {}
    for event_type in WORKFLOW_EVENT_TYPES:
        mapping = mappings.get(event_type) or {}
        if not mapping.get("dedupe_key_template"):
            errors.append(f"{event_type} is missing a dedupe key template")
        if not mapping.get("owner"):
            errors.append(f"{event_type} is missing an owner")
        if not mapping.get("ticket_action"):
            errors.append(f"{event_type} is missing a ticket action")

    templates = bundle.get("payload_templates") or {}
    for destination in ["jira", "github", "slack", "microsoft_teams"]:
        if destination not in templates:
            errors.append(f"missing payload template: {destination}")
    return errors
