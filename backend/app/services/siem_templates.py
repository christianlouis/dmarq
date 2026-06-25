"""Versioned SIEM integration templates and validation helpers."""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from app.services.webhook_events import (
    EVENT_ALERT_CREATED,
    EVENT_COMPLIANCE_DROP,
    EVENT_REPORT_IMPORTED,
    EVENT_REPORTS_MISSING,
    EVENT_SENDER_NEW,
)

SIEM_SCHEMA_VERSION = "dmarq.siem.event.v1"
SIEM_TEMPLATE_VERSION = "2026-05-23"

SIEM_EVENT_TYPES = [
    EVENT_REPORT_IMPORTED,
    EVENT_SENDER_NEW,
    EVENT_COMPLIANCE_DROP,
    EVENT_REPORTS_MISSING,
    EVENT_ALERT_CREATED,
]

SIEM_SEVERITIES = ["info", "low", "medium", "high", "critical"]

SIEM_EVENT_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://dmarq.app/schemas/siem/dmarq-siem-event-v1.schema.json",
    "title": "DMARQ SIEM Event",
    "description": "Stable SIEM envelope for DMARQ posture, report, and alert events.",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "event_type",
        "event_id",
        "event_time",
        "severity",
        "source",
        "entity",
        "metrics",
        "redaction",
    ],
    "properties": {
        "schema_version": {"const": SIEM_SCHEMA_VERSION},
        "event_type": {"type": "string", "enum": SIEM_EVENT_TYPES},
        "event_id": {
            "type": "string",
            "description": "Stable event or delivery identifier for deduplication.",
            "minLength": 8,
        },
        "event_time": {"type": "string", "format": "date-time"},
        "severity": {"type": "string", "enum": SIEM_SEVERITIES},
        "source": {
            "type": "object",
            "additionalProperties": False,
            "required": ["application", "instance", "environment"],
            "properties": {
                "application": {"const": "dmarq"},
                "instance": {"type": "string"},
                "environment": {"type": "string"},
            },
        },
        "entity": {
            "type": "object",
            "additionalProperties": False,
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string"},
                "sender_ip": {"type": ["string", "null"]},
                "sender_org": {"type": ["string", "null"]},
                "reporter": {"type": ["string", "null"]},
                "alert_rule": {"type": ["string", "null"]},
            },
        },
        "metrics": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "message_count": {"type": ["integer", "null"], "minimum": 0},
                "aligned_count": {"type": ["integer", "null"], "minimum": 0},
                "failed_count": {"type": ["integer", "null"], "minimum": 0},
                "compliance_rate": {"type": ["number", "null"], "minimum": 0, "maximum": 100},
                "previous_compliance_rate": {
                    "type": ["number", "null"],
                    "minimum": 0,
                    "maximum": 100,
                },
                "drop_points": {"type": ["number", "null"], "minimum": 0, "maximum": 100},
                "missing_days": {"type": ["integer", "null"], "minimum": 0},
            },
        },
        "alert": {
            "type": ["object", "null"],
            "additionalProperties": False,
            "required": ["title", "detail", "status"],
            "properties": {
                "title": {"type": "string"},
                "detail": {"type": "string"},
                "status": {"type": "string", "enum": ["active", "resolved", "informational"]},
            },
        },
        "redaction": {
            "type": "object",
            "additionalProperties": False,
            "required": ["pii_redacted", "secret_fields_removed", "raw_report_included"],
            "properties": {
                "pii_redacted": {"const": True},
                "secret_fields_removed": {"const": True},
                "raw_report_included": {"const": False},
                "notes": {"type": "string"},
            },
        },
        "links": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "domain_url": {"type": ["string", "null"], "format": "uri"},
                "report_url": {"type": ["string", "null"], "format": "uri"},
            },
        },
        "tags": {"type": "array", "items": {"type": "string"}},
        "extensions": {
            "type": "object",
            "description": "Optional namespaced integration fields.",
            "additionalProperties": True,
        },
    },
}

BASE_REDACTION = {
    "pii_redacted": True,
    "secret_fields_removed": True,
    "raw_report_included": False,
    "notes": "Contains aggregate counts and posture metadata only.",
}

SIEM_EVENT_EXAMPLES: Dict[str, Dict[str, Any]] = {
    "sender_new": {
        "schema_version": SIEM_SCHEMA_VERSION,
        "event_type": EVENT_SENDER_NEW,
        "event_id": "dmarq-sender-new-20260523-example-com-20301135",
        "event_time": "2026-05-23T16:30:00Z",
        "severity": "medium",
        "source": {
            "application": "dmarq",
            "instance": "dmarq-preprod",
            "environment": "preprod",
        },
        "entity": {
            "domain": "example.com",
            "sender_ip": "203.0.113.5",
            "sender_org": "Example SaaS Mail",
            "reporter": "google.com",
            "alert_rule": "new_sender_source",
        },
        "metrics": {
            "message_count": 42,
            "aligned_count": 40,
            "failed_count": 2,
            "compliance_rate": 95.24,
            "previous_compliance_rate": None,
            "drop_points": None,
            "missing_days": None,
        },
        "alert": {
            "title": "New sending source for example.com",
            "detail": "203.0.113.5 was first observed sending authenticated mail.",
            "status": "active",
        },
        "redaction": BASE_REDACTION,
        "links": {
            "domain_url": "https://dmarq.example/domains/example.com",
            "report_url": None,
        },
        "tags": ["email-security", "dmarc", "new-sender"],
        "extensions": {},
    },
    "compliance_drop": {
        "schema_version": SIEM_SCHEMA_VERSION,
        "event_type": EVENT_COMPLIANCE_DROP,
        "event_id": "dmarq-compliance-drop-20260523-example-com",
        "event_time": "2026-05-23T16:35:00Z",
        "severity": "high",
        "source": {
            "application": "dmarq",
            "instance": "dmarq-preprod",
            "environment": "preprod",
        },
        "entity": {
            "domain": "example.com",
            "sender_ip": None,
            "sender_org": None,
            "reporter": None,
            "alert_rule": "compliance_drop",
        },
        "metrics": {
            "message_count": 1280,
            "aligned_count": 914,
            "failed_count": 366,
            "compliance_rate": 71.41,
            "previous_compliance_rate": 94.8,
            "drop_points": 23.39,
            "missing_days": None,
        },
        "alert": {
            "title": "DMARC compliance dropped for example.com",
            "detail": "Compliance fell by 23.39 percentage points in the current window.",
            "status": "active",
        },
        "redaction": BASE_REDACTION,
        "links": {
            "domain_url": "https://dmarq.example/domains/example.com",
            "report_url": "https://dmarq.example/domains/example.com/reports",
        },
        "tags": ["email-security", "dmarc", "compliance-drop"],
        "extensions": {},
    },
    "alert_created": {
        "schema_version": SIEM_SCHEMA_VERSION,
        "event_type": EVENT_ALERT_CREATED,
        "event_id": "dmarq-alert-created-20260523-example-com",
        "event_time": "2026-05-23T16:40:00Z",
        "severity": "medium",
        "source": {
            "application": "dmarq",
            "instance": "dmarq-preprod",
            "environment": "preprod",
        },
        "entity": {
            "domain": "example.com",
            "sender_ip": None,
            "sender_org": None,
            "reporter": None,
            "alert_rule": "missing_reports",
        },
        "metrics": {
            "message_count": None,
            "aligned_count": None,
            "failed_count": None,
            "compliance_rate": None,
            "previous_compliance_rate": None,
            "drop_points": None,
            "missing_days": 3,
        },
        "alert": {
            "title": "Missing DMARC reports for example.com",
            "detail": "No aggregate reports have been imported for 3 days.",
            "status": "active",
        },
        "redaction": BASE_REDACTION,
        "links": {
            "domain_url": "https://dmarq.example/domains/example.com",
            "report_url": None,
        },
        "tags": ["email-security", "dmarc", "missing-reports"],
        "extensions": {},
    },
}

SIEM_INGESTION_EXAMPLES: Dict[str, Dict[str, Any]] = {
    "splunk_hec": {
        "time": 1779554100,
        "host": "dmarq-preprod",
        "source": "dmarq:webhook",
        "sourcetype": "_json",
        "index": "email_security",
        "event": SIEM_EVENT_EXAMPLES["compliance_drop"],
    },
    "elastic_ecs": {
        "@timestamp": "2026-05-23T16:35:00Z",
        "ecs.version": "8.11.0",
        "event.kind": "alert",
        "event.category": ["email"],
        "event.type": ["info"],
        "event.dataset": "dmarq.siem",
        "observer.vendor": "DMARQ",
        "observer.product": "DMARQ",
        "rule.name": "compliance_drop",
        "host.name": "dmarq-preprod",
        "dmarq": SIEM_EVENT_EXAMPLES["compliance_drop"],
    },
    "microsoft_sentinel_custom_log": [
        {
            "TimeGenerated": "2026-05-23T16:35:00Z",
            "EventType": EVENT_COMPLIANCE_DROP,
            "Domain": "example.com",
            "Severity": "high",
            "ComplianceRate": 71.41,
            "PreviousComplianceRate": 94.8,
            "DropPoints": 23.39,
            "DmarqEvent": SIEM_EVENT_EXAMPLES["compliance_drop"],
        }
    ],
}

SIEM_CONFIG_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "splunk_hec": {
        "webhook_url_pattern": "https://siem-relay.example/dmarq/splunk-hec",
        "delivery_model": "relay_required",
        "relay_target_url_pattern": "https://splunk.example:8088/services/collector/event",
        "headers_added_by_relay": {
            "Authorization": "Splunk ${SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        },
        "recommended_index": "email_security",
        "recommended_sourcetype": "_json",
        "notes": [
            "Point DMARQ at a relay or workflow endpoint, not directly at Splunk HEC.",
            "DMARQ webhook delivery cannot emit the Splunk Authorization header.",
            "Store the HEC token in the receiving relay, proxy, or SIEM secret store.",
            "Deduplicate with event.event_id or X-DMARQ-Idempotency-Key.",
        ],
    },
    "elastic_logstash_http": {
        "webhook_url_pattern": "https://logstash.example:5044/dmarq",
        "pipeline_hint": "Parse the JSON body, move event_time to @timestamp, and keep the full payload under dmarq.",
        "recommended_index": "logs-dmarq.email_security-default",
        "notes": [
            "Use a Logstash secret store entry for downstream Elasticsearch credentials.",
            "Map severity to event.risk_score or event.severity in the pipeline.",
        ],
    },
    "microsoft_sentinel": {
        "webhook_url_pattern": "https://ingest.monitor.azure.com/dataCollectionRules/${DCR_IMMUTABLE_ID}/streams/Custom-Dmarq_CL",
        "table_name": "Dmarq_CL",
        "notes": [
            "Use an Azure Function, Logic App, or protected relay to add OAuth credentials.",
            "Keep TimeGenerated mapped from event_time for query accuracy.",
        ],
    },
}

REDACTION_GUIDANCE = [
    "Forward aggregate counts, domains, sender IPs, reporter names, and alert metadata.",
    "Do not forward raw report XML, raw RFC 822 messages, mailbox credentials, API tokens, or webhook signing secrets.",
    "Keep recipient addresses, local-parts, authentication headers, and forensic message content redacted unless a separate privacy review approves them.",
    "Use event_id or X-DMARQ-Idempotency-Key for deduplication instead of hashing raw payloads that may include sensitive fields.",
]


def _append_required_field_errors(event: Dict[str, Any], errors: List[str]) -> None:
    for field in SIEM_EVENT_SCHEMA["required"]:
        if field not in event:
            errors.append(f"missing required field: {field}")


def _append_enum_errors(event: Dict[str, Any], errors: List[str]) -> None:
    checks = [
        (
            event.get("schema_version") == SIEM_SCHEMA_VERSION,
            "schema_version must be dmarq.siem.event.v1",
        ),
        (event.get("event_type") in SIEM_EVENT_TYPES, "event_type is not a supported SIEM event"),
        (event.get("severity") in SIEM_SEVERITIES, "severity is not supported"),
    ]
    errors.extend(message for passed, message in checks if not passed)


def _append_redaction_errors(event: Dict[str, Any], errors: List[str]) -> None:
    redaction = event.get("redaction") or {}
    checks = [
        (redaction.get("pii_redacted") is True, "redaction.pii_redacted must be true"),
        (
            redaction.get("secret_fields_removed") is True,
            "redaction.secret_fields_removed must be true",
        ),
        (
            redaction.get("raw_report_included") is False,
            "redaction.raw_report_included must be false",
        ),
    ]
    errors.extend(message for passed, message in checks if not passed)


def _append_alert_errors(event: Dict[str, Any], errors: List[str]) -> None:
    alert = event.get("alert")
    if alert is None:
        return
    if not isinstance(alert, dict):
        errors.append("alert must be an object or null")
        return

    for field in SIEM_EVENT_SCHEMA["properties"]["alert"]["required"]:
        if not alert.get(field):
            errors.append(f"alert.{field} is required when alert is present")

    if alert.get("status") not in {"active", "resolved", "informational"}:
        errors.append("alert.status is not supported")


def get_siem_templates() -> Dict[str, Any]:
    """Return a copy of the versioned SIEM template bundle."""
    return copy.deepcopy(
        {
            "template_version": SIEM_TEMPLATE_VERSION,
            "schema_version": SIEM_SCHEMA_VERSION,
            "event_types": SIEM_EVENT_TYPES,
            "event_schema": SIEM_EVENT_SCHEMA,
            "event_examples": SIEM_EVENT_EXAMPLES,
            "ingestion_examples": SIEM_INGESTION_EXAMPLES,
            "config_templates": SIEM_CONFIG_TEMPLATES,
            "redaction_guidance": REDACTION_GUIDANCE,
        }
    )


def validate_siem_event(event: Dict[str, Any]) -> List[str]:
    """Run lightweight validation for bundled examples without extra dependencies."""
    errors: List[str] = []
    _append_required_field_errors(event, errors)
    _append_enum_errors(event, errors)

    source = event.get("source") or {}
    if source.get("application") != "dmarq":
        errors.append("source.application must be dmarq")

    entity = event.get("entity") or {}
    if not entity.get("domain"):
        errors.append("entity.domain is required")

    _append_redaction_errors(event, errors)
    _append_alert_errors(event, errors)
    return errors
