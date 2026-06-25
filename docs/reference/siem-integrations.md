# SIEM Integration Templates

DMARQ publishes a versioned SIEM event envelope for security analytics
pipelines. Use it when forwarding webhook events or API-derived posture data to
Splunk, Elastic, Microsoft Sentinel, or another JSON-capable SIEM.

## Template Endpoint

Administrators can fetch the current template bundle from:

```http
GET /api/v1/integrations/siem/templates
```

The response contains:

- `template_version`: release date for the template bundle.
- `schema_version`: stable event envelope identifier, currently `dmarq.siem.event.v1`.
- `event_schema`: JSON Schema for normalized SIEM events.
- `event_examples`: source, compliance-drop, and alert examples.
- `ingestion_examples`: Splunk HEC, Elastic ECS, and Microsoft Sentinel shapes.
- `config_templates`: endpoint and mapping hints for common SIEM ingestion paths.
- `redaction_guidance`: sensitive-field handling rules.

## Stable Event Envelope

Every normalized SIEM event uses the same envelope:

```json
{
  "schema_version": "dmarq.siem.event.v1",
  "event_type": "dmarq.compliance.drop",
  "event_id": "dmarq-compliance-drop-20260523-example-com",
  "event_time": "2026-05-23T16:35:00Z",
  "severity": "high",
  "source": {
    "application": "dmarq",
    "instance": "dmarq-preprod",
    "environment": "preprod"
  },
  "entity": {
    "domain": "example.com",
    "sender_ip": null,
    "sender_org": null,
    "reporter": null,
    "alert_rule": "compliance_drop"
  },
  "metrics": {
    "message_count": 1280,
    "aligned_count": 914,
    "failed_count": 366,
    "compliance_rate": 71.41,
    "previous_compliance_rate": 94.8,
    "drop_points": 23.39,
    "missing_days": null
  },
  "alert": {
    "title": "DMARC compliance dropped for example.com",
    "detail": "Compliance fell by 23.39 percentage points in the current window.",
    "status": "active"
  },
  "redaction": {
    "pii_redacted": true,
    "secret_fields_removed": true,
    "raw_report_included": false,
    "notes": "Contains aggregate counts and posture metadata only."
  },
  "links": {
    "domain_url": "https://dmarq.example/domains/example.com",
    "report_url": "https://dmarq.example/domains/example.com/reports"
  },
  "tags": ["email-security", "dmarc", "compliance-drop"],
  "extensions": {}
}
```

Supported normalized event types are:

- `dmarq.report.imported`
- `dmarq.sender.new`
- `dmarq.compliance.drop`
- `dmarq.reports.missing`
- `dmarq.alert.created`

## Splunk HEC

Use the DMARQ webhook URL for a relay, proxy, or workflow endpoint. Do not point
DMARQ directly at Splunk HEC:

```text
https://siem-relay.example/dmarq/splunk-hec
```

The relay forwards to Splunk HEC and adds Splunk's required authorization
header from its own secret store:

```text
https://splunk.example:8088/services/collector/event
Authorization: Splunk ${SPLUNK_HEC_TOKEN}
```

DMARQ webhook delivery uses a fixed DMARQ header set for signing,
idempotency, and content type. It cannot emit `Authorization: Splunk <token>`
on the outbound webhook request. Put the HEC token in the relay, Splunk, or a
secret manager used by the relay. Do not store Splunk credentials in the DMARQ
webhook URL.

Forward the normalized event as the HEC `event` field:

```json
{
  "time": 1779554100,
  "host": "dmarq-preprod",
  "source": "dmarq:webhook",
  "sourcetype": "_json",
  "index": "email_security",
  "event": {
    "schema_version": "dmarq.siem.event.v1",
    "event_type": "dmarq.compliance.drop",
    "event_id": "dmarq-compliance-drop-20260523-example-com"
  }
}
```

## Elastic ECS

For Elastic or Logstash, keep the full DMARQ event under `dmarq` and map common
fields to ECS:

```json
{
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
  "dmarq": {
    "schema_version": "dmarq.siem.event.v1",
    "event_type": "dmarq.compliance.drop",
    "event_id": "dmarq-compliance-drop-20260523-example-com"
  }
}
```

Index into a dedicated dataset such as
`logs-dmarq.email_security-default` so retention, dashboards, and alerts can be
managed independently from application logs.

## Microsoft Sentinel

For Sentinel custom logs, use a protected relay such as Azure Function or Logic
App to add Azure credentials and forward the JSON body to a Data Collection
Rule stream:

```json
[
  {
    "TimeGenerated": "2026-05-23T16:35:00Z",
    "EventType": "dmarq.compliance.drop",
    "Domain": "example.com",
    "Severity": "high",
    "ComplianceRate": 71.41,
    "PreviousComplianceRate": 94.8,
    "DropPoints": 23.39,
    "DmarqEvent": {
      "schema_version": "dmarq.siem.event.v1",
      "event_type": "dmarq.compliance.drop",
      "event_id": "dmarq-compliance-drop-20260523-example-com"
    }
  }
]
```

Map `TimeGenerated` from `event_time` so KQL queries and scheduled analytics
rules use DMARQ's event time instead of relay receipt time.

## Redaction Guidance

Forward:

- Aggregate counts and compliance rates.
- Monitored domains, sender IPs, reporter names, alert rule names, and event IDs.
- Links back to DMARQ pages when the receiving SIEM user is authorized to open them.

Do not forward:

- Raw aggregate report XML.
- Raw RFC 822 mail content or forensic message bodies.
- Mailbox credentials, API tokens, webhook signing secrets, authorization headers, or SIEM ingest tokens.
- Recipient local-parts, authentication headers, and forensic identifiers unless a separate privacy review approves them.

Use `event_id` or `X-DMARQ-Idempotency-Key` for deduplication. Avoid deriving
deduplication hashes from raw payloads that may accidentally include sensitive
fields.
