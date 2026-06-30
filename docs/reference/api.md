# API Reference

DMARQ provides a comprehensive REST API that allows you to integrate with external systems and build custom workflows.

## Authentication

Stable automation endpoints live under `/api/v1/public` and require a scoped
API token in the `X-API-Key` header. Admin endpoints continue to require an
administrator session or admin API key.

### API Keys

To use the API, you need to generate an API key:

Create scoped API tokens with:

```
POST /api-tokens
```

Request:

```json
{
  "name": "SIEM export",
  "scopes": ["reports:read", "posture:read", "tls-reports:read"]
}
```

The raw token is returned once. DMARQ stores only a hash, prefix, scopes, and
usage audit metadata.

### Authentication Header

Include your API key in all requests using the `X-API-Key` header:

```
X-API-Key: your_api_key_here
```

## Base URL

The base URL for all API endpoints is:

```
https://your-dmarq-instance.com/api/v1
```

Replace `your-dmarq-instance.com` with your actual DMARQ hostname.

## API Endpoints

### Stable Public API

These endpoints are read-only and intended for automation. They are versioned
through the `/public` path and avoid UI-specific payloads.

| Endpoint | Required scope | Purpose |
| --- | --- | --- |
| `GET /public/domains` | `reports:read` | Domain report and DNS summary list |
| `GET /public/domains/{domain_id}/reports` | `reports:read` | Recent DMARC aggregate report summaries |
| `GET /public/domains/{domain_id}/posture` | `posture:read` | Evidence-first posture dashboard payload |
| `GET /public/tls-reports/summary` | `tls-reports:read` | SMTP TLS report trends and failure groups |
| `POST /mcp` | `mcp:read` | Read-only MCP-style JSON-RPC tool endpoint |

Successful public API calls update the token's last-used timestamp, source IP,
and usage count for auditing.

### Provider API

Provider, ISP, MSP, and hosting-control-panel integrations use
`/provider` endpoints under the `/api/v1` base URL with provider-scoped
machine tokens. See [Provider Integrations](provider-integrations.md) for
customer provisioning, subscription state updates, WHMCS-style lifecycle
mapping, TMF-style OSS/BSS mapping, and monthly provider billing exports.

### API Tokens

#### List API Tokens

```
GET /api-tokens
```

Returns token metadata, scopes, activity state, and audit fields. Raw token
secrets and hashes are never returned.

#### Create API Token

```
POST /api-tokens
```

Creates a scoped read-only token. The response includes `token` once and
`metadata` for future list/revoke operations.

#### Revoke API Token

```
DELETE /api-tokens/{token_id}
```

Deactivates a token immediately. Revoked tokens can no longer access public API
endpoints.

### Workspace Audit

#### List Workspace Roles

```text
GET /audit/roles
```

Returns the supported workspace RBAC roles and their permission strings.

#### List Workspace Audit Logs

```text
GET /audit/logs
```

Returns recent sanitized audit events for the default workspace. Optional
filters:

| Query parameter | Purpose |
| --- | --- |
| `limit` | Number of rows to return, from 1 to 200 |
| `action` | Restrict to one action key |
| `entity_type` | Restrict to one entity category |

Audit details redact secret-like fields before they are stored.

### Workspace Onboarding

Workspace onboarding endpoints require administrator access and render/apply
versioned onboarding templates for new client workspaces.

#### List Onboarding Templates

```text
GET /onboarding/templates
```

Returns template metadata, variables, domain and mail-source templates,
notification defaults, and operator checklist items.

#### Preview Onboarding Plan

```text
POST /onboarding/preview
```

Request:

```json
{
  "template_id": "standard_monitoring",
  "workspace": {
    "slug": "client-one",
    "name": "Client One"
  },
  "variables": {
    "domain": "example.com",
    "report_mailbox": "dmarc@example.com",
    "imap_server": "imap.example.com"
  }
}
```

Returns the rendered plan without writing to the database. Secret-like fields
are redacted in the response.

#### Apply Onboarding Plan

```text
POST /onboarding/apply
```

Applies the rendered plan by creating or reusing the workspace, adding missing
domains and mail-source shells, seeding safe notification defaults, returning
the operator checklist, and writing a sanitized workspace audit event.

Existing domains and mail sources are not duplicated. Existing notification
settings are preserved unless `overwrite_existing` is set to `true`.

### Mail Source Backfills

Mailbox backfills are admin endpoints for resumable historical imports. Creating
a backfill queues a progress row; connector workers can then process the window
without blocking the UI.

| Endpoint | Purpose |
| --- | --- |
| `GET /mail-sources/{source_id}/backfills?limit=20` | List recent queued, running, completed, failed, cancelled, or backoff jobs |
| `POST /mail-sources/{source_id}/backfills` | Queue a backfill window with optional `requested_start`, `requested_end`, and `max_attempts` |
| `GET /mail-sources/{source_id}/backfills/{job_id}` | Inspect one progress row |
| `POST /mail-sources/{source_id}/backfills/{job_id}/cancel` | Cancel a queued, running, or backoff job |
| `POST /mail-sources/{source_id}/backfills/{job_id}/retry` | Re-queue a failed, cancelled, or backoff job |

The Mail Sources UI shows the latest backfill status, processed message counts,
reports found, duplicates, retry timing, progress percentage, and operator
controls. Backfill responses also include computed fields for
`requested_window_days`, `elapsed_seconds`, `status_summary`, `can_cancel`, and
`can_retry` so clients can show actionable progress without parsing cursors.
Workers persist structured provider checkpoints in `cursor_checkpoint`; clients
can inspect that decoded object for connector, window, processed counts, error
counts, and provider page-cursor state while treating the raw `cursor` as
diagnostic text. Gmail API and Microsoft 365 Graph backfills process provider
message pages in bounded batches and re-queue the same job with the next
provider cursor when more pages remain. API responses mask `page_cursor` as
`**redacted**`; only the worker uses the stored raw cursor to resume. The
background scheduler currently executes due IMAP, Gmail, and Microsoft 365
backfill jobs in bounded batches and records results in import history with
trigger `backfill`. In demo mode, DMARQ exposes credential-free synthetic mail
sources and backfill jobs so the workflow is visible without connecting a real
mailbox.

### MSP Operator Views

#### List Workspace Operator Summaries

```text
GET /operator/workspaces
```

Returns safe cross-workspace summaries for MSP operators: workspace identity,
health status, domain/mail-source counts, latest import status, active alert
count, recent drift event count, aggregate report count, and retention controls.
The endpoint does not return raw report records.

#### Get One Workspace Summary

```text
GET /operator/workspaces/{workspace_id}
```

Returns the same operator summary for a single workspace.

#### Update Workspace Retention

```text
PUT /operator/workspaces/{workspace_id}/retention
```

Request:

```json
{
  "aggregate_reports_days": 730,
  "forensic_reports_days": 120,
  "tls_reports_days": 365
}
```

Updates workspace retention controls and writes a sanitized
`workspace.retention_updated` audit event.

### Optional AI Assistance

AI assistance endpoints require administrator access and remain disabled until
`ai.enabled=true` is set in Settings.

#### Read AI Configuration

```text
GET /ai/config
```

Returns provider mode, model name, whether a remote base URL is configured,
redaction mode, action-tool state, MCP state, and data-handling guarantees. Raw
provider credentials are not stored or returned.

#### Build Safe Context

```text
GET /ai/domains/{domain}/context
```

Returns a redacted context payload for a domain. The payload includes summary
counts, recent reports, top sources, evidence links, and the redaction rules
that were applied.

#### Build Evidence Summary

```text
GET /ai/domains/{domain}/summary
```

Returns a deterministic evidence-first summary and remediation plan. Each
recommendation includes evidence links back to the underlying DMARC data.

#### Build Remediation Plan

```text
GET /ai/domains/{domain}/remediation-plan
GET /ai/domains/{domain}/remediation-plan?finding_code=dkim_selector_missing
```

Returns a cached, step-by-step remediation plan built from redacted report,
DNS, selector, mail-source, and provider context. Template mode is deterministic
and never calls a remote model. When `ai.enabled=true` and `ai.provider` is
`local`, `remote`, or `litellm`, DMARQ can ask LiteLLM for an
OpenAI-compatible JSON plan. Demo mode always uses the template plan and a long
cache window.

#### Build Action Proposals

```text
GET /ai/domains/{domain}/action-proposals
```

Returns reproducible proposal artifacts. Proposal generation is read-only and
does not apply DNS or configuration changes.

#### Confirm Proposal

```text
POST /ai/domains/{domain}/action-proposals/confirm
```

Requires `ai.action_tools_enabled=true` and a `confirmation_text` equal to the
proposal ID. Confirmation is written to the workspace audit log. The current
implementation records human confirmation but does not apply external changes.

### MCP Endpoint

The MCP endpoint is disabled until `mcp.enabled=true` is set. It requires a
scoped API token with `mcp:read`.

```text
POST /mcp
```

Supported JSON-RPC methods:

| Method | Purpose |
| --- | --- |
| `initialize` | Return server capabilities |
| `tools/list` | List read-only tool metadata |
| `tools/call` | Call a read-only tool |

Available tools:

| Tool | Purpose |
| --- | --- |
| `list_domains` | List monitored domains and aggregate counts |
| `domain_summary` | Return an evidence-first summary for one domain |
| `action_proposals` | Return reviewable remediation proposals without applying changes |

Every successful tool call is audited as `mcp.tool_called`.

### Domains

#### List Domains

```
GET /domains
```

Returns a list of all domains in your DMARQ instance.

**Example Response:**
```json
{
  "domains": [
    {
      "id": "1",
      "name": "example.com",
      "added_at": "2025-01-15T14:30:00Z",
      "status": "active",
      "compliance_rate": 87.5
    },
    {
      "id": "2",
      "name": "example.org",
      "added_at": "2025-01-16T09:15:00Z",
      "status": "active",
      "compliance_rate": 95.2
    }
  ],
  "total": 2
}
```

#### Get Domain Details

```
GET /domains/{domain_id}
```

Returns details for a specific domain.

**Example Response:**
```json
{
  "id": "1",
  "name": "example.com",
  "added_at": "2025-01-15T14:30:00Z",
  "status": "active",
  "compliance_rate": 87.5,
  "reports_count": 45,
  "last_report_date": "2025-04-01T00:00:00Z",
  "dns_records": {
    "spf": "v=spf1 include:_spf.example.com ~all",
    "dmarc": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
    "mx": ["10 mail.example.com"]
  }
}
```

#### Get BIMI Posture

```
GET /domains/{domain_id}/dns/bimi
```

Returns the cached BIMI TXT posture for the default selector, including the
queried DNS name, record text, logo URL, certificate URL, warnings, and errors.

#### Get DNS Lint Guidance

```
GET /domains/{domain_id}/dns/lint
GET /domains/{domain_id}/dns/change-plan
POST /domains/{domain_id}/dns/change-plan/apply
GET /domains/dns/providers
GET /domains/dns/lint
GET /domains/dns/lint/export
```

Returns typed DNS lint findings with stable `code` values, suggested target
records, and deterministic `remediation_steps` for DMARC, SPF, DKIM, MTA-STS,
TLS-RPT, and BIMI readiness. DKIM findings distinguish missing selectors,
broken CNAME targets, short RSA keys, and stale selectors. The bulk endpoint
returns the same payload shape per monitored domain, and the export endpoint
returns the finding list as CSV for managed-domain reviews.

The single-domain lint payload also includes `change_plans`. The dedicated
`/dns/change-plan` endpoint returns the same operator-facing plans with
proposed DNS records, captured current values, risk notes, rollback notes,
expected health impact, and manual approval flags.

`GET /domains/dns/providers` returns native and Lexicon-backed provider
capabilities. `POST /domains/{domain_id}/dns/change-plan/apply` accepts
`plan_id`, `provider`, `dry_run`, `confirm`, optional `value`, and `ttl`. Calls
default to dry-run. Real writes require `dry_run=false` and `confirm=true`, are
blocked in demo mode, and are limited to safe TXT/CNAME create/update plans
that already have a concrete value. Applied changes are written to the
workspace audit log and refresh provider-backed DNS change history where the
provider supports it.

#### Get Posture Dashboard

```
GET /domains/{domain_id}/posture
```

Returns the evidence-first posture dashboard for one domain. The response
contains the posture score, coverage for DMARC, SPF, DKIM, MTA-STS, and BIMI,
actionable recommendations, recent provider-backed DNS drift summaries, and
short operator playbooks. Recommendation and playbook evidence links point back
to the page section that triggered the finding.

#### Get Source Intelligence

```
GET /domains/{domain_id}/source-intelligence?days=30
```

Returns coarse region summaries and source anomaly hints for one domain.
DMARQ uses existing report metadata when available and deterministic inferred
fallbacks for demo data; it does not require a live GeoIP lookup. The response
includes top regions, source counts, message/failure counts, and anomalies such
as new senders, new regions, source volume spikes, and increased alignment
failures.

`GET /domains/{domain_id}/sources` also includes per-source `geo` and
`anomalies` fields so the domain detail page can show the same context next to
the raw sending-source evidence.

#### Get Health Score History

```
GET /domains/{domain_id}/posture/history
```

Returns persisted daily health score snapshots for one domain, including score,
grade, policy, aggregate report counts, factor scores, top action drivers,
previous score, and score delta. Use `start_date`, `end_date`, and `limit` to
shape audit or dashboard windows. By default the endpoint captures the current
posture as today's snapshot before reading history; pass `capture_current=false`
when reading already persisted evidence only.

#### Get Workspace Health Score History

```
GET /domains/summary/health/history
```

Returns persisted daily health score snapshots aggregated across the selected
workspace. The response includes account-level score, grade, domain count,
aggregate message/report counts, factor scores, top action drivers, previous
score, and score delta. Use `start_date`, `end_date`, and `limit` to shape the
same date windows used by the dashboard. In demo mode, the endpoint falls back
to rolling dmarq.org and dmarq.com demo history when no persisted snapshots are
available.

#### Export Workspace Health Evidence

```
GET /domains/summary/health/evidence/export
```

Exports sanitized workspace-level score history evidence as CSV by default.
Pass `format=json` for a JSON evidence packet. The export aggregates the same
score, grade, policy, aggregate message/report counts, factor scores, and top
action titles used by the dashboard. It does not include forensic message
content, subjects, recipients, or raw uploaded report bodies.

#### Export Health Evidence

```
GET /domains/{domain_id}/posture/evidence/export
```

Exports sanitized domain score history evidence as CSV by default. Pass
`format=json` for a JSON evidence packet. The export includes aggregate posture
metadata only: score, grade, policy, aggregate message/report counts, factor
scores, and top action titles. It does not include forensic message content,
subjects, recipients, or raw uploaded report bodies.

#### Add Domain

```
POST /domains
```

Adds a new domain to DMARQ.

**Request Body:**
```json
{
  "name": "newdomain.com"
}
```

**Example Response:**
```json
{
  "id": "3",
  "name": "newdomain.com",
  "added_at": "2025-04-21T14:22:00Z",
  "status": "active"
}
```

#### Remove Domain

```
DELETE /domains/{domain_id}
```

Removes a domain from DMARQ.

**Example Response:**
```json
{
  "success": true,
  "message": "Domain removed successfully"
}
```

### Reports

#### List Reports

```
GET /reports
```

Returns a list of DMARC reports.

**Query Parameters:**
- `domain_id` - Filter by domain
- `start_date` - Filter by start date (YYYY-MM-DD)
- `end_date` - Filter by end date (YYYY-MM-DD)
- `source_org` - Filter by source organization
- `page` - Page number for pagination (default: 1)
- `limit` - Number of results per page (default: 25, max: 100)

**Example Response:**
```json
{
  "reports": [
    {
      "id": "1",
      "domain": "example.com",
      "report_id": "google.com:1234567890",
      "date_range": {
        "begin": "2025-04-01T00:00:00Z",
        "end": "2025-04-01T23:59:59Z"
      },
      "source_org": "google.com",
      "source_email": "noreply-dmarc-support@google.com",
      "message_count": 156,
      "pass_count": 142,
      "fail_count": 14,
      "pass_rate": 91.0
    }
  ],
  "total": 245,
  "page": 1,
  "limit": 25,
  "total_pages": 10
}
```

#### Get Report Details

```
GET /reports/{report_id}
```

Returns details for a specific report.

**Example Response:**
```json
{
  "id": "1",
  "domain": "example.com",
  "report_id": "google.com:1234567890",
  "date_range": {
    "begin": "2025-04-01T00:00:00Z",
    "end": "2025-04-01T23:59:59Z"
  },
  "source_org": "google.com",
  "source_email": "noreply-dmarc-support@google.com",
  "policy_published": {
    "domain": "example.com",
    "adkim": "r",
    "aspf": "r",
    "p": "none",
    "sp": "none",
    "pct": 100
  },
  "records": [
    {
      "source_ip": "192.0.2.1",
      "count": 34,
      "policy_evaluated": {
        "disposition": "none",
        "dkim": "pass",
        "spf": "pass"
      },
      "identifiers": {
        "header_from": "example.com",
        "envelope_from": "bounces.example.com"
      },
      "auth_results": {
        "dkim": {
          "domain": "example.com",
          "selector": "default",
          "result": "pass"
        },
        "spf": {
          "domain": "bounces.example.com",
          "result": "pass"
        }
      }
    }
  ]
}
```

#### Upload Report

```
POST /reports/upload
```

Uploads a new DMARC report for processing.

**Request Body:**
- Multipart form with file upload (XML, ZIP, or GZ format)

**Example Response:**
```json
{
  "success": true,
  "message": "Report uploaded and queued for processing",
  "task_id": "abcd1234"
}
```

### TLS Reports

#### Upload TLS Report

```
POST /tls-reports/upload
```

Uploads an SMTP TLS Reporting aggregate attachment. Supported file types are
`.json`, `.json.gz`, and `.zip`.

**Example Response:**
```json
{
  "success": true,
  "report_id": "tls-report-20260520",
  "policies_created": 1,
  "policies_skipped": 0,
  "duplicate": false,
  "message": "TLS report imported."
}
```

#### Summarize TLS Reports

```
GET /tls-reports/summary?domain=example.com&days=30
```

Returns aggregate TLS trends, top failure causes, affected domains, and the
privacy controls for stored TLS-RPT data.

### Statistics

#### Compliance Summary

```
GET /stats/{domain_id}/compliance
```

Returns compliance statistics for a domain.

**Query Parameters:**
- `start_date` - Start date (YYYY-MM-DD)
- `end_date` - End date (YYYY-MM-DD)
- `interval` - Aggregation interval (day, week, month)

**Example Response:**
```json
{
  "domain": "example.com",
  "date_range": {
    "start": "2025-03-01",
    "end": "2025-04-01"
  },
  "overall": {
    "total_messages": 4586,
    "pass": 4102,
    "fail": 484,
    "compliance_rate": 89.4,
    "spf_aligned": 4220,
    "dkim_aligned": 4315
  },
  "trend": [
    {
      "date": "2025-03-01",
      "total": 152,
      "pass": 132,
      "fail": 20,
      "rate": 86.8
    },
    // Additional days...
  ]
}
```

#### Source Summary

```
GET /stats/{domain_id}/sources
```

Returns statistics about sending sources.

**Example Response:**
```json
{
  "domain": "example.com",
  "top_sources": [
    {
      "source_ip": "192.0.2.1",
      "source_domain": "mail-server.example.com",
      "message_count": 2156,
      "pass_count": 2156,
      "fail_count": 0,
      "pass_rate": 100.0
    },
    // Additional sources...
  ]
}
```

### System

#### System Status

```
GET /system/status
```

Returns the status of the DMARQ system.

**Example Response:**
```json
{
  "status": "healthy",
  "version": "1.2.0",
  "uptime": 1234567,
  "database": "connected",
  "imap": "connected",
  "domains_count": 5,
  "reports_count": 12543
}
```

## Rate Limiting

The API is rate limited to prevent abuse:

- 60 requests per minute for most endpoints
- 10 requests per minute for upload endpoints

If you exceed these limits, you'll receive a `429 Too Many Requests` response.

## Errors

The API uses standard HTTP status codes to indicate the success or failure of requests:

- `200 OK` - Request succeeded
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Missing or invalid API key
- `403 Forbidden` - API key doesn't have sufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

Error responses include a JSON body with details:

```json
{
  "error": "validation_error",
  "message": "Invalid domain name format",
  "details": {
    "field": "name",
    "reason": "Does not match domain name pattern"
  }
}
```

## SDKs and Integrations

DMARQ provides client libraries for common programming languages:

- Python: [dmarq-python](https://github.com/yourusername/dmarq-python)
- JavaScript/Node.js: [dmarq-node](https://github.com/yourusername/dmarq-node)

## API Versioning

The API uses versioning in the URL path (/api/v1/) to ensure backward compatibility. When breaking changes are necessary, we'll introduce a new version (e.g., /api/v2/).

## Webhooks

DMARQ can notify downstream systems about operational events from
**Settings > Webhooks** or the admin API.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/webhooks` | List endpoints and supported event types |
| `POST /api/v1/webhooks` | Create an endpoint |
| `PUT /api/v1/webhooks/{id}` | Update an endpoint |
| `DELETE /api/v1/webhooks/{id}` | Disable an endpoint while keeping delivery history |
| `POST /api/v1/webhooks/{id}/test` | Queue and attempt a test delivery |
| `GET /api/v1/webhooks/deliveries` | Inspect recent delivery attempts |
| `POST /api/v1/webhooks/deliveries/process` | Attempt due retries |

Supported event types:
- `dmarq.report.imported`
- `dmarq.sender.new`
- `dmarq.compliance.drop`
- `dmarq.reports.missing`
- `dmarq.alert.created`
- `dmarq.alert.resolved`
- `dmarq.webhook.test`

Deliveries are signed with HMAC-SHA256 using the endpoint signing secret.
Receivers should verify these headers:

| Header | Description |
| --- | --- |
| `X-DMARQ-Event` | Event type |
| `X-DMARQ-Delivery` | Delivery id |
| `X-DMARQ-Idempotency-Key` | Stable deduplication key |
| `X-DMARQ-Timestamp` | Unix timestamp used in the signature |
| `X-DMARQ-Signature` | `v1=<hex hmac>` over `timestamp.delivery_id.body` |

Non-2xx responses are retried with exponential backoff until the endpoint's
maximum attempt count is reached. Operators can inspect the delivery status,
last response code, error text, and response excerpt without reading logs.

## Integration Templates

DMARQ ships operator-ready templates for normalized SIEM ingestion:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/integrations/siem/templates` | Return versioned SIEM schemas, examples, config hints, and redaction guidance |
| `GET /api/v1/integrations/ticketing-chatops/templates` | Return Jira, GitHub, Slack, Teams, mapping, dedupe, and operating-model templates |

The SIEM template bundle includes the stable `dmarq.siem.event.v1` envelope,
examples for sender, compliance-drop, and alert events, and ingestion shapes for
Splunk HEC, Elastic ECS, and Microsoft Sentinel custom logs. See
[SIEM Integration Templates](siem-integrations.md) for the full operator guide.

The ticketing/chatops bundle includes event-to-workflow mappings, Jira and
GitHub issue templates, Slack and Microsoft Teams message templates, and
deduplication guidance. See
[Ticketing and Chatops Templates](ticketing-chatops-integrations.md) for the
full operator guide.
