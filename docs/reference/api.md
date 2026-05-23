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

Successful public API calls update the token's last-used timestamp, source IP,
and usage count for auditing.

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

#### Get Posture Dashboard

```
GET /domains/{domain_id}/posture
```

Returns the evidence-first posture dashboard for one domain. The response
contains the posture score, coverage for DMARC, SPF, DKIM, MTA-STS, and BIMI,
actionable recommendations, recent provider-backed DNS drift summaries, and
short operator playbooks. Recommendation and playbook evidence links point back
to the page section that triggered the finding.

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
