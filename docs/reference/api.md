# API Reference

DMARQ provides a comprehensive REST API that allows you to integrate with external systems and build custom workflows.

## Authentication

All API requests require authentication using an API key.

### API Keys

To use the API, you need to generate an API key:

1. Navigate to **Settings** > **API Access** in the DMARQ UI
2. Click **Create API Key**
3. Enter a description for the key (e.g., "Integration with Slack")
4. Select the permissions you want to grant to this key
5. Click **Generate Key**
6. Copy the key immediately (it will only be shown once)

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

DMARQ can notify your systems about events via webhooks:

1. Navigate to **Settings** > **API Access** > **Webhooks**
2. Click **Add Webhook**
3. Configure:
   - Destination URL
   - Secret token (for verification)
   - Events to subscribe to

Supported events:
- `report.processed` - When a new report is processed
- `compliance.threshold` - When compliance falls below threshold
- `domain.added` - When a domain is added
- `domain.removed` - When a domain is removed