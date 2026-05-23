# TLS Reports

DMARQ can import SMTP TLS Reporting (TLS-RPT) JSON aggregates and summarize
delivery security failures alongside the existing DMARC posture views.

## Importing TLS Reports

Open **TLS Reports** and upload a `.json`, `.json.gz`, or `.zip` TLS-RPT
attachment. A single file can contain multiple policy domains; DMARQ stores
each policy-domain entry independently and skips duplicates by `report-id` plus
policy domain.

Imported reports appear in the same page as:

- daily successful and failed TLS session trends
- top TLS failure causes grouped by `result-type`
- affected policy domains with failure rates
- receiving MX hostnames and reason codes when reporters include them

## API

TLS reporting endpoints require the same admin authentication as other
operational endpoints:

- `POST /api/v1/tls-reports/upload` imports one TLS-RPT attachment.
- `GET /api/v1/tls-reports` lists stored TLS report policy entries.
- `GET /api/v1/tls-reports/summary?domain=example.com&days=30` returns trends,
  top failure causes, and affected domains.

## Retention and Privacy

DMARQ stores only aggregate TLS reporting posture data:

- report ID
- reporting organization and contact info
- policy domain and policy type
- report date range
- successful and failed session counts
- grouped failure result type and failed-session count
- sending MTA IP, receiving MX hostname, HELO, or IP when supplied by the report
- failure reason code and grouped diagnostic text

DMARQ does not store:

- message bodies
- message subjects
- sender or recipient addresses
- recipient local-parts
- raw uploaded attachments
- mailbox credentials or source message identifiers

Use normal database backup and retention processes to control how long imported
TLS-RPT aggregates remain available.
