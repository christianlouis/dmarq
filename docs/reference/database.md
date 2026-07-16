# Database Schema

This document describes the database schema used by DMARQ, including tables, relationships, and key fields.

## Overview

DMARQ uses a relational database to store all its data. The schema is designed to efficiently store and query DMARC report data, domain information, and system settings. The system supports both SQLite (for smaller deployments) and PostgreSQL (for production deployments).

## Schema Diagram

The schema is migration-managed with Alembic. Organizations contain workspaces;
memberships attach users and roles to those boundaries; domains and mail sources
belong to a workspace; imported report rows retain the workspace and domain
scope used by dashboards, exports, remediation, and provider support sessions.
The tables below are the canonical schema reference.

## Core Tables

### Workspaces

The `workspaces` table stores tenant boundaries for multi-organization and MSP
deployments. Existing single-tenant installs are attached to the default
workspace during migration.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Foreign key to organizations.id |
| slug | VARCHAR | Unique stable workspace slug |
| name | VARCHAR | Display name |
| description | TEXT | Optional operator-facing description |
| active | BOOLEAN | Whether the workspace can be used |
| report_retention_days | INTEGER | Aggregate DMARC report retention target |
| forensic_retention_days | INTEGER | Forensic report retention target |
| tls_report_retention_days | INTEGER | SMTP TLS report retention target |
| created_at | TIMESTAMP | When the workspace was created |
| updated_at | TIMESTAMP | When the workspace was last updated |

### Organizations

The `organizations` table stores the account boundary above one or more
workspaces. It represents the SaaS customer, ISP provider account, managed
service customer, or default self-hosted account.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| slug | VARCHAR | Unique stable organization slug |
| name | VARCHAR | Display name |
| description | TEXT | Optional operator-facing description |
| active | BOOLEAN | Whether the organization can be used |
| created_at | TIMESTAMP | When the organization was created |
| updated_at | TIMESTAMP | When the organization was last updated |

### Organization_Memberships

The `organization_memberships` table stores account-level roles that can span
multiple workspaces.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Foreign key to organizations.id |
| user_id | INTEGER | Foreign key to users.id |
| role | VARCHAR(50) | Organization role such as organization_owner or billing_admin |
| active | BOOLEAN | Whether the membership can be used |
| created_at | TIMESTAMP | When the membership was created |
| updated_at | TIMESTAMP | When the membership was last updated |

### Plans

The `plans` table stores entitlement bundles for hosted, provider-billed, and
self-hosted deployments.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| code | VARCHAR(80) | Stable plan code |
| name | VARCHAR | Display name |
| billing_mode | VARCHAR(50) | Billing mode such as direct_stripe or provider_resale |
| public | BOOLEAN | Whether the plan is visible in self-service flows |
| active | BOOLEAN | Whether the plan can be used |
| monthly_price_cents | INTEGER | Optional monthly list price |
| annual_price_cents | INTEGER | Optional annual list price |
| currency | VARCHAR(3) | ISO currency code |
| included_sending_domains | INTEGER | Included domain limit, if any |
| included_message_volume | INTEGER | Included aggregate message volume, if any |
| included_users | INTEGER | Included user limit, if any |
| retention_days | INTEGER | Default report retention target |
| features | TEXT | Comma-separated feature keys |

### Billing_Accounts

The `billing_accounts` table stores the billing destination for an organization.
It supports Stripe subscriptions, manual contracts, provider resale, WHMCS-style
hosting billing, TM Forum style provider billing, and self-hosted licenses.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Foreign key to organizations.id |
| billing_mode | VARCHAR(50) | Billing mode |
| status | VARCHAR(50) | Billing account status |
| provider_id | VARCHAR(120) | Optional external provider identifier |
| external_customer_id | VARCHAR(120) | Optional provider customer identifier |
| stripe_customer_id | VARCHAR(120) | Optional Stripe customer identifier |
| invoice_delivery_mode | VARCHAR(50) | How invoices are delivered |
| tax_reference | VARCHAR(120) | Optional tax or contract reference |

### Subscriptions

The `subscriptions` table stores current and historical plan assignments. Stripe
IDs are optional so provider-billed and self-hosted accounts can be represented
without Stripe.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Foreign key to organizations.id |
| plan_id | INTEGER | Foreign key to plans.id |
| billing_account_id | INTEGER | Foreign key to billing_accounts.id |
| billing_mode | VARCHAR(50) | Billing mode |
| status | VARCHAR(50) | Subscription lifecycle status |
| current_period_start | TIMESTAMP | Current billing period start |
| current_period_end | TIMESTAMP | Current billing period end |
| stripe_subscription_id | VARCHAR(120) | Optional Stripe subscription identifier |
| external_subscription_id | VARCHAR(120) | Optional provider subscription identifier |
| external_product_code | VARCHAR(120) | Optional provider product code |
| canceled_at | TIMESTAMP | Cancellation time, if any |

### Entitlements

The `entitlements` table stores normalized feature grants and limits derived
from plans, contracts, provider billing systems, or local configuration.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Foreign key to organizations.id |
| subscription_id | INTEGER | Optional foreign key to subscriptions.id |
| key | VARCHAR(120) | Feature or limit key |
| value | VARCHAR(255) | Feature or limit value |
| source | VARCHAR(50) | Source such as plan, contract, or provider |
| active | BOOLEAN | Whether the entitlement is currently active |
| effective_from | TIMESTAMP | Start of the grant |
| expires_at | TIMESTAMP | Optional expiry |

### Usage_Records

The `usage_records` table stores period-based usage for invoices, overages, and
provider monthly-bill exports.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Foreign key to organizations.id |
| workspace_id | INTEGER | Optional foreign key to workspaces.id |
| metric | VARCHAR(120) | Usage metric key |
| quantity | INTEGER | Usage quantity |
| unit | VARCHAR(50) | Unit such as messages or workspaces |
| period_start | TIMESTAMP | Usage period start |
| period_end | TIMESTAMP | Usage period end |
| idempotency_key | VARCHAR(160) | Stable key for exports and retries |
| source | VARCHAR(50) | Source system |
| external_customer_id | VARCHAR(120) | Optional provider customer identifier |

### Provider_Integrations

The `provider_integrations` table stores ISP, MSP, registrar, or hosting-system
integration registrations.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Optional foreign key to organizations.id |
| name | VARCHAR | Operator-facing name |
| provider_type | VARCHAR(80) | Integration type such as whmcs or tmf |
| status | VARCHAR(50) | Integration lifecycle status |
| external_provider_id | VARCHAR(120) | Optional external provider identifier |
| scopes | TEXT | Comma-separated scopes or capabilities |
| callback_url | TEXT | Optional callback URL |

### Billing_Events

The `billing_events` table stores auditable billing lifecycle events without
retaining full provider payloads.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| organization_id | INTEGER | Optional foreign key to organizations.id |
| subscription_id | INTEGER | Optional foreign key to subscriptions.id |
| billing_mode | VARCHAR(50) | Billing mode |
| event_type | VARCHAR(120) | Stable event key |
| provider_id | VARCHAR(120) | Optional provider identifier |
| external_event_id | VARCHAR(160) | Optional provider event identifier |
| status | VARCHAR(50) | Processing status |
| payload_summary | TEXT | Sanitized event summary |

### Workspace_Memberships

The `workspace_memberships` table stores user role assignments for workspace
RBAC.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| workspace_id | INTEGER | Foreign key to workspaces.id |
| user_id | INTEGER | Foreign key to users.id |
| role | VARCHAR(50) | Workspace role such as workspace_owner or analyst |
| active | BOOLEAN | Whether the membership can be used |
| created_at | TIMESTAMP | When the membership was created |
| updated_at | TIMESTAMP | When the membership was last updated |

### Workspace_Audit_Logs

The `workspace_audit_logs` table records sanitized sensitive actions per
workspace so operators can answer who changed what and when.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| workspace_id | INTEGER | Foreign key to workspaces.id |
| actor_type | VARCHAR(50) | Authentication type, such as session or api_key |
| actor_id | VARCHAR(120) | User, token, or auth actor identifier |
| action | VARCHAR(100) | Stable action key, such as mail_source.updated |
| entity_type | VARCHAR(80) | Entity category affected |
| entity_id | VARCHAR(120) | Affected entity identifier |
| entity_name | VARCHAR(255) | Optional display name for the entity |
| details | TEXT | Sanitized JSON details with secret fields redacted |
| ip_address | VARCHAR(64) | Client IP when available |
| created_at | TIMESTAMP | When the action happened |

### Domains

The `domains` table stores information about the domains being monitored.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| workspace_id | INTEGER | Foreign key to workspaces.id |
| name | VARCHAR(255) | Domain name (e.g., example.com) |
| created_at | TIMESTAMP | When the domain was added |
| active | BOOLEAN | Whether the domain is actively monitored |
| notes | TEXT | Optional notes about the domain |
| compliance_rate | FLOAT | Cached compliance rate |
| last_updated | TIMESTAMP | When data was last updated |

### Reports

The `reports` table stores metadata about DMARC aggregate reports.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| domain_id | INTEGER | Foreign key to domains.id |
| report_id | VARCHAR(255) | Original report ID from the provider |
| begin_date | TIMESTAMP | Start of report period |
| end_date | TIMESTAMP | End of report period |
| org_name | VARCHAR(255) | Organization that sent the report |
| email | VARCHAR(255) | Email that sent the report |
| processed_at | TIMESTAMP | When the report was processed |
| extra_contact_info | VARCHAR(255) | Additional contact info, if provided |
| error | TEXT | Error information if processing failed |
| raw_xml | TEXT | Original XML report (optional, can be disabled) |

### Report_Records

The `report_records` table stores individual authentication results from reports.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| report_id | INTEGER | Foreign key to reports.id |
| source_ip | VARCHAR(45) | Source IP address |
| count | INTEGER | Count of messages |
| disposition | VARCHAR(10) | Policy applied (none, quarantine, reject) |
| dkim_aligned | BOOLEAN | Whether DKIM alignment passed |
| spf_aligned | BOOLEAN | Whether SPF alignment passed |
| passed | BOOLEAN | Whether overall DMARC passed |
| header_from | VARCHAR(255) | Domain in From header |
| envelope_from | VARCHAR(255) | Domain in envelope From |
| envelope_to | VARCHAR(255) | Domain in envelope To |

### Forensic_Reports

The `forensic_reports` table stores DMARC forensic reports.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| domain_id | INTEGER | Foreign key to domains.id |
| report_id | VARCHAR(255) | Original report ID |
| date | TIMESTAMP | When the report was generated |
| source_ip | VARCHAR(45) | Source IP address |
| source_hostname | VARCHAR(255) | Source hostname, if available |
| failure_type | VARCHAR(20) | Type of auth failure (dkim, spf, both) |
| auth_failure_detail | TEXT | Detailed reason for failure |
| delivery_action | VARCHAR(20) | Action taken (delivered, quarantined, rejected) |
| subject | VARCHAR(255) | Email subject |
| processed_at | TIMESTAMP | When the report was processed |
| headers | TEXT | Email headers |
| original_mail | TEXT | Original email content (if available) |

### IP_Info

The `ip_info` table caches information about IP addresses.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| ip | VARCHAR(45) | IP address |
| hostname | VARCHAR(255) | Resolved hostname |
| country | VARCHAR(2) | Country code |
| asn | INTEGER | Autonomous System Number |
| org | VARCHAR(255) | Organization name |
| last_updated | TIMESTAMP | When the data was last updated |

## User and Authentication Tables

### Users

The `users` table stores user account information.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| workspace_id | INTEGER | Foreign key to workspaces.id |
| username | VARCHAR(50) | Username |
| email | VARCHAR(255) | Email address |
| password_hash | VARCHAR(255) | Hashed password |
| full_name | VARCHAR(100) | Full name |
| is_active | BOOLEAN | Whether the account is active |
| is_admin | BOOLEAN | Whether the user is an administrator |
| created_at | TIMESTAMP | When the account was created |
| last_login | TIMESTAMP | When the user last logged in |

### API_Tokens

The `api_tokens` table stores hashed, scoped API tokens for stable read-only
automation access. Raw token secrets are returned only once at creation time
and are never stored.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| name | VARCHAR(120) | Name/description of the token |
| key_hash | VARCHAR(255) | Bcrypt hash of the token secret |
| key_prefix | VARCHAR(16) | Non-secret prefix for operator identification |
| scopes | TEXT | Comma-separated scopes such as `reports:read` |
| active | BOOLEAN | Whether the token can be used |
| created_at | TIMESTAMP | When the key was created |
| updated_at | TIMESTAMP | When the token row was last changed |
| revoked_at | TIMESTAMP | When the token was revoked |
| last_used_at | TIMESTAMP | Last successful API use |
| last_used_ip | VARCHAR(64) | Source IP from the last successful API use |
| usage_count | INTEGER | Successful API use count |

### Webhook_Endpoints

The `webhook_endpoints` table stores outbound webhook destinations. Target
URLs and signing secrets are encrypted at rest.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| name | VARCHAR(120) | Operator-facing endpoint name |
| url | TEXT | Encrypted destination URL |
| secret | TEXT | Encrypted signing secret |
| event_types | TEXT | Comma-separated event subscriptions, or `*` |
| enabled | BOOLEAN | Whether deliveries can be sent |
| max_attempts | INTEGER | Maximum attempts before a delivery fails |
| timeout_seconds | INTEGER | Per-request timeout |
| last_success_at | TIMESTAMP | Last successful delivery |
| last_failure_at | TIMESTAMP | Last failed delivery attempt |
| failure_count | INTEGER | Consecutive endpoint-level failures |

### Webhook_Deliveries

The `webhook_deliveries` table records delivery attempts and retry state.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| endpoint_id | INTEGER | Foreign key to webhook_endpoints.id |
| event_type | VARCHAR(80) | Delivered event type |
| payload | TEXT | Event envelope JSON |
| idempotency_key | VARCHAR(160) | Stable deduplication key per endpoint |
| status | VARCHAR(24) | pending, delivered, failed, or abandoned |
| attempt_count | INTEGER | Attempts already made |
| max_attempts | INTEGER | Maximum attempts for this delivery |
| next_attempt_at | TIMESTAMP | Next retry time |
| last_attempt_at | TIMESTAMP | Last attempt time |
| delivered_at | TIMESTAMP | Successful delivery time |
| last_status_code | INTEGER | Last HTTP status code |
| last_error | TEXT | Last sanitized error |
| response_excerpt | TEXT | Truncated downstream response |

## DNS and Configuration Tables

### Mail_Sources

The `mail_sources` table stores configured inboxes used to retrieve DMARC,
forensic, and SMTP TLS reports.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| workspace_id | INTEGER | Foreign key to workspaces.id |
| name | VARCHAR | Human-readable source name |
| method | VARCHAR | Source type such as IMAP, Gmail API, or Microsoft Graph |
| server | VARCHAR | IMAP/POP server hostname |
| port | INTEGER | IMAP/POP server port |
| username | VARCHAR | Mailbox username |
| password | TEXT | Encrypted mailbox password |
| m365_auth_mode | VARCHAR | Microsoft 365 authentication mode: `delegated` or `application` |
| enabled | BOOLEAN | Whether scheduled imports should poll this source |
| last_checked | TIMESTAMP | Last polling attempt time |
| created_at | TIMESTAMP | When the source was created |
| updated_at | TIMESTAMP | When the source was last updated |

### DNS_Records

The `dns_records` table stores DNS record information for domains.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| domain_id | INTEGER | Foreign key to domains.id |
| record_type | VARCHAR(10) | Type of record (SPF, DMARC, DKIM, MX, etc.) |
| value | TEXT | Value of the DNS record |
| status | VARCHAR(20) | Status (valid, invalid, warning) |
| last_checked | TIMESTAMP | When the record was last checked |
| dkim_selector | VARCHAR(50) | Selector (for DKIM records) |

### Settings

The `settings` table stores system-wide settings.

| Column | Type | Description |
|--------|------|-------------|
| key | VARCHAR(100) | Setting key (primary key) |
| value | TEXT | Setting value |
| description | VARCHAR(255) | Description of the setting |
| type | VARCHAR(20) | Data type (string, integer, boolean, json) |
| updated_at | TIMESTAMP | When the setting was last updated |
| updated_by | INTEGER | Foreign key to users.id |

## Relationship Tables

### User_Domain_Access

The `user_domain_access` table manages user permissions for specific domains.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to users.id |
| domain_id | INTEGER | Foreign key to domains.id |
| permission | VARCHAR(20) | Permission level (view, edit, admin) |

### Domain_Groups

The `domain_groups` table defines groups of domains.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| name | VARCHAR(100) | Group name |
| description | TEXT | Group description |
| created_by | INTEGER | Foreign key to users.id |
| created_at | TIMESTAMP | When the group was created |

### Domain_Group_Members

The `domain_group_members` table assigns domains to groups.

| Column | Type | Description |
|--------|------|-------------|
| group_id | INTEGER | Foreign key to domain_groups.id |
| domain_id | INTEGER | Foreign key to domains.id |

## Logging Tables

### Activity_Logs

The `activity_logs` table records user actions.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to users.id (null for system) |
| action | VARCHAR(50) | Type of action performed |
| entity_type | VARCHAR(50) | Type of entity affected (domain, report, user) |
| entity_id | INTEGER | ID of the affected entity |
| details | TEXT | JSON with additional details |
| timestamp | TIMESTAMP | When the action occurred |
| ip_address | VARCHAR(45) | IP address of the user |

### System_Logs

The `system_logs` table records system events.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| level | VARCHAR(10) | Log level (info, warning, error, debug) |
| message | TEXT | Log message |
| component | VARCHAR(50) | Component that generated the log |
| timestamp | TIMESTAMP | When the event occurred |
| additional_data | TEXT | JSON with additional data |

## Indexes

The schema includes several indexes to optimize query performance:

- `idx_reports_domain_id`: On reports.domain_id
- `idx_reports_begin_date`: On reports.begin_date
- `idx_reports_end_date`: On reports.end_date
- `idx_report_records_report_id`: On report_records.report_id
- `idx_report_records_source_ip`: On report_records.source_ip
- `idx_users_username`: On users.username
- `idx_users_email`: On users.email
- `idx_domains_name`: On domains.name
- `ix_api_tokens_key_hash`: On api_tokens.key_hash
- `ix_api_tokens_key_prefix`: On api_tokens.key_prefix
- `ix_api_tokens_active_scope`: On api_tokens.active and api_tokens.scopes
- `ix_webhook_endpoints_enabled_events`: On webhook_endpoints.enabled and webhook_endpoints.event_types
- `ix_webhook_delivery_endpoint_idempotency`: Unique on webhook_deliveries.endpoint_id and idempotency_key
- `ix_webhook_delivery_due`: On webhook_deliveries.status and webhook_deliveries.next_attempt_at
- `idx_activity_logs_timestamp`: On activity_logs.timestamp
- `idx_activity_logs_user_id`: On activity_logs.user_id
- `idx_system_logs_timestamp`: On system_logs.timestamp
- `idx_system_logs_level`: On system_logs.level

## Migrations

Database migrations are managed using Alembic, which provides:

- Version control for the database schema
- Automatic schema updates during application upgrades
- Ability to roll back changes if needed
- Generation of new migration scripts for schema changes

To apply migrations:

```bash
cd backend/app
python -m alembic upgrade head
```

To create a new migration after schema changes:

```bash
python -m alembic revision --autogenerate -m "Description of changes"
```

## Query Optimization

The database schema is designed with query optimization in mind:

- Frequently used fields have indexes
- Historical data can be efficiently queried by date ranges
- Counters and aggregate data are cached where appropriate
- Domain-specific data is properly segmented

## Database Backup

Regular backups of the database should be configured:

- For SQLite: Simple file copy or SQLite's `.backup` command
- For PostgreSQL: `pg_dump` command or continuous archiving with WAL

See [Database Backup and Restore](../deployment/backups.md) for backup, restore, and verification commands.
