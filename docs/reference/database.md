# Database Schema

This document describes the database schema used by DMARQ, including tables, relationships, and key fields.

## Overview

DMARQ uses a relational database to store all its data. The schema is designed to efficiently store and query DMARC report data, domain information, and system settings. The system supports both SQLite (for smaller deployments) and PostgreSQL (for production deployments).

## Schema Diagram

![Database Schema](../assets/images/database_schema.png)

## Core Tables

### Domains

The `domains` table stores information about the domains being monitored.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
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
| username | VARCHAR(50) | Username |
| email | VARCHAR(255) | Email address |
| password_hash | VARCHAR(255) | Hashed password |
| full_name | VARCHAR(100) | Full name |
| is_active | BOOLEAN | Whether the account is active |
| is_admin | BOOLEAN | Whether the user is an administrator |
| created_at | TIMESTAMP | When the account was created |
| last_login | TIMESTAMP | When the user last logged in |

### API_Keys

The `api_keys` table stores API keys for programmatic access.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| key_hash | VARCHAR(255) | Hashed API key |
| user_id | INTEGER | Foreign key to users.id |
| name | VARCHAR(100) | Name/description of the key |
| created_at | TIMESTAMP | When the key was created |
| expires_at | TIMESTAMP | When the key expires (optional) |
| last_used | TIMESTAMP | When the key was last used |
| permissions | TEXT | JSON array of permissions |

## DNS and Configuration Tables

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
- `idx_api_keys_key_hash`: On api_keys.key_hash
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

See the [Deployment Guide](../deployment/docker.md) for more information on database backup strategies.