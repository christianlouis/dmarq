# Configuration

This guide details all configuration options available in DMARQ.

## Configuration Methods

DMARQ can be configured through:

1. Environment variables
2. A `.env` file
3. The web-based configuration wizard (on first run)

For production secrets, use the [1Password secret handling guide](secrets.md) so sensitive values are injected into the DMARQ process without being committed or copied into deployment notes.

For database operations, use the [Database Backup and Restore](backups.md) guide before upgrades and migrations.

## Core Settings

### Database Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `DB_TYPE` | Database type | `sqlite` | `sqlite`, `postgres` |
| `DB_PATH` | Path to SQLite database | `./data/dmarq.db` | `/app/data/dmarq.db` |
| `DB_HOST` | PostgreSQL host | `localhost` | `postgres`, `db.example.com` |
| `DB_PORT` | PostgreSQL port | `5432` | `5432` |
| `DB_USER` | PostgreSQL username | `dmarq` | `dmarq_user` |
| `DB_PASS` | PostgreSQL password | - | `secure_password` |
| `DB_NAME` | PostgreSQL database name | `dmarq` | `dmarq_production` |

### Security Settings

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `SECRET_KEY` | Secret key for session security | - | `da39a3ee5e6b4b0d3255bfef95601890` |
| `ALLOWED_HOSTS` | Comma-separated list of allowed hosts | `localhost,127.0.0.1` | `dmarq.example.com,api.dmarq.com` |
| `DEBUG` | Enable debug mode | `false` | `true`, `false` |
| `LOG_LEVEL` | Application logging level | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `CORS_ORIGINS` | Allowed CORS origins | `http://localhost:8000` | `https://dmarq.example.com` |

### Logto Authentication Settings

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `LOGTO_ENDPOINT` | Base URL of your Logto instance | - | `https://your-tenant.logto.app` |
| `LOGTO_APP_ID` | Client ID of the Logto application | - | `your-app-id` |
| `LOGTO_APP_SECRET` | Client Secret of the Logto application | - | `your-app-secret` |
| `LOGTO_REDIRECT_URI` | Override the OAuth callback URL | Auto-detected | `https://dmarq.example.com/api/v1/auth/callback` |
| `LOGTO_SKIP_SSL_VERIFY` | Disable SSL certificate verification for connections to the Logto endpoint. **Only use this when your Logto instance uses a self-signed certificate that you control. Never enable in production environments.** | `false` | `true`, `false` |

### IMAP Settings

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `IMAP_ENABLED` | Enable IMAP report fetching | `false` | `true`, `false` |
| `IMAP_SERVER` | IMAP server address | - | `imap.gmail.com` |
| `IMAP_PORT` | IMAP server port | `993` | `993`, `143` |
| `IMAP_USERNAME` | IMAP username | - | `dmarc@example.com` |
| `IMAP_PASSWORD` | IMAP password | - | `app_password_here` |
| `IMAP_USE_SSL` | Use SSL for IMAP connection | `true` | `true`, `false` |
| `IMAP_POLLING_INTERVAL` | Minutes between polling | `60` | `30`, `60`, `120` |
| `IMAP_FOLDER` | IMAP folder to check | `INBOX` | `DMARC`, `reports` |
| `IMAP_MARK_AS_READ` | Mark processed emails as read | `true` | `true`, `false` |
| `IMAP_ARCHIVE_FOLDER` | Folder to move processed emails to | - | `Processed`, `Archive` |
| `DELETE_IMPORTED_EMAILS` | Delete IMAP emails after a DMARC report is successfully imported | `false` | `true`, `false` |

### Application Settings

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `APP_NAME` | Custom instance name | `DMARQ` | `Company DMARC Monitor` |
| `TIMEZONE` | Application timezone | `UTC` | `America/New_York`, `Europe/London` |
| `LANGUAGE` | Default language | `en` | `en`, `fr`, `es` |
| `REPORTS_PER_PAGE` | Reports to show per page | `25` | `10`, `50`, `100` |
| `MAX_UPLOAD_SIZE` | Maximum file upload size (MB) | `10` | `20`, `50` |
| `SESSION_LIFETIME` | Session lifetime in minutes | `1440` (24h) | `60`, `720` |

### Notification Configuration

DMARQ stores notification targets in the web settings table. Configure them under
**Settings** > **Notifications** and use newline-separated Apprise URLs, such as
email, Slack, Teams, Discord, or webhook targets. Saved target URLs are redacted
from API responses and encrypted at rest with the application `SECRET_KEY`.

| Setting | Description | Default | Example |
|---------|-------------|---------|---------|
| `notifications.apprise_enabled` | Enable Apprise notification delivery | `false` | `true` |
| `notifications.apprise_urls` | Newline-separated Apprise target URLs | - | `mailto://user:pass@example.com` |
| `notifications.min_send_interval_minutes` | Minimum minutes between outbound notification deliveries | `15` | `30` |
| `notifications.redact_pii_enabled` | Redact email addresses from outbound notification text | `true` | `true` |
| `notifications.alert_new_sources_enabled` | Alert on newly observed sending sources | `true` | `true` |
| `notifications.alert_compliance_drop_enabled` | Alert on recent compliance-rate drops | `true` | `true` |
| `notifications.alert_compliance_drop_points` | Minimum compliance-rate drop in percentage points | `10` | `15` |
| `notifications.alert_failure_threshold_enabled` | Alert on high recent DMARC failure volume | `true` | `true` |
| `notifications.alert_failure_threshold_count` | Failed messages in the last day before alerting | `100` | `250` |
| `notifications.alert_missing_reports_enabled` | Alert when a monitored domain stops receiving reports | `true` | `true` |
| `notifications.alert_missing_reports_days` | Days without reports before alerting | `2` | `3` |
| `notifications.summary_daily_enabled` | Send one daily DMARC activity summary | `false` | `true` |
| `notifications.summary_weekly_enabled` | Send one weekly DMARC activity summary | `false` | `true` |
| `notifications.summary_send_hour_utc` | UTC hour for scheduled summaries | `8` | `7` |
| `notifications.summary_weekday_utc` | UTC weekday for weekly summaries, where 0 is Monday | `0` | `4` |

Alert history is stored in the database-backed `alert_history` table.
Notification and alert-rule configuration changes are stored in
`alert_configuration_audit` with secret values sanitized. Current retention is
indefinite; prune old resolved history and audit rows according to your
operational policy if long-term storage size matters.

### Cloudflare Integration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token for read-only zone discovery and DNS inspection | - | `your_cloudflare_api_token` |
| `CLOUDFLARE_ZONE_ID` | Optional default Cloudflare Zone ID | - | `your_cloudflare_zone_id` |
| `WEBHOOK_SECRET` | Required secret for inbound email worker webhooks | - | `openssl rand -hex 32` |

Cloudflare credentials can also be stored from **Settings**. The API token is
encrypted in the settings table and redacted when settings are read back. Leave
the Zone ID blank to discover every active zone visible to the token.

The read-only integration exposes:

- `GET /api/v1/domains/cloudflare/discover` to list available zones.
- `POST /api/v1/domains/cloudflare/import` to create monitored domain rows from zones.
- `GET /api/v1/domains/{domain}/dns/cloudflare` to inspect managed DNS records, return DMARC/SPF/DKIM suggestions, and record detected DNS changes.
- `GET /api/v1/domains/{domain}/dns/history` to review DNS record additions, modifications, and removals.

### DNS Result Cache

DMARC, SPF, and DKIM DNS checks are cached in the database-backed `dns_cache`
table for 15 minutes per domain, DNS provider, and DKIM selector set. Domain DNS
API responses include whether the result came from cache and when it was
checked. Use `?refresh=true` on the domain DNS endpoint to bypass a fresh cache
entry for operational rechecks.

Cloudflare-managed DNS record snapshots and change events are stored in
`dns_record_snapshots` and `dns_record_changes`. They are updated whenever the
Cloudflare DNS analysis endpoint is called.

### Advanced Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `WORKERS` | Number of worker processes | `1` | `2`, `4` |
| `WORKER_CONCURRENCY` | Tasks per worker | `2` | `4`, `8` |
| `MAX_CONNECTIONS` | Database connection pool size | `10` | `20`, `50` |
| `CACHE_TYPE` | Cache backend type | `memory` | `memory`, `redis` |
| `CACHE_URL` | Cache backend URL | - | `redis://localhost:6379/0` |
| `CACHE_TTL` | Cache TTL in seconds | `300` | `600`, `1800` |

## Configuration Examples

### Basic SQLite Setup

```
DB_TYPE=sqlite
DB_PATH=./data/dmarq.db
SECRET_KEY=your_secure_key_here
```

### Production PostgreSQL Setup

```
DB_TYPE=postgres
DB_HOST=postgres.example.com
DB_PORT=5432
DB_USER=dmarq
DB_PASS=secure_password
DB_NAME=dmarq_production
SECRET_KEY=your_secure_key_here
ALLOWED_HOSTS=dmarq.example.com
DEBUG=false
```

### With IMAP Enabled

```
IMAP_ENABLED=true
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USERNAME=dmarc@example.com
IMAP_PASSWORD=app_password_here
IMAP_USE_SSL=true
IMAP_POLLING_INTERVAL=30
IMAP_MARK_AS_READ=true
```

### With Apprise Notifications

1. Open **Settings** > **Notifications**.
2. Enable notifications.
3. Add one Apprise target URL per line.
4. Save and use **Send Test** to verify delivery.

## Configuration Hierarchy

DMARQ uses the following order of precedence for configuration:

1. Environment variables (highest priority)
2. `.env` file
3. Default values (lowest priority)

## Sensitive Information

For sensitive information like passwords and API tokens, we recommend:

1. Use 1Password Environments or another deployment secrets manager instead of committing secrets to files
2. Inject secrets as environment variables or a locally mounted env file that is not stored in version control
3. Keep separate secret bundles for development, preprod, and production
4. Rotate credentials from the secret manager first, then restart DMARQ so it receives the new values

See [Secret Handling with 1Password](secrets.md) for the recommended production workflow.

## Runtime Configuration Changes

Some settings can be changed through the web interface after installation:

1. Navigate to **Settings** > **System** in the DMARQ interface
2. Modify the available settings
3. Click **Save Changes**

Note that some core settings (like database connection parameters) can only be changed via environment variables or the `.env` file and require a restart of the application.

## Configuration Validation

DMARQ validates your configuration on startup. If there are issues, they will be logged and the application may not start correctly. Common validation checks include:

- Database connection parameters
- Secret key presence and strength
- IMAP credentials (if IMAP is enabled)
- Notification targets can be tested from the settings page

Check the application logs if you encounter startup issues related to configuration.
