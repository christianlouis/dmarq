# Configuration

This guide details all configuration options available in DMARQ.

## Configuration Methods

DMARQ can be configured through:

1. Environment variables
2. A `.env` file
3. The web-based configuration wizard (on first run)

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

### Application Settings

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `APP_NAME` | Custom instance name | `DMARQ` | `Company DMARC Monitor` |
| `TIMEZONE` | Application timezone | `UTC` | `America/New_York`, `Europe/London` |
| `LANGUAGE` | Default language | `en` | `en`, `fr`, `es` |
| `REPORTS_PER_PAGE` | Reports to show per page | `25` | `10`, `50`, `100` |
| `MAX_UPLOAD_SIZE` | Maximum file upload size (MB) | `10` | `20`, `50` |
| `SESSION_LIFETIME` | Session lifetime in minutes | `1440` (24h) | `60`, `720` |

### Alerting Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `ALERTS_ENABLED` | Enable alerts | `false` | `true`, `false` |
| `ALERT_EMAIL` | Email to send alerts to | - | `admin@example.com` |
| `SMTP_SERVER` | SMTP server for sending alerts | - | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` | `587`, `465` |
| `SMTP_USERNAME` | SMTP username | - | `alerts@example.com` |
| `SMTP_PASSWORD` | SMTP password | - | `smtp_password` |
| `SMTP_USE_TLS` | Use TLS for SMTP | `true` | `true`, `false` |
| `ALERT_THRESHOLD` | Compliance threshold for alerts | `90` | `80`, `95` |

### Cloudflare Integration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CF_ENABLED` | Enable Cloudflare integration | `false` | `true`, `false` |
| `CF_API_TOKEN` | Cloudflare API token | - | `your_cloudflare_api_token` |
| `CF_ZONE_ID` | Cloudflare Zone ID | - | `your_cloudflare_zone_id` |

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

### With Email Alerting

```
ALERTS_ENABLED=true
ALERT_EMAIL=admin@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD=smtp_password
SMTP_USE_TLS=true
ALERT_THRESHOLD=95
```

## Configuration Hierarchy

DMARQ uses the following order of precedence for configuration:

1. Environment variables (highest priority)
2. `.env` file
3. Default values (lowest priority)

## Sensitive Information

For sensitive information like passwords and API tokens, we recommend:

1. Use environment variables instead of committing them to files
2. For Docker, use Docker secrets or environment files that are not stored in version control
3. For production systems, consider using a secrets manager like HashiCorp Vault or AWS Secrets Manager

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
- SMTP credentials (if alerting is enabled)

Check the application logs if you encounter startup issues related to configuration.