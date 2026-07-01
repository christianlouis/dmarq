# Configuration

This guide details all configuration options available in DMARQ.

## Configuration Methods

DMARQ can be configured through:

1. Environment variables
2. A `.env` file
3. The web-based configuration wizard (on first run)

For production secrets, use the [1Password secret handling guide](secrets.md) so sensitive values are injected into the DMARQ process without being committed or copied into deployment notes.

For database operations, use the [Database Backup and Restore](backups.md) guide before upgrades and migrations.
For deployment verification, upgrades, rollback, and routine checks, use the [Operator Runbook](operations.md). For incident response, use [Troubleshooting Playbooks](troubleshooting.md).

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

DMARQ supports multiple authentication modes. Keep `AUTH_MODE=auto` to preserve
the existing Logto auto-detection behavior, or choose an explicit mode.
The setup page and `GET /api/v1/auth/providers` expose the same provider
registry so operators can see which identity modes are ready, which values are
missing, and which ecosystem presets use the generic OIDC or trusted-proxy
paths.

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `AUTH_MODE` | Browser authentication mode: `auto`, `disabled`, `logto`, `authentik`, `oidc`, or `trusted_proxy` | `auto` | `authentik` |
| `AUTH_DISABLED` | Disable authentication entirely. Only use for local development or a separately protected deployment. | `false` | `true`, `false` |
| `PUBLIC_BASE_URL` | Public URL used when building OAuth callback URLs behind a reverse proxy or ingress | Auto-detected | `https://dmarq.example.com` |

#### Logto

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `LOGTO_ENDPOINT` | Base URL of your Logto instance | - | `https://your-tenant.logto.app` |
| `LOGTO_APP_ID` | Client ID of the Logto application | - | `your-app-id` |
| `LOGTO_APP_SECRET` | Client Secret of the Logto application | - | `your-app-secret` |
| `LOGTO_REDIRECT_URI` | Override the OAuth callback URL | Auto-detected | `https://dmarq.example.com/api/v1/auth/callback` |
| `LOGTO_SKIP_SSL_VERIFY` | Disable SSL certificate verification for connections to the Logto endpoint. **Only use this when your Logto instance uses a self-signed certificate that you control. Never enable in production environments.** | `false` | `true`, `false` |

#### Authentik Direct OIDC

Create an Authentik OAuth2/OpenID provider and register DMARQ's callback URL:
`https://<your-dmarq-host>/api/v1/auth/callback`.

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `AUTH_MODE` | Set to `authentik` for direct Authentik OIDC | `auto` | `authentik` |
| `AUTHENTIK_ISSUER_URL` | Authentik provider issuer URL | - | `https://idp.example.com/application/o/dmarq` |
| `AUTHENTIK_CLIENT_ID` | Authentik OAuth client ID | - | `client-id` |
| `AUTHENTIK_CLIENT_SECRET` | Authentik OAuth client secret | - | `client-secret` |
| `AUTHENTIK_REDIRECT_URI` | Optional callback URL override | Auto-detected | `https://dmarq.example.com/api/v1/auth/callback` |
| `AUTHENTIK_ALLOWED_EMAILS` | Optional comma-separated email allowlist | - | `admin@example.com` |
| `AUTHENTIK_ALLOWED_DOMAINS` | Optional comma-separated email-domain allowlist | - | `example.com,example.org` |

#### Generic OIDC

Use this for Keycloak, Entra ID, Google Workspace, Okta, Ping/OneLogin, and
other OIDC-capable providers.

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `AUTH_MODE` | Set to `oidc` for generic OIDC | `auto` | `oidc` |
| `OIDC_ISSUER_URL` | OIDC issuer URL | - | `https://idp.example.com/realms/dmarq` |
| `OIDC_CLIENT_ID` | OIDC client ID | - | `dmarq` |
| `OIDC_CLIENT_SECRET` | OIDC client secret | - | `client-secret` |
| `OIDC_REDIRECT_URI` | Optional callback URL override | Auto-detected | `https://dmarq.example.com/api/v1/auth/callback` |
| `OIDC_PROVIDER_LABEL` | UI label for the sign-in provider | `OpenID Connect` | `Keycloak` |
| `OIDC_ALLOWED_EMAILS` | Optional comma-separated email allowlist | - | `admin@example.com` |
| `OIDC_ALLOWED_DOMAINS` | Optional comma-separated email-domain allowlist | - | `example.com` |
| `OIDC_SKIP_SSL_VERIFY` | Disable TLS verification for provider requests. Do not use in production unless explicitly allowed. | `false` | `true`, `false` |

Presets such as Keycloak, Microsoft Entra ID, and Google Workspace do not need
bespoke DMARQ code paths. Use `AUTH_MODE=oidc`, set `OIDC_PROVIDER_LABEL` to
the provider name, and restrict single-user/self-hosted installs with
`OIDC_ALLOWED_EMAILS` or `OIDC_ALLOWED_DOMAINS`.

#### Authentik Outpost / Trusted Proxy

Use `AUTH_MODE=trusted_proxy` only when DMARQ is not reachable except through a
trusted authentication proxy such as an Authentik Outpost. DMARQ trusts the
configured headers and treats the authenticated user as the self-hosted instance
owner.

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `AUTH_MODE` | Enable trusted proxy mode | `auto` | `trusted_proxy` |
| `AUTH_TRUSTED_PROXY_PROVIDER` | Provider label stored in auth context | `authentik` | `authentik` |
| `AUTH_TRUSTED_PROXY_EMAIL_HEADER` | Header containing the authenticated email | `X-Authentik-Email` | `X-Authentik-Email` |
| `AUTH_TRUSTED_PROXY_SUBJECT_HEADER` | Header containing the stable user id | `X-Authentik-Uid` | `X-Authentik-Uid` |
| `AUTH_TRUSTED_PROXY_NAME_HEADER` | Header containing display name | `X-Authentik-Name` | `X-Authentik-Name` |
| `AUTH_TRUSTED_PROXY_USERNAME_HEADER` | Header containing username | `X-Authentik-Username` | `X-Authentik-Username` |
| `AUTH_TRUSTED_PROXY_ALLOWED_EMAILS` | Optional comma-separated email allowlist | - | `admin@example.com` |
| `AUTH_TRUSTED_PROXY_ALLOWED_DOMAINS` | Optional comma-separated domain allowlist | - | `example.com` |

Cloudflare Access and Akamai EAA are tracked as trusted-proxy presets, not DNS
provider account connectors. Use them only when they are the sole path to
DMARQ, strip spoofed identity headers, and provide a stable verified identity.
DNS zone access for Cloudflare, Akamai Edge DNS/FastDNS, Route53, Hetzner, and
Linode is separate from login and belongs to the DNS provider connector flow.

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
| `DEMO_MODE` | Force generated demo reports and demo DNS records for public demo instances. Do not enable on production customer data. | `false` | `true` |

### Sender Reputation Feeds

External sender-IP reputation feeds are disabled by default. Enable them only
after reviewing each provider's terms, credential model, rate limits, and
privacy implications. DMARQ never needs these feeds to parse DMARC reports; they
only enrich observed sending-source evidence.

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `SOURCE_REPUTATION_FEEDS_ENABLED` | Enable external reputation feed lookups. Demo mode still disables live external lookups. | `false` | `true` |
| `SOURCE_REPUTATION_FEEDS` | Comma-separated enabled feed IDs. Supported first IDs are `spamhaus_dqs`, `spamcop_scbl`, and `barracuda_brbl`. | - | `spamhaus_dqs,spamcop_scbl` |
| `SOURCE_REPUTATION_SPAMHAUS_DQS_ZONE` | Spamhaus DQS query zone assigned to your account. Required before the `spamhaus_dqs` provider becomes active. | - | `example.dq.spamhaus.net` |
| `SOURCE_REPUTATION_FEED_TIMEOUT_SECONDS` | Per-provider DNSBL lookup timeout. | `2` | `2` |
| `SOURCE_REPUTATION_FEED_CACHE_SECONDS` | Persistent cache TTL for per-IP feed results. | `86400` | `86400` |
| `SOURCE_REPUTATION_FEED_MAX_IPS` | Maximum source IPs checked per reputation refresh. | `100` | `250` |

Feed lookups are skipped for private, reserved, loopback, and otherwise
non-global IP addresses. Feed failures are shown as evidence, but they do not
create blacklist findings by themselves. A source is treated as listed only when
a configured provider returns a positive listing response.

### Demo Mode

Set `DEMO_MODE=true` only for public demo environments such as `demo.dmarq.org`.
When enabled, DMARQ replaces the in-memory report store with deterministic
synthetic DMARC aggregate reports for `dmarq.org` and `dmarq.com`. The data is
generated inside the application, rolls forward with the current date, and
always covers the last 90 days so 30, 60, and 90 day views remain populated.

Demo mode also uses a built-in DNS provider for those two domains. It returns a
mix of clean records, middle-of-the-road records, and intentional lint findings
so the domain detail, posture, DNS guidance, CSV export, and report views have
useful content without requiring real inbound reports or public DNS changes.

The generated data also fills the dashboard summary API, top sending source
rankings, change summaries, redacted forensic/failure samples, and SMTP TLS
Reporting summaries. Public demo deployments should also keep the demo
read-only guard enabled by leaving `DEMO_MODE=true`; mutating requests are
blocked so visitors cannot upload, delete, or reconfigure demo content.

The public dashboard uses the same demo payload to present a guided product
tour. The default view is a single user managing multiple domains, with
`dmarq.org` and `dmarq.com` visible immediately. Visitors can then zoom out to
SaaS, managed-service, ISP/reseller, or self-hosted deployment examples and
switch generated personas to inspect the account, workspace, billing, and
domain scope that each user would see.

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

Forensic report privacy controls are configured under **Settings** >
**Forensic Reports**.

| Setting | Description | Default | Example |
|---------|-------------|---------|---------|
| `forensics.redaction_mode` | Email-address redaction in forensic metadata: `balanced`, `domain_only`, or `strict` | `balanced` | `strict` |
| `forensics.redact_long_tokens_enabled` | Redact long opaque tokens in forensic metadata | `true` | `true` |

Alert history is stored in the database-backed `alert_history` table.
Notification and alert-rule configuration changes are stored in
`alert_configuration_audit` with secret values sanitized. Current retention is
indefinite; prune old resolved history and audit rows according to your
operational policy if long-term storage size matters.

### DNS Provider Integrations

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token for zone discovery, DNS inspection, and optional approved DNS writes | - | `your_cloudflare_api_token` |
| `CLOUDFLARE_ZONE_ID` | Optional default Cloudflare Zone ID | - | `your_cloudflare_zone_id` |
| `HETZNER_DNS_API_TOKEN` | Hetzner Console API token for read-only DNS zone import through `api.hetzner.cloud` | - | `your_hetzner_read_only_api_token` |
| `HETZNER_API_TOKEN` | Fallback Hetzner token name if you already inject generic Hetzner Cloud credentials | - | `your_hetzner_read_only_api_token` |

### Email Service and Webhook Integrations

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `POSTMARK_ACCOUNT_TOKEN` | Optional Postmark account token for read-only sender-domain discovery | - | `your_postmark_account_token` |
| `WEBHOOK_SECRET` | Required secret for inbound email worker webhooks | - | `openssl rand -hex 32` |

Cloudflare credentials can also be stored from **Settings**. The API token is
encrypted in the settings table and redacted when settings are read back. Leave
the Zone ID blank to discover every active zone visible to the token.

The integration exposes these operational routes:

| Route | Purpose |
| --- | --- |
| `GET /api/v1/domains/dns/import/cloudflare/preview` | Preview zones visible to the connected Cloudflare token without creating rows. |
| `POST /api/v1/domains/dns/import/cloudflare` | Import selected Cloudflare zones as monitored domains before reports arrive. |
| `GET /api/v1/domains/dns/import/hetzner/preview` | Preview zones visible to the configured Hetzner read-only token without creating rows. |
| `POST /api/v1/domains/dns/import/hetzner` | Import selected Hetzner DNS zones as monitored domains before reports arrive. |
| `GET /api/v1/domains/cloudflare/discover` | List available zones. |
| `POST /api/v1/domains/cloudflare/import` | Create monitored domain rows from zones. |
| `GET /api/v1/domains/{domain}/dns/cloudflare` | Inspect managed DNS records, return DMARC/SPF/DKIM suggestions, and record detected DNS changes. |
| `GET /api/v1/domains/{domain}/dns/history` | Review DNS record additions, modifications, and removals. |
| `GET /api/v1/domains/dns/providers` | List native and Lexicon-backed DNS write providers. |
| `POST /api/v1/domains/{domain}/dns/change-plan/apply` | Dry-run or explicitly apply one safe DNS change plan. |
| `GET /api/v1/domains/mail-services/import/providers` | List mail service providers that support sender-domain import. |
| `GET /api/v1/domains/mail-services/import/postmark/preview` | Preview Postmark sender domains and required DNS records without creating rows. |
| `POST /api/v1/domains/mail-services/import/postmark` | Import selected Postmark sender domains as monitored domains before reports arrive. |

Provider writes are opt-in at action time. Requests default to dry-run, and real
writes require `confirm=true` plus `dry_run=false`. Public demo mode rejects
provider writes even if credentials are configured. DNS change-plan responses
include the currently ready write providers, the provider DMARQ recommends from
nameserver detection when possible, and safety notes for apply-ready versus
manual-only changes. If a write request selects a provider that does not match
the detected provider, DMARQ rejects it unless the request explicitly sets
`allow_provider_mismatch=true`; applied overrides are captured in the workspace
audit log.

Postmark sender-domain discovery is read-only. DMARQ uses the Postmark account
token to list domains and sender signatures, then stores imported domains as
monitored domains so DNS linting, report import, and remediation guidance can
work before aggregate reports arrive. If Postmark exposes required DKIM or
return-path DNS records, DMARQ maps missing or conflicting records into the
normal DNS lint and change-plan responses. DMARQ does not modify Postmark or DNS
records in this workflow; DNS writes still require an explicit confirmed action
through a configured DNS provider connector.

Cloudflare is implemented natively and supports DNS-zone import, record
readback, dry-run, approved apply, verification, and rollback evidence. Hetzner
DNS supports read-only zone import via Hetzner Console API tokens. `GET
/api/v1/domains/dns/providers` exposes the broader connector registry so
operators can see which providers are ready, planned, or Lexicon-backed before
wiring credentials.

Tier 1 connector metadata currently covers:

- Cloudflare: API token, ready for zone import and approved DNS repair.
- Amazon Route 53: planned zone import/read path; Lexicon-backed write path
  where the runtime and credentials are available. Prefer IAM role assumption
  with external ID for hosted deployments.
- Akamai Edge DNS / FastDNS: planned EdgeGrid-backed DNS connector. Akamai EAA
  is an access/SSO frontdoor option and does not replace the Edge DNS connector.
- Hetzner DNS: read-only zone import using `HETZNER_DNS_API_TOKEN`;
  Lexicon-backed write path where the runtime and credentials are available.
- Linode DNS: planned zone import/read path; Lexicon-backed write path where
  the runtime and credentials are available.

Additional API-backed providers use DNS-Lexicon where the provider is available
in the runtime and its credentials are supplied through Lexicon-compatible
environment/configuration. Some providers require provider-specific Python
extras in a custom image.

### DNS Result Cache

DMARC, SPF, and DKIM DNS checks are cached in the database-backed `dns_cache`
table for 15 minutes per domain, DNS provider, and DKIM selector set. Domain DNS
API responses include whether the result came from cache and when it was
checked. Use `?refresh=true` on the domain DNS endpoint to bypass a fresh cache
entry for operational rechecks.

Cloudflare-managed DNS record snapshots and change events are stored in
`dns_record_snapshots` and `dns_record_changes`. They are updated whenever the
Cloudflare DNS analysis endpoint is called.

### AI Remediation Plans

DMARQ can generate deterministic remediation plans without a model. To enable
model-enhanced plans, set `ai.enabled=true`, choose `ai.provider=litellm`
or another LiteLLM-backed provider mode in Settings, and configure
`ai.model`. `ai.remote_base_url` can point at an OpenAI-compatible gateway when
needed.

Provider API keys are not stored in DMARQ settings. Inject `OPENAI_API_KEY`,
`LITELLM_API_KEY`, or provider-specific environment variables into the backend
process with your deployment secret manager. In hosted or GitOps deployments,
prefer 1Password, Kubernetes Secrets, or an equivalent injector so raw keys are
not copied into application settings.

Remote remediation plans are cached with `ai.remediation_cache_seconds`
(`86400` by default). Demo mode uses template-backed plans and a longer fixed
cache window.

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
