# Settings

This guide covers the various settings and configuration options available in DMARQ.

## General Settings

### Account and Access Milestone

Administrators see an **Account and Access Milestone** card at the top of
Settings. It summarizes the #12 account/auth foundation in product terms:
authentication modes, workspace RBAC, membership management, workspace
switching, onboarding, billing ownership, provider lifecycle, plan limits,
enterprise provisioning, and audited support access.

The card separates implementation state from deployment setup. **Open slices**
should be zero when the product foundation is complete. **Setup gates** identify
environment-specific configuration still needed before using a mode, such as
Stripe for direct billing, provider machine tokens for ISP/OEM integrations, or
SCIM/MFA controls for enterprise tenants.

### User Profile

To manage your user profile:

1. Click on your username in the top-right corner
2. Select **Profile Settings**
3. Here you can:
   - Update your name and email address
   - Change your password
   - Set your timezone and date format preferences
   - Configure UI theme preferences (light/dark mode)

### System Settings

System-wide settings are available to administrators:

1. Navigate to **Settings** > **System**
2. Configure the following options:
   - **Instance Name**: Custom name for your DMARQ instance
   - **Logo**: Upload a custom logo for branding
   - **Session Timeout**: How long before inactive users are logged out
   - **Default Language**: Set the default interface language

## Notification Settings

### Apprise Notifications

Configure where DMARQ sends notifications:

1. Navigate to **Settings**.
2. Open **Notifications**.
3. Enable notifications.
4. Add one Apprise target URL per line.
5. Save and use **Send Test** to verify delivery.

Target URLs are encrypted in the database and redacted after saving so
credentials are not exposed through the settings API or page reloads.

The notification page also includes a minimum send interval. This cooldown
limits repeated outbound notifications if several alert checks run close
together. Email addresses in notification titles and bodies are redacted by
default before messages are sent.

### Alert Thresholds

Set alert rules and thresholds in **Settings** > **Notifications**:

- **New Sending Sources**: newly observed IPs or servers sending as a monitored domain
- **Compliance Drops**: recent compliance-rate drops beyond the configured point threshold
- **High DMARC Failures**: failed messages over the daily threshold
- **Missing Reports**: monitored domains without reports for the configured number of days

Use **Check Alerts** to preview the current alert count, or **Send Alerts Now** to
send the current alert summary through the configured Apprise targets.

### Summary Notifications

Configure daily or weekly summaries in **Settings** > **Notifications**:

- **Daily Summary**: sends one summary after the configured UTC hour each day
- **Weekly Summary**: sends one summary on the configured UTC weekday
- **Preview Summary**: shows message volume, report count, and active alert count
- **Send Summary Now**: sends the selected daily or weekly summary immediately

### Alert History

Alert history appears in **Settings** > **Notifications** after alerts have been
evaluated or sent. Each row shows whether the alert is active or resolved, how
many times it has been observed, and the latest alert detail.

### Configuration Audit

Notification and alert-rule setting changes appear in **Settings** >
**Notifications**. Secret values are shown only as redacted markers in this
audit trail.

### Integration Notifications

Apprise supports email, Slack, Teams, Discord, generic webhooks, and many other
targets through the same notification field. Add each destination on a separate
line.

## Webhooks

Use **Settings** > **Webhooks** when another system needs structured DMARQ
events instead of human-readable notifications.

1. Add a name and HTTPS endpoint URL.
2. Choose all events or one event type.
3. Save the endpoint.
4. Use **Test** to send a signed test event.
5. Inspect **Recent Deliveries** to see status, attempts, response codes, and errors.

DMARQ signs each delivery with `X-DMARQ-Signature` and includes
`X-DMARQ-Idempotency-Key` so receivers can reject replays and deduplicate
retries. Endpoint URLs and signing secrets are encrypted at rest.

For SIEM pipelines, DMARQ also exposes a versioned template bundle at
`/api/v1/integrations/siem/templates`. It includes the stable
`dmarq.siem.event.v1` event schema, Splunk HEC, Elastic ECS, and Microsoft
Sentinel examples, plus redaction guidance for sensitive fields.

For ticketing and chatops workflows, use
`/api/v1/integrations/ticketing-chatops/templates`. It includes event mappings,
Jira and GitHub issue templates, Slack and Microsoft Teams message templates,
dedupe keys, and recommended ownership/noise-control rules.

## DNS Provider Imports

Use DNS provider imports when you want DMARQ to monitor domains that exist at
your DNS provider even if no DMARC reports have arrived yet.

- Cloudflare uses a scoped API token with zone/DNS read access.
- Amazon Route 53 uses the server-side AWS credential chain, a configured AWS
  profile, or a role ARN plus external ID.
- Hetzner DNS uses a read-only DNS API token.
- Linode DNS uses a Domains read-only personal access token.
- Akamai Edge DNS/FastDNS uses EdgeGrid credentials through an `.edgerc`
  section selected by `AKAMAI_EDGERC_SECTION` or the `AKAMAI_*` environment
  variables.

The import flow only creates monitored domains in DMARQ. It does not change DNS
records. DNS repair remains a separate preview-and-approve action.

## API Access

DMARQ provides an API for integration with other systems:

1. Navigate to **Settings** > **API Access**
2. Here you can:
   - Generate API keys
   - View and revoke existing keys
   - Set permissions and access levels for each key
   - View API usage statistics

## Integrations

### Cloudflare Integration

If you use Cloudflare for DNS management:

1. Navigate to **Settings** > **Cloudflare Integration**
2. Configure:
   - **API Token**: Your Cloudflare API token
   - **Zone ID**: Optional Cloudflare Zone ID for a single domain
3. Use **Discover** to preview DNS zones visible to the token.
4. Use **Import New** to create monitored domain rows for selected/new zones,
   even before DMARQ has received reports for those domains.

For inspection only, the token needs zone and DNS read access. To apply DNS
change plans from a domain detail page, the token also needs Cloudflare DNS
write permission for the affected zone. DMARQ uses the token to fetch managed
DNS records, detect missing or malformed DMARC/SPF/DKIM entries, record DNS
additions, modifications, or removals over time, and apply explicitly approved
TXT/CNAME remediation plans.

The DNS-zone import workflow is provider-shaped. Cloudflare, Route 53, Hetzner
DNS, Linode DNS, and Akamai Edge DNS/FastDNS can import zones or domains before
reports arrive. Hetzner import uses a read-only Hetzner Console API token from
`HETZNER_DNS_API_TOKEN` (or the fallback `HETZNER_API_TOKEN`). Linode import
uses `LINODE_API_TOKEN` (or `LINODE_TOKEN`). Akamai import uses EdgeGrid
credentials from `AKAMAI_EDGERC_PATH` plus optional `AKAMAI_EDGERC_SECTION`
(defaulting to `default`) or the direct `AKAMAI_HOST`, `AKAMAI_CLIENT_TOKEN`,
`AKAMAI_CLIENT_SECRET`, and `AKAMAI_ACCESS_TOKEN` variables.

DMARQ never performs background DNS edits. A write-capable token only enables
operator-approved actions from the DNS change plan UI, and each applied change
is recorded in the workspace audit log.

### Mail Service Sender Imports

If you use Postmark to send mail:

1. Navigate to **Settings** > **Mail Service Imports**.
2. Add a Postmark account token.
3. Use **Discover** to preview sender domains and their verification state.
4. Use **Import New** to create monitored domain rows before DMARQ has received
   reports for those domains.

Imported domains appear in the normal domain list and detail pages. The detail
page shows that the domain came from Postmark, while DNS linting and
remediation guidance stay inside DMARQ. When the Postmark token is available,
DMARQ also maps Postmark's required DKIM and return-path records into the
domain DNS lint and change-plan views. Those plans can be reviewed and, where a
DNS provider connector is configured, previewed through the normal safe DNS
write flow. This workflow is read-only against Postmark and does not change DNS
records without explicit operator approval.

### Other Integrations

DMARQ supports additional integrations:

1. Navigate to **Settings** > **Integrations**
2. Select the integration you wish to configure
3. Follow the specific setup instructions for that integration

## Backup and Data Management

### Data Retention

Configure how long DMARQ keeps data:

1. Navigate to **Settings** > **Data Management**
2. Configure retention periods for:
   - **Aggregate Reports**: How long to keep aggregate report data
   - **Forensic Reports**: How long to keep forensic report data
   - **Activity Logs**: How long to keep system activity logs

### Backup Configuration

Set up automated backups:

1. Navigate to **Settings** > **Data Management** > **Backups**
2. Configure:
   - **Backup Schedule**: How often to create backups
   - **Backup Location**: Where to store backups (local, S3, etc.)
   - **Retention**: How many backups to keep

### Data Export

Configure scheduled data exports:

1. Navigate to **Settings** > **Data Management** > **Exports**
2. Configure scheduled exports to CSV or JSON format
3. Set delivery methods (download, email, FTP, etc.)

## System Logs

View and manage system logs:

1. Navigate to **Settings** > **Logs**
2. Filter logs by:
   - **Log Level**: Error, Warning, Info, Debug
   - **Component**: API, Parser, IMAP, Authentication, etc.
   - **Time Range**: When the logs were generated
3. Download logs for external analysis if needed

## Advanced Settings

Advanced configuration options (administrators only):

1. Navigate to **Settings** > **Advanced**
2. Configure:
   - **Database Connection**: Change database settings
   - **Worker Configuration**: Configure background processing settings
   - **Caching**: Adjust cache settings for performance
   - **Debug Mode**: Enable additional logging for troubleshooting
