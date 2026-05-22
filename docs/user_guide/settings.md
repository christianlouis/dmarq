# Settings

This guide covers the various settings and configuration options available in DMARQ.

## General Settings

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

1. Navigate to **Settings** > **Integrations** > **Cloudflare**
2. Configure:
   - **API Token**: Your Cloudflare API token
   - **Zone ID**: The Cloudflare Zone ID for your domain
   - **Permissions**: What actions DMARQ can take on your DNS records

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
