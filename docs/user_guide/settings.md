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

### Email Notifications

Configure how you receive email notifications:

1. Navigate to **Settings** > **Notifications** > **Email**
2. Configure the following:
   - **Email Address**: Where notifications will be sent
   - **Notification Frequency**: Immediate, daily digest, or weekly summary
   - **Notification Types**: Select which events trigger notifications

### Alert Thresholds

Set thresholds for when alerts are triggered:

1. Navigate to **Settings** > **Notifications** > **Thresholds**
2. Configure thresholds for:
   - **Compliance Rate Drop**: Alert when compliance falls below a threshold
   - **New Sending Sources**: Alert when new IPs/servers send email as your domain
   - **Authentication Failures**: Alert when failures exceed a certain number
   - **Report Processing Issues**: Alert on report processing errors

### Integration Notifications

If you've enabled additional notification channels through Apprise:

1. Navigate to **Settings** > **Notifications** > **Integrations**
2. Configure each integration separately (Slack, Teams, Discord, etc.)
3. Set which notification types go to each channel

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