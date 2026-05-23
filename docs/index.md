# DMARQ Documentation

Welcome to the official documentation for DMARQ - a comprehensive DMARC reporting and analysis tool.

DMARQ helps organizations monitor their email authentication status, analyze DMARC reports, and improve email deliverability and security.

## What is DMARQ?

DMARQ is a full-stack DMARC monitoring platform designed to help organizations track and improve their email authentication. It processes DMARC reports (aggregate and forensic) and presents compliance insights via a user-friendly dashboard.

## Key Features

- **DMARC Report Processing**: Automatically collect and parse DMARC aggregate and forensic reports
- **Interactive Dashboard**: Visualize compliance rates and authentication trends
- **DNS Health Checks**: Verify your email authentication records (SPF, DKIM, DMARC)
- **Mailbox Integrations**: Automatically fetch reports from IMAP, Gmail, and Microsoft 365 inboxes
- **Alerting**: Get notified about important authentication issues
- **Easy Setup**: Web-based configuration wizard for quick onboarding

## Getting Started

To get started with DMARQ, please see the [Getting Started](user_guide/getting_started.md) guide.

For installation instructions, check the [Docker Setup](deployment/docker.md) or [Manual Installation](deployment/manual.md) guides. Operators should use the [Operator Runbook](deployment/operations.md) for deployment modes, verification, upgrades, and rollback, and the [Troubleshooting Playbooks](deployment/troubleshooting.md) for ingestion, authentication, DNS, database, and notification failures. For production secrets, use [Secret Handling with 1Password](deployment/secrets.md). For database operations, use [Database Backup and Restore](deployment/backups.md). For upgrades, use the [Release Checklist](deployment/release-checklist.md).

For Microsoft 365 setup, see [Microsoft 365 Mail Sources](user_guide/microsoft365.md).

For SMTP TLS reporting imports and privacy controls, see [TLS Reports](user_guide/tls_reports.md).

For aggregate-report parser support, known edge cases, and fixture guidance, see [DMARC Aggregate Format Compatibility](reference/dmarc-compatibility.md).

For opt-in AI summaries and read-only MCP automation, see [AI and MCP Automation](reference/ai-mcp-automation.md).
