# DMARQ Documentation

Welcome to the official documentation for DMARQ - a DMARC reporting and domain
mail-health tool.

DMARQ helps organizations monitor email authentication, analyze DMARC reports,
understand DNS and sender posture, and improve mail-sending health without
giving up control of their data.

## What is DMARQ?

DMARQ is a full-stack DMARC monitoring platform designed to help organizations
track and improve email authentication. It processes DMARC reports, presents
compliance insights, and is growing into a human-in-the-loop remediation
assistant: automatic detection and guidance, operator-approved repair.

The product direction is intentionally practical:

- show which domains and senders are healthy,
- explain what is broken and why it matters,
- prepare safe fixes for DNS and provider configuration,
- support both commercial providers and self-hosted mail infrastructure,
- surface sender reputation and blacklist risks, and
- provide guidance in language operators can act on.

## Key Features

- **DMARC Report Processing**: Automatically collect and parse DMARC aggregate and forensic reports
- **Interactive Dashboard**: Visualize compliance rates and authentication trends
- **DNS Health Checks**: Verify your email authentication records (SPF, DKIM, DMARC)
- **Mailbox Integrations**: Automatically fetch reports from IMAP, Gmail, and Microsoft 365 inboxes
- **Alerting**: Get notified about important authentication issues
- **Easy Setup**: Web-based configuration wizard for quick onboarding
- **Human-in-the-loop Remediation**: Detect automatically, explain clearly, apply only after approval
- **Roadmap**: Health scoring, sender reputation, provider imports, direct intake workers, and localized guidance

## Getting Started

To get started with DMARQ, please see the [Getting Started](user_guide/getting_started.md) guide.

For installation instructions, check the [Docker Setup](deployment/docker.md) or [Manual Installation](deployment/manual.md) guides. Operators should use the [Operator Runbook](deployment/operations.md) for deployment modes, verification, upgrades, and rollback, and the [Troubleshooting Playbooks](deployment/troubleshooting.md) for ingestion, authentication, DNS, database, and notification failures. For production secrets, use [Secret Handling with 1Password](deployment/secrets.md). For database operations, use [Database Backup and Restore](deployment/backups.md). For upgrades, use the [Release Checklist](deployment/release-checklist.md).

For Microsoft 365 setup, see [Microsoft 365 Mail Sources](user_guide/microsoft365.md).
For connector implementation boundaries, see the
[Microsoft 365 Graph Connector Contract](reference/microsoft365-graph-connector.md).

SMTP TLS reporting imports and privacy controls are covered in [TLS Reports](user_guide/tls_reports.md).

Safe migration from another DMARC platform is covered in
[Migrating from another DMARC platform](user_guide/migration.md).

Aggregate-report parser support, known edge cases, and fixture guidance are documented in [DMARC Aggregate Format Compatibility](reference/dmarc-compatibility.md).

Opt-in AI summaries and read-only MCP automation are covered in [AI and MCP Automation](reference/ai-mcp-automation.md).

The current product direction across self-hosted, hosted SaaS, ISP/OEM,
provider integrations, billing, localization, and mail-health automation is
captured in the [Product Roadmap](development/roadmap.md).

ISP, MSP, and hosting-control-panel lifecycle integrations are documented in
[Provider Integrations](reference/provider-integrations.md).
