# DMARQ Dashboard

The DMARQ dashboard provides an at-a-glance view of your email authentication status and recent issues.

## Overview

When you log in to DMARQ, you'll be presented with the main dashboard that displays key metrics about your DMARC compliance and email authentication status. The dashboard is designed to give you immediate insight into the report-and-DNS loop DMARQ focuses on: who sent mail, whether it aligned, which DNS records are healthy, and what should be fixed next.

## Dashboard Components

### DMARC Compliance Rate

This section shows the percentage of emails passing DMARC (SPF or DKIM aligned) out of total emails. A higher compliance rate indicates that your email authentication is working correctly.

- **Trend Line**: Chart showing compliance rate over time
- **Domain Count**: Number of monitored domains contributing reports
- **Email and Report Counts**: Aggregate message and report volume for the visible period

### Policy Enforcement Trends

The enforcement panel summarizes how many monitored domains currently enforce a
policy of `quarantine` or `reject`. Domains still using `p=none` are treated as
monitoring-only so you can see whether authentication issues are fixed before
moving toward enforcement.

- **Enforced**: All monitored domains are enforcing DMARC
- **Mixed**: Some domains enforce while others remain in monitoring
- **Monitoring**: No monitored domains are enforcing yet

### DNS Record Health Check

This panel lists the essential DNS signals for email authentication:

- **SPF**: Status of your SPF TXT record
- **DKIM**: List of DKIM selectors in use from aggregate reports
- **DMARC**: Your domain's DMARC record and key tags (p= policy, rua, ruf, pct, etc.)
- **Policy**: Whether at least one monitored domain is enforcing DMARC

The domain detail page contains the deeper DNS posture, linting output,
recommendations, and evidence behind these summary checks.

### Volume and Sending Sources

The volume chart compares compliant and non-compliant messages over the recent
reporting window. The top sending sources panel ranks the largest source IPs and
shows which ones account for the most observed volume.

Use these two panels together: a traffic spike from a known compliant sender is
usually routine, while a spike from an unknown or failing sender needs review.

### Forensic Report Drilldown

For detailed investigation of DMARC failures, the dashboard links into redacted
failure samples:

- **Filtering**: Filter reports by date, source IP, or sending source
- **Detailed View**: Examine metadata and authentication results for each sample
- **Grouped Analysis**: Review repeated failure patterns without storing message bodies

### What Changed

The change summary highlights new sources, compliance drops, and policy gaps
detected in the current reporting window. These entries are designed to point to
the next DNS or sender-configuration action rather than act as a general alert
feed.

### Demo Mode

When `DEMO_MODE=true`, the dashboard uses generated rolling data for
`dmarq.org` and `dmarq.com`. The demo data fills the aggregate dashboard,
forensic report summaries, SMTP TLS report summaries, DNS posture, and exports.
It intentionally includes healthy senders, partially aligned senders, and a few
misconfigurations so each dashboard panel has realistic content.

## Customizing the Dashboard

You can customize various aspects of the dashboard:

1. **Date Range**: Adjust the time period for API-backed trend data
2. **Domain Detail Views**: Drill into one domain for source, DNS, and report evidence
3. **Settings**: Configure retention, forensic redaction, notifications, and integrations

## Next Steps

After reviewing your dashboard, you may want to:

- [Manage your domains](domains.md) to add or configure additional domains
- [Review detailed reports](reports.md) for deeper analysis
- [Configure settings](settings.md) to adjust notification preferences
