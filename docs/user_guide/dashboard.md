# DMARQ Dashboard

The DMARQ dashboard provides an at-a-glance view of your email authentication status and recent issues.

## Overview

When you log in to DMARQ, you'll be presented with the main dashboard that displays key metrics about your DMARC compliance and email authentication status. The dashboard is designed to give you immediate insights into your email security posture.

## Dashboard Components

### DMARC Compliance Rate

This section shows the percentage of emails passing DMARC (both SPF and/or DKIM aligned) out of total emails. A higher compliance rate indicates that your email authentication is working correctly.

- **Compliance Gauge**: Visual representation of your current compliance rate
- **Trend Line**: Chart showing compliance rate over time
- **Failure Count**: Number of messages that failed DMARC checks

### Policy Enforcement Trends

This section visualizes how your domain's DMARC policy and enforcement have evolved:

- **Timeline Chart**: Shows the proportion of emails that were quarantined/rejected over time
- **Policy Change Markers**: Indicators of when policy changed from `none → quarantine → reject`
- **Blocked Email Statistics**: Bar chart showing how many spoofed emails were blocked per month

### DNS Record Health Check

This panel lists the essential DNS records for email authentication:

- **SPF**: Status of your SPF TXT record
- **DKIM**: List of DKIM selectors in use from aggregate reports
- **DMARC**: Your domain's DMARC record and key tags (p= policy, rua, ruf, pct, etc.)
- **MX**: Status of your mail exchanger records
- **BIMI**: Status of your Brand Indicators for Message Identification record

Each record is displayed with its actual value and a status indicator.

### Alerts Summary

This section highlights recent alerts or important notices:

- **Recent Alerts**: List of the last several alerts with severity indicators
- **Quick Actions**: Options to resolve or dismiss alerts

### Forensic Report Drilldown

For detailed investigation of DMARC failures:

- **Filtering**: Filter reports by date, source IP, or sending source
- **Detailed View**: Examine specifics of each forensic report
- **Header Analysis**: Option to view full email headers for advanced troubleshooting

## Customizing the Dashboard

You can customize various aspects of the dashboard:

1. **Date Range**: Adjust the time period for displayed data
2. **View Preferences**: Choose which metrics are most important to you
3. **Refresh Rate**: Set how often data is automatically refreshed

## Next Steps

After reviewing your dashboard, you may want to:

- [Manage your domains](domains.md) to add or configure additional domains
- [Review detailed reports](reports.md) for deeper analysis
- [Configure settings](settings.md) to adjust notification preferences