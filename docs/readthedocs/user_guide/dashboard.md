# Dashboard

The DMARQ dashboard provides a comprehensive overview of your DMARC compliance status across all your domains. This centralized view allows you to quickly identify compliance issues and track improvements over time.

## Dashboard Overview

![Dashboard Overview](../assets/imgs/dashboard-screenshot.png)

The main dashboard is divided into several key sections:

1. **Domain Summary**: Shows a list of all monitored domains with their compliance rates
2. **Compliance Metrics**: Displays overall compliance statistics across all domains
3. **Recent Reports**: Shows the most recently received DMARC reports
4. **Email Volume Trends**: Charts email volume over time
5. **Authentication Results**: Breakdown of SPF, DKIM, and DMARC pass rates

## Key Metrics Explained

### Compliance Rate

The compliance rate represents the percentage of email messages that pass DMARC authentication. This is a key metric for understanding your email authentication health.

- **90-100%**: Excellent - Your email authentication is working well
- **70-89%**: Good - Some improvements may be needed
- **Below 70%**: Needs attention - Significant authentication issues exist

### Email Volume

The email volume chart shows the number of emails sent using your domains over time. This helps you identify:

- Unusual spikes that might indicate spam or phishing attempts
- Normal sending patterns for your domains
- The impact of email marketing campaigns or other planned sending activities

### Authentication Breakdown

This section provides detailed insights into how emails are passing or failing authentication:

- **SPF Results**: Shows pass/fail rates for Sender Policy Framework checks
- **DKIM Results**: Shows pass/fail rates for DomainKeys Identified Mail signatures
- **DMARC Results**: Shows overall pass/fail rates based on your DMARC policy

## Filtering and Customization

The dashboard supports various filtering options to help you focus on specific data:

1. **Date Range**: Filter data by a specific time period
2. **Domain Filter**: Focus on specific domains
3. **Compliance Status**: Filter to show only passing or failing results

To customize your view:

1. Click the **Filter** button in the top-right corner
2. Select your desired filters
3. Click **Apply Filters** to update the dashboard view

## Dashboard Widgets

### Domain Summary Widget

The domain summary widget provides at-a-glance information about each domain:

| Column | Description |
|--------|-------------|
| Domain | The domain name |
| Compliance | Current compliance rate percentage |
| Trend | Weekly compliance trend (up/down arrow) |
| Policy | Current DMARC policy (none/quarantine/reject) |
| Reports | Number of reports received |

### Compliance Chart

The compliance chart visualizes your DMARC compliance over time:

- **Blue Line**: Shows your actual compliance rate
- **Red Dashed Line**: Shows the recommended 98% threshold for enforcement
- **Green Zone**: Indicates when compliance is high enough for stricter policies

## Actionable Insights

The dashboard is designed to provide actionable insights to improve your email authentication:

1. **Quick Actions**: Each domain has quick action buttons to:
   - View detailed reports
   - Check DNS configuration
   - Update DMARC policy

2. **Compliance Recommendations**: The system provides automated recommendations based on your compliance levels:
   - When to move from p=none to p=quarantine
   - When to move from p=quarantine to p=reject
   - Specific sending sources that need configuration

## Exporting Data

To export dashboard data for reports or further analysis:

1. Click the **Export** button in the top-right corner
2. Choose your preferred format (CSV, PDF, or PNG)
3. Select the data range and metrics to include
4. Click **Generate Export** to download your data

## Related Documentation

- [Managing Domains](domains.md) - Learn how to add and configure domains
- [DMARC Reports](reports.md) - Detailed information about DMARC reports
- [DMARC Policies](../reference/policies.md) - Understanding DMARC policies