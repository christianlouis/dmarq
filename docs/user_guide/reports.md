# DMARC Reports

This guide explains how to work with DMARC reports in DMARQ.

## Types of DMARC Reports

DMARQ supports two types of DMARC reports:

### Aggregate Reports (RUA)

Aggregate reports provide statistical data about email authentication results. These reports:
- Are typically sent daily by email providers
- Contain summaries of email volumes and authentication results
- Do not include the content of individual emails
- Are XML files, often compressed

### Forensic Reports (RUF)

Forensic reports provide information about individual messages that failed DMARC authentication:
- Include details about specific authentication failures
- May contain email headers and sometimes partial content
- Help diagnose specific delivery issues
- Not all providers send forensic reports due to privacy concerns

## Viewing Reports

### Aggregate Reports List

To view your aggregate reports:

1. Navigate to **Reports** in the main navigation
2. Select the **Aggregate** tab
3. Use filters to narrow down reports by:
   - Date range
   - Source organization (e.g., Google, Yahoo, Microsoft)
   - Domain (if monitoring multiple domains)
   - Policy applied (none, quarantine, reject)

The report list shows:
- Report date
- Sending organization
- Number of messages
- Pass/fail statistics
- DMARC policy applied

### Aggregate Report Details

To view details of a specific aggregate report:

1. Click on any report in the list
2. Review the detailed information, including:
   - Source IP addresses
   - Message counts
   - SPF and DKIM alignment results
   - Sending sources (by domain and IP)
   - Pass/fail rates by source

### Forensic Reports

To view forensic reports (when available):

1. Navigate to **Reports** in the main navigation
2. Select the **Forensic** tab
3. Use filters similar to aggregate reports
4. Click on any report to view details about the specific authentication failure

## Understanding Report Data

### Key Metrics

Important metrics to look for in DMARC reports:

- **SPF Alignment**: Whether the domain in the From header matches the domain that passed SPF
- **DKIM Alignment**: Whether the domain in the From header matches the domain in the DKIM signature
- **Source IPs**: The IP addresses sending email on behalf of your domain
- **Volume Trends**: Changes in email volume over time
- **Failure Patterns**: Recurring patterns in authentication failures

### Report Visualization

DMARQ provides several visualizations to help understand report data:

- **Source Distribution**: Chart showing email volume by sending source
- **Authentication Results**: Breakdown of SPF, DKIM, and alignment results
- **Geographic Distribution**: Map showing the origin of emails by country
- **Timeline View**: Changes in email authentication over time

## Importing Reports Manually

If you need to import DMARC reports manually:

1. Navigate to **Reports** in the main navigation
2. Click **Upload Report**
3. Select the report file from your computer (XML, ZIP, or GZ format)
4. Click **Upload** to process the report

DMARQ will parse the report and add it to your database.

## Exporting Report Data

To export report data for external analysis:

1. Navigate to the report list or detail view
2. Click **Export**
3. Choose your preferred format:
   - CSV for spreadsheet analysis
   - JSON for programmatic processing
   - PDF for sharing with stakeholders
4. Select the data points to include
5. Click **Generate Export** to download the file