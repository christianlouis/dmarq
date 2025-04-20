# Managing Domains

This guide explains how to add, configure, and manage domains in DMARQ.

## Adding a New Domain

To add a new domain for DMARC monitoring in DMARQ:

1. Navigate to **Domains** in the main navigation
2. Click the **Add Domain** button
3. Enter your domain name (e.g., `example.com`)
4. Click **Verify** to ensure the domain is valid
5. Click **Add Domain** to confirm

DMARQ will add the domain to your account and begin monitoring for DMARC reports related to this domain.

## Domain Settings

For each domain, you can configure several settings:

### DMARC Policy Configuration

DMARQ allows you to view and optionally manage your DMARC policy:

- **Current Policy**: View your active DMARC policy (none, quarantine, reject)
- **Policy History**: Track changes to your DMARC policy over time
- **Policy Recommendations**: Get suggestions for improving your DMARC implementation based on your compliance rate

### DNS Record Management

If you've enabled Cloudflare integration, you can manage your email authentication DNS records directly from DMARQ:

- **View Current Records**: See all SPF, DKIM, DMARC, and BIMI records
- **Update Records**: Modify existing records as your email infrastructure changes
- **Add New Records**: Create new records like additional DKIM selectors

To update a record:

1. Find the record you want to change in the DNS Records section
2. Click **Edit**
3. Make your changes in the record editor
4. Click **Save** to apply the changes to your DNS

### Report Delivery Settings

Configure where and how DMARC reports are delivered:

- **RUA Email**: The email address receiving aggregate reports
- **RUF Email**: The email address receiving forensic reports
- **Report Frequency**: How often you want to receive reports

## Domain Health Check

DMARQ provides a health check feature for each domain:

1. Navigate to the domain details page
2. Click **Run Health Check** to analyze your domain's email authentication setup
3. Review the results, which include:
   - SPF record validation
   - DKIM selector verification
   - DMARC record syntax check
   - MX record confirmation
   - BIMI record validation (if applicable)

## Domain Groups

If you manage multiple domains, you can organize them into groups:

1. Go to the **Domains** page
2. Click **Manage Groups**
3. Create a new group and give it a name
4. Drag and drop domains into the group

Groups allow you to:
- View aggregate statistics across multiple related domains
- Apply settings changes to multiple domains at once
- Organize domains by business unit, client, or purpose

## Removing a Domain

To remove a domain from DMARQ:

1. Navigate to the **Domains** page
2. Find the domain you wish to remove
3. Click the **Options** menu (three dots)
4. Select **Remove Domain**
5. Confirm the removal

Note that removing a domain will delete all stored DMARC reports for that domain.