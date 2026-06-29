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
   - MTA-STS TXT and HTTPS policy validation
   - MX record confirmation
   - BIMI record validation (if applicable)

### Posture Dashboard

The domain detail page starts with an evidence-first posture dashboard. It
summarizes coverage for DMARC, SPF, DKIM, MTA-STS, and BIMI, assigns a simple
posture score, and shows each recommendation with links back to the DNS record,
report trend, sending-source table, or posture evidence that triggered it.

The same surface includes a **What Changed** panel when provider-backed DNS
change tracking has observed additions, edits, or removals. Those summaries are
designed for drift review: operators can see the previous and current values
without reading logs.

Operator playbooks sit beside the recommendations. They are short remediation
checklists for common gaps such as missing SPF, missing DKIM, policy enforcement
readiness, MTA-STS setup, or BIMI prerequisites.

### DNS Guidance

The domain detail page also shows typed DNS lint findings next to suggested
target records. DMARQ checks DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and BIMI
readiness, then exposes the same guidance through the single-domain lint API,
bulk lint API, and CSV export for managed-domain reviews.

Each lint finding includes a short remediation checklist. DKIM findings now
distinguish missing observed selectors, broken selector CNAME targets, short
RSA keys, and selectors that still resolve but have no recent report traffic.
Optional AI remediation plans can turn the same redacted DNS/report context
into a longer step-by-step plan through LiteLLM/OpenAI-compatible providers;
demo mode keeps these plans template-backed and heavily cached.

The same section also shows a read-only proposed DNS change plan when findings
are actionable. These plans include the record name, type, proposed value,
captured current values when available, risk notes, rollback guidance, and
expected health impact. They are copy/paste aids for an operator; DMARQ does
not apply DNS changes automatically.

### MTA-STS Posture

The domain detail page checks `_mta-sts.<domain>` and fetches the policy from `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

DMARQ marks the check healthy when the TXT record contains `v=STSv1` with an `id`, the HTTPS policy is reachable, and the policy includes `version`, `mode`, `mx`, and `max_age`. Findings include the DNS record, policy URL, mode, MX patterns, and actionable guidance for missing records, fetch failures, invalid policies, or non-enforcing `testing`/`none` modes.

When `_mta-sts.<domain>` exists but `mta-sts.<domain>` does not resolve or the HTTPS policy cannot be fetched, DMARQ treats this as a policy-hosting problem rather than a missing TXT record. Keep the TXT record if its `id` is current, publish DNS for `mta-sts.<domain>`, serve the policy at `/.well-known/mta-sts.txt`, and rotate the TXT `id` after changing the policy so receivers refetch it.

MTA-STS posture uses the same cached DNS refresh behavior as the existing DNS health checks. Use the DNS refresh action when you publish or update a policy and need DMARQ to re-check immediately.

### BIMI Readiness

The domain detail page checks the default BIMI selector at
`default._bimi.<domain>`.

DMARQ validates that the BIMI TXT record starts with `v=BIMI1`, includes an
HTTPS `l=` SVG logo URL, and uses HTTPS for the optional `a=` certificate URL.
The readiness guidance also checks whether DMARC is ready for BIMI: the domain
must use `p=quarantine` or `p=reject`, `pct` must be `100` or omitted, and any
published `sp=` subdomain policy must also enforce.

BIMI posture is read-only. Findings link back to the BIMI TXT record, logo URL,
certificate URL, and DMARC policy evidence so operators can see which
prerequisite is blocking readiness.

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
