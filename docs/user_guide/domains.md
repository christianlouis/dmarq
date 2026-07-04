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

- **Default RUA Email**: The central workspace mailbox that should receive
  aggregate reports, such as `dmarc-reports@example.net`
- **Domain RUA Override**: An optional per-domain mailbox when one domain needs
  a different aggregate-report destination
- **RUF Email**: The email address receiving forensic reports
- **Report Frequency**: How often you want to receive reports

DNS guidance and the mail authentication wizard use the domain override first,
then the workspace default, and only fall back to `dmarc@<domain>` when neither
is configured.

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

The dashboard also includes a **Remediation Queue** that merges health-score
actions and DNS lint change plans into one prioritized list. Items are marked
as approval-ready, manual, or investigate-only, and include the evidence,
blast radius, prerequisites, and expected health-score impact. Approval-ready
DNS items link back to the DNS change-plan review area; they still require an
operator preview and explicit approval before any provider write is sent.
Each item also shows a notification profile such as approval required, action
required, investigation required, or summary only. These labels explain how
DMARQ would route the item into alerting or ticketing workflows; viewing the
queue does not send a notification. API clients also receive a sanitized
`payload_preview` for each item so ticketing, webhook, and chatops routes can
be tested before delivery automation is enabled.

The same notification block includes a dispatch readiness preview. It explains
whether remediation dispatch is enabled, whether the event is configured, if a
previewed or acknowledged audit marker is still required, and whether an
enabled webhook endpoint is subscribed to the event. This is a readiness check
only; DMARQ does not enqueue webhook deliveries or send notifications from the
queue view. The queue header summarizes how many items are ready to notify,
blocked, awaiting acknowledgement, or covered by webhook routes so operators can
see the next action without opening every item.

After a remediation notification is previewed or acknowledged, an operator can
explicitly enqueue the notification through the dispatch API with
`confirm=true`. Dispatch currently means "create persisted webhook delivery
rows for configured endpoints"; it does not send from the queue view and does
not apply DNS changes. The delivery history can then be inspected through the
webhook delivery state.

### Source Intelligence

The domain detail page groups sending sources into regions, reverse DNS
hostnames, ASNs, BGP prefixes, registries, and likely network operators when
that evidence is available from reports or cached sender-network enrichment.
It also flags unusual source behavior, including new senders, new regions,
source volume spikes, and increased SPF/DKIM alignment failures.

Each sending source also shows when DMARQ first and last observed mail from
that host, how many distinct report days include the source, and a compact
recent volume history. Use this to separate current infrastructure from stale
legacy traffic: a source that last sent yesterday deserves different treatment
than a one-off sender that appeared three months ago.

Use these findings before editing DNS. A new source is not automatically a
trusted sender; confirm the service owner first, then update SPF or DKIM only
when the source is legitimate.

Reputation evidence is shown separately from network ownership. ASN and BGP
prefix data explains who appears to operate the sending infrastructure; optional
reputation feeds can add DNSBL, blocklist, or abuse-confidence evidence when an
administrator has enabled those providers. A clean Geo/ASN lookup is not the
same thing as a clean reputation result.

Known sender matching recognizes common provider evidence from DMARC reports,
reverse DNS, and authentication domains. The built-in profiles include Google
Workspace, Microsoft 365, Amazon SES, Postmark, SendGrid, Mailgun, SparkPost,
Mailjet, Mailchimp, Brevo, Klaviyo, HubSpot, Constant Contact, Zendesk, Stripe,
Zoho, and Salesforce. Treat a match as an investigation shortcut rather than
proof of ownership: always confirm the service in your own provider account
before authorizing DNS changes.

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

The same section also shows a proposed DNS change plan when findings are
actionable. These plans include the record name, type, proposed value, captured
current values when available, risk notes, rollback guidance, and expected
health impact. Operators can copy/paste the records manually, preview a
provider mutation, or apply safe TXT/CNAME changes through a configured DNS
provider after explicit browser confirmation.

When DMARQ can detect the authoritative DNS provider from nameservers and a
matching connector is available, the change-plan section highlights the
recommended provider. Each plan also includes safety notes that explain why the
plan is apply-ready or why it remains manual-only.

The Apply button uses the provider preview as the final confirmation source. If
there is no current preview for the selected plan, DMARQ prepares one first and
then asks the operator to confirm the exact provider, operation, record name,
record type, TTL, previous value, proposed value, and rollback summary before a
live provider write is submitted.

Remediation notification previews can also be marked as previewed,
acknowledged, snoozed, resolved, or rejected through the API. These markers are
written to the workspace audit log with the sanitized notification preview, but
they do not send notifications, enqueue webhooks, or touch DNS. This gives
operators an auditable lifecycle before any automated remediation loop is
enabled.

Dispatch remains opt-in through notification settings:
`notifications.remediation_dispatch_enabled`,
`notifications.remediation_dispatch_channel`,
`notifications.remediation_dispatch_require_acknowledgement`, and
`notifications.remediation_dispatch_events`. The current supported channel is
`webhook`; enabling the settings only makes queue items dispatch-eligible. A
separate dispatch request with `confirm=true` is still required to create
delivery rows.

The domain detail page shows recent operator history on each remediation
notification, including preview/acknowledgement markers, snoozes or rejections,
and confirmed dispatch enqueue events. This keeps the recommended next action
next to the evidence: an operator can see whether a recommendation is still
waiting for review, already acknowledged, or already queued for the configured
webhook route. The timeline is read-only and highlights that remediation
notification handling does not perform DNS writes.

If an operator selects a different provider than the nameserver-detected
provider, DMARQ blocks the preview/apply request by default. The mismatch can be
overridden only with an explicit confirmation that the selected provider
actually manages the zone; that override is captured in the workspace audit log
when a write is applied.

After a confirmed provider write, DMARQ reads the record back from the provider
API and shows the verification result. Do not treat the issue as repaired until
the response says the expected value was verified. If verification fails, keep
the change under review and check provider state, propagation, and whether a
different authoritative DNS provider manages the zone.

On the public demo, the same flow is simulated. The confirmation, apply result,
verification message, audit evidence, and rollback guidance are shown, but
DMARQ does not contact a DNS provider or modify live DNS records.

Provider previews and apply responses also include rollback guidance. For
updates, DMARQ shows the previous provider value when it was captured; for
creates, it explains how to remove the created record. Rollback is deliberately
manual-review only so an operator can confirm no current sender depends on the
record before reverting it.

Automatic apply is intentionally limited. DMARQ only applies plans that already
contain a concrete DNS value and a low-risk operation such as create or update.
Plans that require provider-specific values, DKIM rotation, record
consolidation, or stale-selector removal remain manual until an operator
chooses the exact value and timing.

### MTA-STS Posture

The domain detail page checks `_mta-sts.<domain>` and fetches the policy from `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

DMARQ marks the check healthy when the TXT record contains `v=STSv1` with an `id`, the HTTPS policy is reachable, and the policy includes `version`, `mode`, `mx`, and `max_age`. Findings include the DNS record, policy URL, mode, MX patterns, and actionable guidance for missing records, fetch failures, invalid policies, or non-enforcing `testing`/`none` modes.

When `_mta-sts.<domain>` exists but `mta-sts.<domain>` does not resolve or the HTTPS policy cannot be fetched, DMARQ treats this as a policy-hosting problem rather than a missing TXT record. Keep the TXT record if its `id` is current, publish DNS for `mta-sts.<domain>`, serve the policy at `/.well-known/mta-sts.txt`, and rotate the TXT `id` after changing the policy so receivers refetch it.

MTA-STS posture uses the same cached DNS refresh behavior as the existing DNS health checks. Use the DNS refresh action when you publish or update a policy and need DMARQ to re-check immediately.

### DANE/TLSA Posture

When a domain has MX records, DMARQ can inspect passive DANE/TLSA readiness for
the `_25._tcp.<mx-host>` names on a best-effort basis. The check is read-only:
it reports whether TLSA records exist, whether their syntax is usable, and
whether capped live SMTP STARTTLS probing can reach an MX certificate that
produces an operator-ready `3 1 1` SPKI SHA-256 suggestion.

Treat generated TLSA values as review evidence, not an automatic DNS change.
The operator still needs to confirm DNSSEC posture, MX certificate rotation
policy, and maintenance timing before publishing or replacing TLSA records.

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
