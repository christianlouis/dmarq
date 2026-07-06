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

The domain list hides domains with no reports and no observed message volume by
default so historical or newly imported empty zones do not dominate daily
triage. Use **Show empty domains** when you intentionally want to audit those
domains.

The list also shows compact DNS evidence badges. **Cached DNS** and
**Fresh DNS** indicate normal evidence, **Fallback DNS** or **Partial DNS**
means an independent resolver had to be used, **Last known DNS** means DMARQ is
protecting the UI from a transient resolver failure with recently cached
evidence, and **DNS failed** means the latest explicit refresh could not produce
usable evidence.

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

The Domains page **Reload** action recomputes DNS evidence with bounded
parallelism, so larger workspaces do not wait for every domain one after
another. At application startup, DMARQ also prewarms DNS cache rows in the
background and prioritizes domains that already have reports or message volume.

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
Use **Refresh queue** to reload the remediation queue from the backend after
new reports, DNS checks, or operator lifecycle changes are available. If a
manual refresh fails, DMARQ keeps the currently loaded queue on screen and shows
a refresh warning so an operator does not lose context during a transient API or
network problem.
Use the queue filters to focus on all work, preview-ready repairs, blocked
repairs, evidence-gated items, notification-ready work, operator-waiting items,
manual work, or reputation review without losing the underlying prioritized
queue. The filter bar shows how many matching items are visible, how many match
the selected view, and how many remain in the full queue. Operators can sort the
same filtered queue by priority, repair readiness, or severity, and expand the
compact six-item list to show every matching item.
Each item now also shows the remediation track, priority band, owner, risk
level, safe-automation flag, and the exact operator decision DMARQ expects next.
Action plans include decision checkpoints and a rollback or fallback note so an
operator can verify the zone, sender, evidence freshness, and recovery path
before approving, closing, or converting a remediation item.
Verification cards include a closure gate and stale-evidence warning. This is
the rule DMARQ expects before an operator-resolved item should become an
evidence-verified repair.
Each remediation card also shows a **Fresh evidence path**. It names the
evidence that must be refreshed before the item can be closed safely, such as
DNS records, DMARC reports, sending-source intelligence, source reputation, or
a provider-specific DKIM/SPF/CNAME value. When the action is safe and read-only,
the card offers a focused refresh button that reloads the relevant backend
evidence and then rebuilds the queue. If a missing provider value is the blocker,
DMARQ shows that prerequisite instead of pretending it can refresh or repair the
item automatically.
The queue header also counts closure gates and rollback notes, so operators can
spot how much work still needs fresh evidence or a recovery plan before opening
every remediation card.
The **Repair progression** panel separates the recommendation from the next
safe gate. It tells the operator whether a connected provider preview is ready,
whether a provider-specific value is still missing, whether a sending source
must be classified first, whether the work is manual DNS, or whether fresh
reputation/report/DNS evidence is still required before closure. This panel is
read-only; it does not apply DNS changes or send provider requests. The top
**Next remediation** panel mirrors the same repair-gate status so the operator
can see the current blocker, readiness label, readiness score, next safe action,
freshness requirement, closure gate, stale-evidence warning, and first
readiness reason before opening the full queue. When a focused read-only
evidence refresh is available, the panel also links directly to the relevant
evidence section and exposes the same safe refresh action as the full queue
card.
Repair progression also includes a readiness label, 0-100 readiness score,
human-readable reasons, and blocker keys. Use this to separate work that is
ready for provider preview from work that is blocked by missing provider values,
sender classification, reputation evidence, or the required fresh-evidence
closure gate.
DNS-backed remediation items also include a **Provider repair plan** panel.
This panel separates three questions that should not be conflated:
whether DMARQ can prepare a safe provider preview, whether the change could be
applied after explicit approval, and whether fresh evidence is still required
before the repair is considered closed. It shows the connected provider,
operation, record name/type, apply blockers, provider-value prerequisites, and
manual fallback. It also lists before-apply checks, after-apply evidence
checks, blast radius, and an operator warning so a preview cannot be mistaken
for a completed repair. The panel also shows the current apply-confirmation
state. Ready provider repairs include the confirmation phrase an operator would
need after reviewing the preview; blocked repairs explain which blockers must
clear before a live-write confirmation should even be requested. Attempt
history is shown separately so future provider apply audit entries can be
reviewed without treating a preview as an apply. Public API and read-only MCP
consumers see the same context without preview/apply links and with an explicit
read-only approval gate. Those read-only responses also clear the confirmation
phrase and mark `apply_confirmation` as blocked so external automation cannot
mistake advisory context for a live-write affordance.
When provider apply audit entries exist, the queue summary counts both recorded
provider apply attempts and entries whose provider readback was verified.
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
queue view. The UI lists every dispatch blocker, not only the first one, so
operators can fix settings, routing, acknowledgement, and webhook coverage in
one pass. The queue header summarizes how many items are ready to notify,
blocked, awaiting acknowledgement, or covered by webhook routes so operators
can see the next action without opening every item.

When an operator marks an item resolved and the same finding no longer appears
in the current queue, the domain detail page lists it under evidence-verified
repairs. That section shows how DMARQ verified the absence, what evidence was
used, how many older verified repairs are hidden in the compact view, and what
fresh reports or DNS checks should keep monitoring the fix. It also shows the
closure gate and next safe action so an operator can tell that a resolved marker
is still conditional on fresh evidence staying clean. The compact view shows
the newest verified repairs first and can be expanded to show every verified
repair returned by the backend response. Stale or unknown queue-absence
evidence is called out so operators refresh evidence before relying on an old
verified marker.

After a remediation notification is previewed or acknowledged, an operator can
explicitly enqueue the notification through the dispatch API with
`confirm=true`. Dispatch currently means "create persisted webhook delivery
rows for configured endpoints"; it does not send from the queue view and does
not apply DNS changes. The delivery history can then be inspected through the
webhook delivery state. Lifecycle markers and dispatch requests may include an
operator note; DMARQ stores that note in the audit trail and shows it in the
recent operator history.

Dashboard action-plan cards and remediation-loop cards both deep-link into the
selected domain's remediation queue. Use those links when triaging workspace
health: they keep the operator on the evidence and approval surface instead of
dropping them on a generic domain overview.
The dashboard remediation loop also mirrors the Fresh Evidence path from the
domain queue. Its evidence-gated counters split the queue into DNS, report, and
reputation refreshes, and each remediation card states the concrete read-only
evidence action that should happen before the operator marks an item fixed.
Use the dashboard remediation filters and sort control when the workspace has
many active items. The dashboard can focus on preview-ready work, fresh evidence
requirements, provider apply work, blocked applies, provider apply history,
manual repairs, or reputation review, and the compact card list can expand to
show every matching item. The dashboard summary cards also count provider
previews, apply-after-approval work, blocked applies, and missing provider
values so a workspace-level triage view matches the domain queue semantics.
When provider apply history exists, the dashboard and domain rows show the
attempt count and how many applies have been verified by follow-up evidence.
The same dashboard area also surfaces confirmed notification dispatches and
operator follow-up activity so remediation work does not disappear after a
webhook has been queued.
Items with stale DNS, report, or reputation evidence can be filtered separately.
When a remediation card knows the relevant evidence section, the dashboard links
directly to that part of the domain detail page.

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
The recent-volume bars use a logarithmic scale so an occasional large outbound
day does not hide smaller but still recent sender activity.

Use the source filters to switch from all sources to reputation-review,
listed-only, authentication-review, unchecked reputation, recently active, stale,
or clean-reputation views. The source table also shows compact counters for the
same categories, so an operator can see whether the page is mostly historical
noise or has current risky senders that need action.

Use these findings before editing DNS. A new source is not automatically a
trusted sender; confirm the service owner first, then update SPF or DKIM only
when the source is legitimate.

Reputation evidence is shown separately from network ownership. ASN and BGP
prefix data explains who appears to operate the sending infrastructure; optional
reputation feeds can add DNSBL, blocklist, or abuse-confidence evidence when an
administrator has enabled those providers. A clean Geo/ASN lookup is not the
same thing as a clean reputation result.
When you use **Refresh reputation**, DMARQ recalculates cached IP reputation
evidence. If the refresh times out or a provider is unavailable, the page keeps
the previously loaded sending-source rows visible and shows the refresh error
separately.

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
Optional AI remediation plans can turn the same DNS/report context into a
longer step-by-step plan through LiteLLM/OpenAI-compatible providers. Strict
mode redacts email local-parts, while balanced and no-redaction modes preserve
email addresses and domains; secrets and opaque tokens are still redacted in
every mode. Demo mode keeps these plans template-backed and heavily cached.

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

Verification cards also show the method, freshness requirement, and failure
mode for each item. For example, provider-backed DNS repairs require a human
approval plus fresh DNS evidence after propagation; sender investigations wait
for a new DMARC report window before a source can be considered fixed.

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
