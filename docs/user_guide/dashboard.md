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

### Remediation Loop

The remediation loop card turns current domain health findings into operator
work. It separates operator-marked resolved work from evidence-verified fixed
work and shows the current approval, manual-action, and investigation counts.
Repair-gate counters distinguish provider previews that are ready for review,
items that still need fresh evidence before closure, and findings that are
blocked before repair. The dashboard also separates items waiting on an operator
for sender classification, manual repair, reputation review, or general operator
review. The section header shows the loop status, top incident family, next
action, and the last successful summary refresh time so operators can triage the
queue before reading every card. Use **Refresh queue** when new reports, DNS
refreshes, or operator markers should be reflected immediately. A failed manual
refresh keeps the previously loaded dashboard visible and shows a refresh warning
instead of replacing the page with an empty state. Cards are sorted so provider
previews and approval-ready work appear before blocked, reputation,
investigation, and manual work. Each card shows the same readiness label and
0-100 score used on the domain remediation queue. Cards also show the next safe
action, first readiness reason, freshness requirement, closure gate, and blocker
summary before linking to the selected domain for the full evidence, approval,
and verification flow. Filter chips let you isolate preview-ready repairs,
approval verification, sender review, report-evidence follow-up, blocked work,
manual work, reputation review, and stale-evidence cases without opening every
domain. The same filter bar can now isolate remediation notifications that are
ready to send, already dispatched, blocked by notification settings, or waiting
for operator follow-up after dispatch.
Open the domain detail queue for the full provider-repair plan. That view shows
whether a DNS item has a safe provider preview, can be applied only after
explicit approval, is blocked by missing provider values, or should fall back to
manual DNS work. Provider repair items also expose before-apply and after-apply
checklists so operators can review the blast radius and required evidence before
approving or closing a repair.

### Demo Mode

When `DEMO_MODE=true`, the dashboard uses generated rolling data for
`dmarq.org` and `dmarq.com`. The demo data fills the aggregate dashboard,
forensic report summaries, SMTP TLS report summaries, DNS posture, and exports.
It intentionally includes healthy senders, partially aligned senders, and a few
misconfigurations so each dashboard panel has realistic content.

The public demo is meant to start in the same place a normal self-service user
would: one account with multiple domains. From there, the demo path on the
dashboard walks through the larger deployment models:

1. Start with `dmarq.org` and `dmarq.com` as a single-user, multi-domain account.
2. Zoom out to an account view with users, roles, workspaces, plan limits, and billing ownership.
3. Switch to an ISP/provider view with bundled customer workspaces and monthly billing export examples.
4. Impersonate a demo customer user to see scoped workspace access.
5. Compare the same DMARC workflows in a self-hosted deployment where billing remains local.

All demo users, customer IDs, provider IDs, invoices, and domains outside
`dmarq.org`/`dmarq.com` are generated examples. Support impersonation in the
demo is explicit UI state; production impersonation should be audited and
permission-gated.

The account detail panel keeps the active organization, workspace, and viewed
user visible while you move through the demo path. Workspaces can be selected
directly; `dmarq.org` and `dmarq.com` link to report-backed domain detail pages,
while ISP and self-hosted sample domains are marked as demo-only tenant context
until the demo includes full report stores for those generated tenants.

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
