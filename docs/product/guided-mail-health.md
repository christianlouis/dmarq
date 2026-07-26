# Guided Mail Health

DMARQ's classic dashboard remains the complete operational surface for DNS,
report, source, remediation, and audit work. The guided view is an optional
starting point for people who first need a clear answer to three questions:

1. What do the current reports mean?
2. Could mail I intend to send be affected?
3. What is the safest next step?

## Safe rollout

The experience is protected by two independent controls:

1. Set `GUIDED_MAIL_HEALTH_UI_ENABLED=true` on the deployment and recreate the
   application container.
2. A workspace operator chooses **Try guided view** from its dashboard.

Existing workspaces remain on the classic dashboard until the second step. An
operator can return to it immediately with **Use classic dashboard**.

## Problem-first setup

When `GUIDED_MAIL_HEALTH_UI_ENABLED=true`, a fresh self-hosted workspace can
optionally state why it installed DMARQ: suspected delivery trouble, confusing
reports, likely domain abuse, preventive monitoring, or simple curiosity. The
answer and chosen explanation depth are stored per workspace. It selects a
clear first action, but does not enable the guided dashboard, alter DNS, or
hide the established setup and evidence workflows.

Guidance intentionally describes aggregate DMARC reports as authentication and
receiver-policy evidence. It does not present them as proof of an individual
bounce, inbox placement, or read event.

## Intake choices

The setup assistant keeps the direct IMAP path available, and exposes the
other supported routes in the same place: Gmail OAuth, Microsoft 365 Graph,
manual XML/ZIP/GZIP upload, and an inbound webhook such as a Cloudflare Email
Worker. The choices describe their operational boundary before collecting
credentials: OAuth or application permissions for hosted mail, no mailbox
credential for upload, and reachable HTTPS plus a webhook secret for forwarded
mail.

## What the first guided assessment can say

It reads only the indexed sender facts created during aggregate-report
ingestion. Opening the dashboard does not trigger DNS, PTR, reputation, or
delivery lookups.

- A known sender with DMARC authentication failures is presented as a possible
  impact to intended mail, with a direct link to its evidence.
- An unknown sender whose failures were consistently rejected or quarantined is
  presented as likely unauthorized use with no immediate configuration change.
- Missing report evidence directs the operator to report intake.

The assessment deliberately says that aggregate DMARC reports record receiver
authentication and policy evaluation. They do **not** prove whether an
individual message was delivered, bounced, placed in spam, or read. Delivery
claims require later DSN or provider-delivery evidence.

## Next increments

The initial view supports the `watch` context. Workspace preferences already
reserve `diagnose` and `evidence` contexts plus guided, standard, and expert
explanation depth for the subsequent product slices.
