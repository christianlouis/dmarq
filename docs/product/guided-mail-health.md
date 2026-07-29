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
operator can return to it immediately with **Use classic dashboard**. A user
may independently choose how much explanation they see and whether the guided
card opens in **Watch**, **Diagnose**, or **Evidence** context; API-key and
single-user deployments retain the workspace default. These choices live in
**Profile > How DMARQ explains findings** and do not alter evidence, warning,
permission, or DNS-approval behavior.

## Profile boundaries

DMARQ deliberately separates personal presentation from shared operational
context:

- Each signed-in user may select **Guide me**, **Balanced**, or **Full technical
  detail**, a default Watch/Diagnose/Evidence context, and contextual teaching
  hints. An analyst may change these personal values without workspace-write
  permission.
- The workspace stores ordered installation goals, report-data preference,
  notification posture, and a small non-secret description of the mail setup.
  Changing this shared profile requires workspace-write permission and creates
  a sanitized audit event.
- Auth-disabled and API-key single-user installations store presentation
  choices on the workspace so a browser restart does not reset them.

The profile schema is versioned. Mail context accepts only known providers,
self-hosted-sender status, DNS provider, preferred report-intake route, DNS
control, and setup-effort preference. Passwords, tokens, mailbox addresses,
and arbitrary fields are rejected rather than persisted.

## Problem-first setup

When `GUIDED_MAIL_HEALTH_UI_ENABLED=true`, a fresh self-hosted workspace can
optionally state why it installed DMARQ: suspected delivery trouble, confusing
reports, likely domain abuse, preventive monitoring, or simple curiosity. The
answer is stored as an ordered, versioned workspace goal; a signed-in person's
chosen explanation depth is stored as their own presentation preference. The
same interview can record whether the operator prefers a local data path,
privacy, a balanced trade-off, convenience, or help deciding. These options
rank future intake advice but never claim one hosting model is universally
better. The profile selects a clear first action, but does not enable the
guided dashboard, alter DNS, or hide the established setup and evidence
workflows.

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

The initial view supports all three presentation contexts over the same
read-only assessment:

- **Watch** keeps the conclusion and one next step prominent.
- **Diagnose** adds the observed facts and verification condition.
- **Evidence** links directly to the unchanged sender or report evidence.

No context changes the underlying evidence, permissions, or DNS write safety.
