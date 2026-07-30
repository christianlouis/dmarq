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
  Saving resumable interview drafts requires workspace-write permission but
  does not create noisy audit rows. Completing the interview creates one
  sanitized audit event.
- Auth-disabled and API-key single-user installations store presentation
  choices on the workspace so a browser restart does not reset them.

The profile schema is versioned. Mail context accepts only monitored domain
names, known providers, self-hosted-sender status, whether the domain sends
mail, DNS provider and control, preferred report-intake route, setup-effort
preference, low-volume/bounce presence, bounded symptom metadata, and the
saved interview step. Passwords, tokens, mailbox addresses, message content,
and arbitrary fields are rejected rather than persisted.

## Problem-first setup

When `GUIDED_MAIL_HEALTH_UI_ENABLED=true`, a fresh self-hosted workspace can
optionally state why it installed DMARQ: suspected delivery trouble, confusing
reports, likely domain abuse, preventive monitoring, or simple curiosity. The
primary answer and optional secondary concerns are stored as ordered,
versioned workspace goals; a signed-in person's
chosen explanation depth is stored as their own presentation preference. The
same interview can record whether the operator prefers a local data path,
privacy, a balanced trade-off, convenience, or help deciding. These options
rank future intake advice but never claim one hosting model is universally
better. The four short screens save after every decision and can be resumed. A
fresh install starts with the user's problem, then asks for the affected
domain, DNS control, intended sending, and explanation preference. Unknown
answers may be skipped. Existing installations receive a current plan
immediately and may open the same questions only when useful.

The resulting `dmarq.diagnostic_plan.v1` response is deterministic and
read-only. It combines the stored workspace profile with persisted domains,
last-known-good DNS posture (including stored DKIM selectors and DMARC report
destinations), aggregate/failure/TLS report counts, source status, and DNS
provider readiness. It returns one current action with rationale and a
verifiable completion condition, at most four later steps, known facts,
inferences, and unknowns. Generating the plan never performs a DNS lookup,
connects to a mailbox, or writes to a provider. The profile and plan do not
enable the guided dashboard, alter DNS, or hide the established setup and
evidence workflows.

Guidance intentionally describes aggregate DMARC reports as authentication and
receiver-policy evidence. It does not present them as proof of an individual
bounce, inbox placement, or read event.

Assessments and source rows expose these boundaries through the versioned
[`dmarq.mail_signal.v1` contract](../reference/mail-signal-contract.md).
Observed authentication, receiver-reported disposition, DMARQ inference, and
unknown delivery outcome remain separate facts. Later DSN or provider-event
adapters can add stronger delivery evidence without reinterpreting historical
aggregate reports.

## Intake choices

The setup assistant returns a versioned
`dmarq.report_intake_recommendation.v1` result with one primary path and
progressively disclosed alternatives. It ranks manual XML/ZIP/GZIP upload,
local IMAP, Proton Mail Bridge, Gmail OAuth, Microsoft 365 Graph, Cloudflare
Email Routing and Worker, AWS SES/Lambda, and a generic authenticated raw-email
webhook from saved operator preferences and persisted source/import state.

Each option explains its data flow, processors, credential boundary, public
exposure, dependencies, failure modes, trade-off, and one verification method
before collecting credentials. Hosted webhook paths are not selectable as the
recommendation until the instance has public HTTPS; Bridge is not recommended
until its local availability is confirmed. Existing working sources rank ahead
of unnecessary migrations.

The visible first-report status distinguishes an accepted report, a safe
duplicate, rejected content, a configured source still waiting for receiver
reports, and a setup that still needs a source. Generating the recommendation
does not contact a provider, reveal a secret, deploy infrastructure, or change
DNS. The complete comparison and security contract is documented in
[Report intake options](../reference/report-intake-options.md).

## What the first guided assessment can say

It reads only the indexed sender facts created during aggregate-report
ingestion. Opening the dashboard does not trigger DNS, PTR, reputation, or
delivery lookups.

- A known sender with DMARC authentication failures is presented as a possible
  impact to intended mail, with a direct link to its evidence.
- An unknown sender whose failures were consistently rejected or quarantined is
  presented as likely unauthorized use with no immediate configuration change.
- Missing report evidence directs the operator to report intake.

The `dmarq.mail_health_assessment.v2` response also compares the immediately
preceding bounded evidence window. A legitimate source that previously passed
and now fails is prioritized ahead of a larger anonymous failure count. Its
machine-readable contract contains an assessment ID, outcome, impact, urgency
and confidence bands, freshness, known facts, inferences, unknowns, one safe
next action, verification condition, and aggregate-safe evidence references.
The ID is stable for the exact workspace, domain, conclusion, evidence window,
supporting signal set, and algorithm version; a new window or changed evidence
produces a new ID. Localized prose is presentation data, not the stored source
of truth.

Operators can classify one exact domain/source-IP pair as `legitimate`,
`unknown`, `unauthorized`, `expected_forwarding`, or `stale`. Each decision is
append-only in the workspace audit trail with actor, time, reason, and scope.
The latest decision affects future assessments but never changes historical
DMARC reports. Expected forwarding produces a forwarding/DKIM review and never
suggests adding an intermediary IP to SPF without sender-side evidence.

If intake is connected and the saved profile says a domain is low-volume, an
empty current window is a watch state rather than an urgent failure. If the
operator reports a bounce while aggregate reports show DMARC passes, DMARQ
returns insufficient delivery evidence and points to the SMTP response, DSN,
or provider event instead of claiming that authentication proves delivery.

The assessment deliberately says that aggregate DMARC reports record receiver
authentication and policy evaluation. They do **not** prove whether an
individual message was delivered, bounced, placed in spam, or read. Delivery
claims require later DSN or provider-delivery evidence.

Read-only integrations receive the same structured assessment from
`GET /api/v1/public/mail-health/assessment?days=30` or the MCP
`mail_health_assessment` tool. Normal reads query bounded persisted projections
and audit decisions only; they perform no live DNS, network, reputation, or
provider enrichment.

## Next increments

The initial view supports all three presentation contexts over the same
read-only assessment:

- **Watch** keeps the conclusion and one next step prominent.
- **Diagnose** adds the observed facts and verification condition.
- **Evidence** links directly to the unchanged sender or report evidence.

No context changes the underlying evidence, permissions, or DNS write safety.
