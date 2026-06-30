# DMARQ Product Roadmap

Last updated: 2026-06-30

DMARQ has moved beyond its original MVP. The product now parses aggregate and
forensic DMARC reports, imports from IMAP/Gmail/Microsoft 365, persists report
data, provides DNS posture guidance, supports alerts, exposes API/webhook/SIEM
integrations, and has workspace foundations for MSP-style operation.

The next roadmap turns that foundation into three durable product modes:

- **Self-hosted DMARQ:** privacy-first deployment where operators keep full
  control of reports, secrets, and infrastructure.
- **DMARQaaS:** hosted DMARQ with subscriptions, onboarding, tenant isolation,
  billing, and support expectations.
- **ISP/OEM DMARQ:** DMARQ embedded into ISP, MSP, registrar, and hosting
  provider environments, including provider-owned billing and provisioning.

It also grows DMARQ toward competitive parity with commercial DMARC monitoring
platforms such as Valimail, EasyDMARC, dmarcian, PowerDMARC, and DMARCguard
while preserving DMARQ's differentiators: self-hosted operation, transparent
evidence, human-approved changes, and no forced DNS delegation.

This roadmap is intentionally product-oriented. It should drive implementation
issues, not replace release notes or the completed milestone history in
[`milestones.md`](../milestones.md).

## Product North Star

DMARQ should become a domain mail-health assistant, not only a DMARC report
viewer.

The desired user story is:

> DMARQ observes DMARC and mail-delivery health, detects what is wrong, safely
> prepares what can be fixed, and tells the operator how healthy each sending
> domain is - regardless of whether the sender uses commercial providers or
> self-hosted mail infrastructure.

The human-in-the-loop boundary is non-negotiable:

- DMARQ may automatically ingest, detect, correlate, explain, prioritize, draft
  repair plans, and notify.
- DMARQ may apply changes only when the operator has connected a scoped
  provider, reviewed the exact change, and approved the action.
- DMARQ must show what it changed, what it could not change, and what still
  needs manual work.
- DMARQ should never hide DNS or mail-server modifications behind background
  automation.

## Product Commitments

The roadmap must continue to honor the public DMARQ promise:

- Ingest and visualize **aggregate and forensic** DMARC reports.
- Show who sends mail for a domain, what passes DMARC/SPF/DKIM, what fails, and
  how to fix it.
- Keep self-hosted deployment first-class through Docker and documented
  production operation.
- Keep Cloudflare and DNS integrations read-only by default: discover, analyze,
  suggest, and track changes. DNS write automation must be opt-in per action,
  previewed, permission-scoped, explicitly confirmed, and audited.
- Preserve privacy boundaries. Self-hosted deployments do not require a third
  party to see reports. Hosted and ISP modes must state clearly who operates the
  service and must enforce tenant isolation, audit logs, retention controls, and
  secret redaction.
- Keep normal operation GUI-first: setup, mailbox connection, DNS linting,
  alerts, and report review should not require CLI work.
- Make remediation understandable. Technical DNS values stay exact, but
  operator-facing explanations should support localization, with German as the
  first non-English target language.

## Current Baseline

Completed or substantially delivered:

- Aggregate report parsing for XML, ZIP, GZIP, legacy DMARC, and DMARCbis-style
  report variants.
- Forensic/RUF report metadata parsing with privacy controls.
- IMAP, Gmail, and Microsoft 365 Graph mail-source ingestion.
- Durable report and record storage with duplicate handling and import history.
- Dashboard, domain reports, source reports, trend charts, exports, and
  recommendations.
- DNS health checks for DMARC/SPF/DKIM plus posture checks for MTA-STS, TLS-RPT,
  and BIMI.
- Cloudflare read-only inspection, DNS snapshots, and DNS change history.
- Notifications, alert rules, alert history, and Apprise delivery.
- API tokens, webhooks, SIEM templates, and ticketing/chatops templates.
- Workspace, RBAC vocabulary, audit-log, onboarding-template, and MSP operator
  foundations.
- Demo deployment that rolls forward from main through CI/GitOps.
- Kubernetes high-availability work for tolerating loss of one hardware host.

The main open strategic issues are:

- [Issue #12](https://github.com/christianlouis/dmarq/issues/12): user
  management, SaaS, ISP/OEM, subscription, and billing tracker. Most foundation
  slices are complete; the remaining active child is enterprise identity and
  support-access hardening.
- [Issue #304](https://github.com/christianlouis/dmarq/issues/304): health
  score, A-F rating, and remediation action plan.
- [Issue #305](https://github.com/christianlouis/dmarq/issues/305): competitive
  parity tracker for DMARC monitoring platforms.
- [Issue #384](https://github.com/christianlouis/dmarq/issues/384): autonomous
  mail health remediation loop with human approval.
- [Issue #385](https://github.com/christianlouis/dmarq/issues/385): sender IP
  reputation and blacklist monitoring.
- [Issue #386](https://github.com/christianlouis/dmarq/issues/386): ecosystem
  integration roadmap.
- [Issue #387](https://github.com/christianlouis/dmarq/issues/387):
  localization and multilingual remediation guidance.

## Roadmap Tracks

### Track A: Trustworthy Core Product

Goal: keep DMARQ excellent at the thing users came for before adding commerce.

Deliverables:

- Keep parser compatibility current with real-world aggregate and forensic
  report formats.
- Add a dashboard-level health score, A-F rating, score breakdown, and
  prioritized action plan.
- Add named sender identification so raw source IPs become recognizable services
  with provider-specific remediation.
- Keep demo data realistic for `dmarq.org` and `dmarq.com`, including
  30/60/90-day windows, ordinary sources, corner cases, and safe
  misconfiguration examples.
- Improve dashboard-to-detail navigation so every summary card leads to the
  evidence and recommended action.
- Continue polishing detail views so the whole app feels useful, dense, and
  visually consistent.
- Maintain export and data-access guarantees for a customer's own report data.
- Add score history and compliance evidence exports for audit workflows.
- Add sender IP reputation and blacklist signals as visible health-score
  contributors.
- Group raw findings into remediation incidents: fixed, approval-ready, manual,
  or informational.

Exit criteria:

- A domain owner can answer who sends mail, what is failing, what changed, and
  what to do next without leaving the dashboard/detail flow.
- A domain owner can distinguish observed problems from approved repairs and
  manual work still waiting on them.
- Demo mode continues to showcase realistic aggregate, forensic, DNS, TLS-RPT,
  MTA-STS, and BIMI states without touching production paths.

### Track A2: Ecosystem Integrations and Localization

Goal: make DMARQ fit into the places where operators already manage domains,
DNS, mail delivery, hosting, tickets, and customer accounts.

Integration categories:

| Ecosystem | Why it matters | First useful behavior | Write boundary |
| --- | --- | --- | --- |
| DNS providers | DMARC/SPF/DKIM fixes live in DNS | detect provider, import zones, generate change plans | human-approved only |
| Mail services | sender domains and DKIM records originate there | import verified sender domains and required DNS records | human-approved only |
| Self-hosted MTAs | many deliverability problems are not SaaS-specific | show IP reputation, DNS, rDNS, and alignment guidance | manual or explicit integration |
| Hosting panels | SMB users manage DNS/mail in control panels | ISPConfig/cPanel/Plesk/WHMCS integration path | provider-scoped approval |
| Report intake workers | polling mailboxes is not always ideal | Cloudflare/AWS SES/generic webhook intake | no DNS writes |
| Ticketing/chatops/SIEM | operators need workflows, not dashboards only | alert and evidence envelopes | read/notify by default |
| Identity/provider portals | hosted and ISP deployments need lifecycle hooks | OIDC, SCIM, provider SSO, provisioning APIs | audited admin actions |

Localization priorities:

- English remains the source and fallback language.
- German is the first non-English target because early visible community signals
  and the project context suggest a strong German-speaking operator audience.
- Danish, Hebrew, and Estonian are later candidate languages based on a small,
  aggregate review of public GitHub stargazer profile locations. This is a weak
  signal, not nationality inference, and should be validated through community
  feedback before significant translation work.

Exit criteria:

- Remediation guidance can be localized without changing DNS record values,
  protocol tags, provider names, or evidence.
- Users can understand what to do next in their preferred language.
- Community contributors have a documented path to review or add translations.

### Track B: Auth, RBAC, and Tenant Safety

Goal: make multi-user and multi-tenant operation real, not just a login screen.

Build on the existing workspace model:

- **Organization/account:** billing and legal customer boundary.
- **Workspace:** operational tenant boundary for domains, mail sources, reports,
  alerts, API tokens, audit logs, and retention settings.
- **Membership:** user-to-organization and user-to-workspace role assignment.
- **Entitlement:** local materialized feature/quota state used by access checks.

Deliverables:

- Keep OIDC/Logto as the preferred production authentication path.
- Preserve explicit auth-disabled mode for local development only.
- Add invitation and membership management for organizations/workspaces.
- Add workspace/account switcher for users with access to multiple tenants.
- Enforce workspace-scoped RBAC in API dependencies and UI actions.
- Record audit events for login-sensitive actions, membership changes, billing
  changes, provider provisioning, and support access.
- Support MFA policy enforcement for business/enterprise plans.
- Add SCIM 2.0 after membership management is stable.
- Add SAML only if OIDC is insufficient for real customer requirements.

Exit criteria:

- Users can belong to multiple organizations/workspaces and switch safely.
- Every read/write path enforces tenant boundaries.
- Audit logs can explain who changed membership, billing, domains, mail sources,
  DNS recommendations, alerts, and retention.

### Track C: DMARQaaS

Goal: offer hosted DMARQ without weakening self-hosted DMARQ.

Deliverables:

- Signup flow that creates organization, owner membership, first workspace, and
  guided first-domain checklist.
- Domain ownership verification before production use.
- Hosted onboarding for IMAP, Gmail, Microsoft 365, Cloudflare, alerts, and DNS
  linting.
- Plan-limit UI for domains, message volume, users, retention, API/webhooks, and
  SSO/SCIM.
- Hosted privacy documentation for data processing, retention, tenant isolation,
  support access, backups, and deletion.
- Admin/support tooling with strict impersonation controls and audit trail.

Exit criteria:

- A new hosted customer can sign up, pay or start trial, add a domain, connect a
  report mailbox, and reach a useful dashboard without operator intervention.
- Self-hosted installs continue to work without Stripe, DMARQ cloud accounts, or
  hosted-only dependencies.

### Track D: Billing, Subscriptions, and Entitlements

Goal: separate product access from payment processor assumptions.

Billing modes to support:

| Mode | Customer invoice owner | Payment/ledger owner | DMARQ role |
| --- | --- | --- | --- |
| `direct_stripe` | DMARQ | Stripe Billing | Subscription checkout, webhooks, entitlements |
| `manual_contract` | DMARQ | External/manual | Contract-driven entitlement state |
| `provider_resale` | ISP/MSP/hoster | Provider billing system | Provisioning, usage export, provider references |
| `provider_whmcs` | Hosting provider | WHMCS | Provisioning module plus usage/overage export |
| `provider_tmf` | ISP/telco | OSS/BSS stack | TM Forum-aligned customer/bill/payment references |
| `self_hosted_license` | Customer/operator | None or external | License/support entitlement only |

Suggested DMARQaaS price hypotheses:

| Tier | Price hypothesis | Included |
| --- | ---: | --- |
| Free / Trial | EUR 0 | 1 sending domain, 10k msgs/mo, 14-30d history, 1 user |
| Starter | EUR 19/mo | 2 sending domains, 100k msgs/mo, 90d history, 1 user |
| Growth | EUR 49/mo | 8 sending domains, 500k-1M msgs/mo, 180d history, 3 users |
| Business | EUR 129/mo | 25 sending domains, 2M msgs/mo, 1y history, 10 users, API/webhooks |
| Enterprise | from EUR 399/mo | SSO, SCIM, audit export, custom retention, SLA/support |
| ISP/OEM | custom | Wholesale domains/volume, provider SSO, provisioning API |

Implementation guidance:

- Use Stripe Billing, Checkout Sessions in subscription mode, and Stripe
  Customer Portal for direct DMARQaaS.
- Use Stripe Prices, not deprecated plan objects.
- Store Stripe price IDs and provider product codes as configuration/data, not
  hard-coded business logic.
- Treat Stripe, WHMCS, and ISP systems as event sources that update local
  subscriptions and entitlements asynchronously.
- Enforce application access from local entitlements only.
- Keep provider-billed accounts valid without Stripe customer/subscription IDs.
- Export idempotent usage records by period for provider monthly billing.

Exit criteria:

- Stripe subscription changes update local entitlements through webhooks.
- Provider-billed accounts can appear on an ISP monthly bill without Stripe.
- Usage exports are stable enough for recurring invoicing and overage billing.
- Suspended accounts enter safe read-only/grace states before termination.

### Track E: ISP, MSP, and Hosting Provider Integrations

Goal: make DMARQ easy for providers to embed into existing customer portals and
billing stacks.

Standards and ecosystems to align with:

- OIDC/OAuth 2.0 for SSO.
- SCIM 2.0 for enterprise/provider user provisioning.
- Domain Connect for guided DNS setup where DNS providers support it.
- WHMCS provisioning modules and usage metrics for hosting providers.
- cPanel/WHM and Plesk APIs or extensions for hosting-control-panel workflows.
- TM Forum Open APIs as a conceptual mapping for larger ISP/telco integrations.

Deliverables:

- Provider API tokens with scopes for customer/workspace provisioning.
- Create/suspend/reactivate/terminate lifecycle endpoints.
- Provider SSO handoff and workspace deep links.
- Usage export endpoints for monthly billing.
- Provider-visible health and import summaries without exposing raw tenant report
  rows.
- WHMCS provisioning module as the first practical hosting integration.
- Domain Connect templates for DMARC/SPF/DKIM/MTA-STS/BIMI setup assistance.
- cPanel/WHM and Plesk adapters after the provider API stabilizes.

Exit criteria:

- An ISP can sell DMARQ as a package, provision a customer workspace, bill it on
  the customer's existing monthly invoice, and suspend/reactivate service without
  using the DMARQ UI manually.
- Customer-facing users land directly in the right organization/workspace
  through provider SSO.

### Track F: Production Reliability and HA

Goal: make self-hosted, SaaS, and provider deployments operationally credible.

Deliverables:

- Preserve the completed
  [issue #206](https://github.com/christianlouis/dmarq/issues/206) guarantee:
  tolerate loss of any one Kubernetes hardware host for prod/preprod.
- Move Alembic migrations out of app init containers into a single migration
  job/release step.
- Run multiple app replicas with readiness/liveness probes, topology spread, and
  PDBs.
- Confirm sessions, auth state, scheduler behavior, and background imports are
  safe across replicas.
- Align CloudNativePG and Longhorn topology with the cluster HA standard.
- Document disaster recovery, restore drills, and operational SLOs for hosted
  and provider deployments.

Exit criteria:

- App and preprod remain reachable after losing one hardware host.
- Deployments do not run racing migrations.
- Operators can verify rollout, rollback, backup, restore, and tenant isolation
  from documented runbooks.

### Track G: Competitive Parity and Product Intelligence

Goal: make DMARQ credible against established DMARC monitoring platforms without
copying their lock-in patterns.

Deliverables:

- Implement health score, A-F rating, score factors, and score-driven action
  plans.
- Add named sender identification and provider-specific remediation.
- Persist score history and expose audit-ready evidence exports.
- Expand advanced DNS linting for SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and BIMI.
- Productize public API and MCP tools for posture, reporting, DNS health,
  action plans, and tenant summaries.
- Evaluate DANE, ARC, and ARF as passive validation/reporting features before
  deciding whether active hosted services belong in DMARQ.
- Add migration and data-portability workflows from other DMARC tools.
- Polish ISP, MSP, and multi-tenant demos so users can move between single
  domain, organization, provider, customer, billing, and support-access views.
- Add geo/source enrichment and anomaly detection views.
- Design operator-approved DNS change plans and optional provider write
  integrations without changing the read-only default.
- Add sender IP reputation and blacklist monitoring as a mail-health signal.
- Add an autonomous remediation loop that turns findings into human-approved
  repair plans and notifications.
- Add multilingual remediation guidance so advice is actionable outside an
  English-only operations team.

Exit criteria:

- DMARQ can answer the same buyer questions as commercial DMARC monitoring
  platforms: score, grade, sender identity, what changed, what to fix, what the
  audit evidence is, whether sending IPs have reputation risk, and how to
  migrate in or out.
- Features remain evidence-linked, tenant-safe, exportable, and usable in
  self-hosted mode.

## Sequencing

### Phase 1: Product Roadmap and Design Freeze

Outcome: shared implementation blueprint for #12.

- Finalize this roadmap and #12 issue comments.
- Split #12 into child issues for schema, auth/RBAC, SaaS onboarding, billing,
  provider API, WHMCS, and website copy.
- Define non-negotiable guardrails for self-hosted mode and DNS read-only
  defaults.

### Phase 2: Organization and Entitlement Foundation (Started)

Outcome: local data model can represent SaaS, ISP, and self-hosted modes.

- Add organization/account model above workspaces. (Initial schema added.)
- Add subscription, billing account, entitlement, usage record, provider
  integration, and billing event models.
- Backfill existing installs into a default organization and default workspace.
  (Initial migration and runtime bootstrap added.)
- Add demo-mode SaaS, managed-service, and ISP deployment data for public demos.
- Add organization summary and provider usage export APIs for UI/provider
  integration work. (Initial read APIs added.)
- Add provider subscription state update API for ISP billing systems to push
  suspend/reactivate/cancel lifecycle changes. (Initial write API added.)
- Add entitlement checks without changing current self-hosted behavior.

### Phase 3: Auth and Workspace RBAC

Outcome: multi-user access is enforced.

- Add membership management and workspace/account switching.
- Enforce role checks in API dependencies.
- Add UI affordances for users, roles, invitations, and audit logs.
- Add tests for cross-workspace isolation and forbidden access.

### Phase 4: Direct DMARQaaS Billing

Outcome: hosted customers can subscribe directly.

- Add Stripe Checkout, Customer Portal, webhook handling, and local entitlement
  sync.
- Add plan-limit display and warning states.
- Add hosted signup/onboarding flow.
- Add billing/audit UI for organization owners.

### Phase 5: Provider-Billed ISP/OEM Mode

Outcome: providers can provision and bill DMARQ themselves.

- Add provider provisioning API and provider-scoped tokens.
- Add monthly usage export.
- Add suspend/reactivate/cancel lifecycle enforcement.
- Build first WHMCS module.
- Add provider SSO handoff.

### Phase 6: HA and Operational Maturity

Outcome: commercial deployments are reliable enough to sell.

- Maintain Kubernetes HA behavior from the completed host-loss work.
- Add migration job pattern.
- Document SLOs, backup/restore, retention, support access, and incident
  response for SaaS/provider modes.
- Run production-like failover and restore drills.

### Phase 7: Competitive Parity Slices

Outcome: DMARQ becomes comparable with commercial DMARC monitoring products on
the features buyers expect.

- Build health score, A-F rating, and action plan first.
- Add named sender identification and provider remediation.
- Add score history and compliance evidence exports.
- Expand DNS linting and guided configuration.
- Productize API/MCP surfaces for posture and reporting.
- Add migration, portability, geo/source intelligence, anomaly detection, and
  optional DNS change-plan workflows.
- Add reputation/blacklist monitoring for sending IPs and source identities.
- Add localization support for remediation and notification text.

### Phase 8: Mail Health Autopilot

Outcome: DMARQ can guide operators from observation to safe repair.

- Group DNS, DMARC, sender, provider, and reputation findings into domain health
  incidents.
- Classify each incident as informational, manual, approval-ready, or already
  fixed.
- Notify operators when important incidents appear, worsen, are fixed, or need
  approval.
- Connect one-click repair to the same audited, human-approved change-plan
  model instead of adding provider-specific shortcuts.

## GitHub Tracking

- [Issue #12](https://github.com/christianlouis/dmarq/issues/12): auth,
  multi-user, SaaS, ISP/OEM, subscription, billing, and entitlement roadmap.
- [Issue #243](https://github.com/christianlouis/dmarq/issues/243):
  enterprise identity provisioning and support-access controls.
- [Issue #304](https://github.com/christianlouis/dmarq/issues/304): health
  score, A-F rating, and remediation action plan.
- [Issue #305](https://github.com/christianlouis/dmarq/issues/305):
  competitive parity tracker.
- [Issue #306](https://github.com/christianlouis/dmarq/issues/306): named
  sender identification and provider-specific remediation.
- [Issue #307](https://github.com/christianlouis/dmarq/issues/307): score
  history, trends, and compliance evidence exports.
- [Issue #308](https://github.com/christianlouis/dmarq/issues/308): advanced
  DNS linting and guided configuration.
- [Issue #309](https://github.com/christianlouis/dmarq/issues/309): public API
  and MCP tools for posture and reporting.
- [Issue #310](https://github.com/christianlouis/dmarq/issues/310): DANE, ARC,
  and ARF competitive protocol coverage evaluation.
- [Issue #311](https://github.com/christianlouis/dmarq/issues/311): migration
  and data portability workflows.
- [Issue #312](https://github.com/christianlouis/dmarq/issues/312): ISP, MSP,
  and multi-tenant demo workflow polish.
- [Issue #313](https://github.com/christianlouis/dmarq/issues/313): geo/source
  enrichment and anomaly detection views.
- [Issue #314](https://github.com/christianlouis/dmarq/issues/314):
  operator-approved DNS change plans and optional provider write integrations.
- [Issue #378](https://github.com/christianlouis/dmarq/issues/378): import
  domains from verified sender mail services.
- [Issue #379](https://github.com/christianlouis/dmarq/issues/379): import
  domains from DNS provider zones.
- [Issue #380](https://github.com/christianlouis/dmarq/issues/380): safe
  one-click DNS repair across provider plugins.
- [Issue #381](https://github.com/christianlouis/dmarq/issues/381): detect DNS
  provider from NS records and suggest automation path.
- [Issue #382](https://github.com/christianlouis/dmarq/issues/382): Postmark
  DNS automation for sender domain setup.
- [Issue #383](https://github.com/christianlouis/dmarq/issues/383): direct
  DMARC report intake via hosted mail/webhook workers.
- [Issue #384](https://github.com/christianlouis/dmarq/issues/384):
  autonomous mail health remediation loop.
- [Issue #385](https://github.com/christianlouis/dmarq/issues/385): sender IP
  reputation and blacklist monitoring.
- [Issue #386](https://github.com/christianlouis/dmarq/issues/386): ecosystem
  integration roadmap.
- [Issue #387](https://github.com/christianlouis/dmarq/issues/387):
  localization and multilingual remediation guidance.

Completed reference issues:

- [Issue #206](https://github.com/christianlouis/dmarq/issues/206): Kubernetes
  host-loss high availability.
- [Issues #236-#242](https://github.com/christianlouis/dmarq/issues?q=repo%3Achristianlouis%2Fdmarq+is%3Aissue+236..242):
  #12 foundation slices for RBAC, membership, workspace switching, SaaS
  onboarding, Stripe billing, provider lifecycle, and entitlement visibility.
