# DMARQ Product Roadmap

Last updated: 2026-06-26

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

This roadmap is intentionally product-oriented. It should drive implementation
issues, not replace release notes or the completed milestone history in
[`milestones.md`](../milestones.md).

## Product Commitments

The roadmap must continue to honor the public DMARQ promise:

- Ingest and visualize **aggregate and forensic** DMARC reports.
- Show who sends mail for a domain, what passes DMARC/SPF/DKIM, what fails, and
  how to fix it.
- Keep self-hosted deployment first-class through Docker and documented
  production operation.
- Keep Cloudflare and DNS integrations read-only by default: discover, analyze,
  suggest, and track changes. Any future write automation must be opt-in,
  previewed, permission-scoped, and audited.
- Preserve privacy boundaries. Self-hosted deployments do not require a third
  party to see reports. Hosted and ISP modes must state clearly who operates the
  service and must enforce tenant isolation, audit logs, retention controls, and
  secret redaction.
- Keep normal operation GUI-first: setup, mailbox connection, DNS linting,
  alerts, and report review should not require CLI work.

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

The main open strategic issues are:

- [Issue #12](https://github.com/christianlouis/dmarq/issues/12): user
  management, SaaS, ISP/OEM, subscription, and billing foundation.
- [Issue #206](https://github.com/christianlouis/dmarq/issues/206): Kubernetes
  high availability for loss of one hardware host.

## Roadmap Tracks

### Track A: Trustworthy Core Product

Goal: keep DMARQ excellent at the thing users came for before adding commerce.

Deliverables:

- Keep parser compatibility current with real-world aggregate and forensic
  report formats.
- Keep demo data realistic for `dmarq.org` and `dmarq.com`, including
  30/60/90-day windows, ordinary sources, corner cases, and safe
  misconfiguration examples.
- Improve dashboard-to-detail navigation so every summary card leads to the
  evidence and recommended action.
- Continue polishing detail views so the whole app feels useful, dense, and
  visually consistent.
- Maintain export and data-access guarantees for a customer's own report data.

Exit criteria:

- A domain owner can answer who sends mail, what is failing, what changed, and
  what to do next without leaving the dashboard/detail flow.
- Demo mode continues to showcase realistic aggregate, forensic, DNS, TLS-RPT,
  MTA-STS, and BIMI states without touching production paths.

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

- Complete [issue #206](https://github.com/christianlouis/dmarq/issues/206):
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

## Sequencing

### Phase 1: Product Roadmap and Design Freeze

Outcome: shared implementation blueprint for #12.

- Finalize this roadmap and #12 issue comments.
- Split #12 into child issues for schema, auth/RBAC, SaaS onboarding, billing,
  provider API, WHMCS, and website copy.
- Define non-negotiable guardrails for self-hosted mode and DNS read-only
  defaults.

### Phase 2: Organization and Entitlement Foundation

Outcome: local data model can represent SaaS, ISP, and self-hosted modes.

- Add organization/account model above workspaces.
- Add subscription, billing account, entitlement, usage record, provider
  integration, and billing event models.
- Backfill existing installs into a default organization and default workspace.
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

- Complete Kubernetes HA work.
- Add migration job pattern.
- Document SLOs, backup/restore, retention, support access, and incident
  response for SaaS/provider modes.
- Run production-like failover and restore drills.

## GitHub Tracking

- [Issue #12](https://github.com/christianlouis/dmarq/issues/12): auth,
  multi-user, SaaS, ISP/OEM, subscription, billing, and entitlement roadmap.
- [Issue #206](https://github.com/christianlouis/dmarq/issues/206):
  Kubernetes host-loss high availability.

Recommended child issues for #12:

- Organization/account schema and migration.
- Entitlements and plan limits.
- Workspace RBAC enforcement.
- Invite/member management UI.
- Stripe Billing integration.
- Provider billing state and monthly usage exports.
- Provider provisioning API.
- WHMCS module.
- Domain Connect templates.
- Website copy update for self-hosted, SaaS, and ISP modes.
