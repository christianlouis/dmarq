# Changelog

All notable changes to DMARQ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added the versioned DMARQ agent-installation contract and `dmarqctl` control
  surface for machine-readable host preflight, idempotent Compose environment
  bootstrap, browserless first-run setup, secret-safe output, and bounded
  release/intake readiness status.
- Added a supported Kubernetes Helm chart with existing-Secret references,
  bundled or external PostgreSQL, persistence, ingress, health probes, safe
  production defaults, and an idempotent browserless setup Job.
- Added a provisioner-free Terraform module for declarative Kubernetes install,
  upgrade, drift detection, and destroy, plus a disposable-cluster CI acceptance
  path that exercises the complete lifecycle.

### Fixed
- Made a selected but unconfigured Akamai ETP, Infoblox, or custom DNS profile
  explicitly degrade to Public DNS for read-only lookups. Settings and setup
  now show the deployment configuration still required, while domain DNS and
  DANE checks retain fallback evidence instead of failing with HTTP 500.
- Kept the bundled PostgreSQL workload least-privileged but bootable by granting
  only the five capabilities required by the official Alpine image to prepare
  its data directory and drop from root to the `postgres` user.
- Restored sender ASN, network, and country enrichment when a selected private
  DNS resolver is unavailable by falling back to independent public DNS and
  Cloudflare DoH for Team Cymru lookups. Failed enrichments now retry after a
  short cache interval instead of remaining unknown for a full day.
- Reduced dashboard and domain-detail information density without removing
  workflows: health and remediation now lead with one concise status and next
  action, analytics and evidence stay folded until requested, and queue metrics,
  evidence, DNS, sender intelligence, reports,
  migration, and audit context remain directly available through progressive
  disclosure and the existing domain-section navigation.
- Kept public-demo exploration honest and consistent by disabling write controls
  in the browser, matching dashboard intake status to seeded mail sources, and
  returning read-only ownership context instead of a broken demo-domain 404.
- Aligned Dashboard and Reports rolling presets to inclusive UTC calendar days,
  compacted all-time domain rows, and added usable report cards plus complete
  loading, error, and empty states on small screens.
- Removed the provider-console organization-summary N+1 query pattern by
  batching workspaces, billing, subscriptions, entitlements, and active seat
  usage, with a query-count regression test across multiple tenants.
- Added a contextual Billing & Plan action when a provider operator reaches a
  customer seat limit, including structured `plan_limit_exceeded` API errors.
- Recorded the inherited Debian `perl-base` CVEs as a time-bounded security risk
  acceptance with required controls, a review deadline, and explicit exit
  conditions instead of silently suppressing scanner results.
- Classified four historical secret-scanner findings as synthetic test fixtures
  and baselined only their exact fingerprints, leaving all new secret findings
  visible to GitGuardian and Gitleaks.
- Enabled `no-new-privileges` in the supported Docker Compose application
  service so inherited base-image packages cannot gain additional privileges.
- Published `docker-stable`, `docker-latest`, immutable release, and short-SHA
  images for both Linux AMD64 and ARM64, and made the release gate reject an
  incomplete architecture manifest before promotion.
- Distinguished active failing DKIM selectors from active passing, recent,
  historical, and manually configured evidence. Only current selector failures
  now enter the primary DNS remediation flow; rotation history remains visible
  with first/last seen dates and report/message counts under progressive
  disclosure.
- Expanded standalone Docker greenfield verification beyond health checks to
  cover first-run setup, deterministic DMARC fixture ingestion, exact totals,
  duplicate rejection, application-container recreation, and persisted state.
- Kept provider support-session user selection CSP-safe and resolved the
  selected user by ID before stale email fallback state, so multi-user account
  impersonation opens the customer view for the operator's actual selection.
- Kept workspace-scoped status and navigation reads available during long
  SQLite mailbox backfills by avoiding no-op legacy workspace migration writes.
- Kept Docker and Kubernetes HTTP readiness independent from scheduled mailbox
  scans by moving blocking connector work off the application event loop and
  delaying the first cycle until startup completes.
- Recognized common provider subjects such as `Report domain:` during IMAP
  connection tests, ignored unrelated archives without parse-error noise, and
  parsed quoted Gmail folder names correctly.
- Restored report-detail and forensics interactions under strict CSP and kept
  each DKIM remediation card tied to its matching selector.
- Stopped remediation queues from advertising provider previews when the
  connector exists but its credentials are not configured; manual DNS guidance
  remains available until a provider connection is ready.
- Labeled the dashboard health score as traffic-weighted so a high-volume
  healthy domain cannot visually hide the separate count of domains needing
  attention.

### Added
- Added unattended Microsoft 365 shared-mailbox ingestion through Entra
  application permissions, including tenant-specific client credentials,
  explicit mailbox targeting, folder discovery, connection tests, manual and
  scheduled imports, backfills, encrypted secrets, and Exchange Online RBAC
  safety guidance without requiring a redirect URI or interactive user.
- Added state-aware self-hosted onboarding that recognizes existing domains,
  mailbox health, imported evidence, DNS-provider credentials, and notification
  setup, then routes operators to the first required incomplete step instead of
  reopening a blank setup form.
- Added one dashboard next-action surface with report-backed domain scope,
  explicit scheduled-import state, and progressively disclosed analytics so
  remediation or mailbox recovery leads before secondary metrics.
- Added report investigation summaries and provider/network source clusters,
  with failing traffic first, compact IP evidence, paginated raw records, and
  destructive report deletion moved into an overflow menu.
- Clarified domain-remediation priority so active DMARC and sender-alignment
  blockers lead while optional BIMI, MTA-STS, and TLS posture work is identified
  as secondary when no higher-impact issue is active.
- Added honest, incremental IMAP backfill diagnostics with checked, recognized,
  new, existing, ignored, and warning counts plus persisted polling progress.
- Replaced the wide Mail Sources account table with responsive account rows,
  a clear Import action, direct historical backfill access, and progressively
  disclosed connection, history, edit, and delete controls.
- Simplified the first-run information hierarchy without removing capabilities:
  the core navigation now leads with dashboard, domains, reports, mail sources,
  and settings; specialized tools remain available under More and Advanced;
  dashboard, settings, and domain detail views expose one clear next action
  before expandable diagnostic, remediation, migration, and provider context.
- Hardened fresh-install and domain workflows for small screens and strict CSP,
  including responsive action headers, contained horizontal content, safe
  nested-data rendering, and working empty-domain visibility controls.
- Added a published-image Docker installation path with generated persistent
  secrets, an internal-only PostgreSQL service, a clean-host verification
  script, registry-image smoke tests, and separate `docker-stable`,
  `docker-latest`, and local source-build channels.
- Added a zero-knowledge greenfield deployment checklist covering setup, DMARC
  fixture ingestion, persistence, Gmail IMAP acceptance, duplicate handling,
  scheduled polling, and the Kubernetes runtime contract.
- Added a product-backed site-manager console at `/provider` with risk-sorted
  customer accounts, domain/report/user/billing drill-down, persistent provider
  provisioning, active plan selection, and mobile account cards.
- Added explicit provider-operator allowlisting and an opt-in, non-destructive
  starter plan bootstrap for fresh persistent ISP/MSP installations.
- Added signed, time-boxed customer support sessions with a required reason,
  target-user RBAC, fixed workspace scope, customer-visible start/end audits,
  persistent context banner, and return-to-provider flow.
- Added an idempotent relational provider-demo seed covering six organizations,
  plans, billing, entitlements, users, memberships, domains, reports, imports,
  health histories, and audit activity.
- Added separate read permissions for customer membership and mail-source status
  so read-only support sessions can inspect configuration without mutating it.
- Added provider-demo workflow polish with an operator checklist, tenant-health
  queue, selected-tenant next action, and a demo-only audited support-session CTA.
- Added provider-demo host routing so multi-user demo deployments start on the
  provider workflow instead of the single-user dashboard.
- Added clearer Settings next-step CTAs, section navigation, local save
  guidance, folded advanced areas, and visible labels for the desktop icon rail.
- Added a separately gated `/provider-demo` surface for ISP/MSP and multi-tenant demo workflows, keeping the self-hosted dashboard demo focused on the single-user story.
- Added focused regression coverage for reputation-feed configuration,
  TLS-report serialization, and TLSA parsing edge cases.
- Added a Settings account/access milestone readiness summary for #12, separating completed auth/workspace/billing/provider foundations from environment-specific setup gates.
- Added mail-source authorization health signals to poll status, operations health, and dashboard intake status so expired or incomplete Gmail OAuth connections request reauthorization instead of appearing simply connected.
- Added recovery diagnostics to manual dashboard mail polling results so failed Gmail/Microsoft 365 imports surface the likely action, such as reconnecting the mailbox.
- Added early Gmail backfill reauthorization checks when a source has no refresh token, preventing long-running backfills from failing later with opaque provider errors.
- Documented shipped mail-health surfaces separately from future roadmap work
  so health scoring, evidence exports, read-only API/MCP access, and sender
  reputation no longer read as purely future features.
- Added in-product release metadata with version, image, git ref, build date, recent changes, and a link to the full changelog.
- Added a domain-level DMARC/SPF/DKIM mail-authentication wizard entry point that renders generated target records as ordered setup steps.
- Added an explicit AI redaction mode for operators who want to preserve email addresses and domains in AI context while still protecting secrets and opaque tokens.
- Added Cloudflare OAuth rights profiles for read-only zone import, read-only plus Radar enrichment, and full DNS repair.
- Added configurable mail-authentication setup defaults so generated DMARC/TLS-RPT guidance can use central report mailboxes.
- Added source intelligence context for sending IPs, including provider recognition, network details, Radar links, and report activity history.
- Added human-approved DNS repair groundwork for provider-connected domains.
- Added self-hosted demo refinements focused on the single-user, multiple-domain workflow.
- Added richer remediation-loop verification context, including priority bands, risk labels, safe-automation flags, verified-fixed totals, and next-check evidence for resolved items that no longer appear in the active queue.
- Added a domain remediation queue refresh control and expandable evidence-verified repair list for operators reviewing historical fixes.
- Added explicit remediation repair-progression context so each queue item shows whether it is preview-ready, blocked by a prerequisite, waiting for sender classification, manual-only, or pending fresh verification evidence.
- Added remediation action-plan decision checkpoints and rollback guidance so operators can review evidence freshness and recovery paths before approving or closing a repair.
- Added remediation verification closure gates and stale-evidence warnings so resolved items are not confused with evidence-verified repairs.
- Added queue-level closure-gate and rollback-guidance counters to highlight remediation items that still need fresh evidence or a recovery path.
- Added remediation repair-readiness levels, scores, reasons, and blockers so operators can distinguish preview-ready work from manual, blocked, classification, and reputation-review work.
- Added first-screen remediation freshness and closure-gate context so the top domain action panel shows what evidence must be current before closure.
- Added top-panel remediation evidence controls so operators can open the relevant evidence section or run the safe read-only evidence refresh without scrolling.
- Added verified-repair freshness counters so stale or unknown repair-history evidence is visible before opening individual entries.
- Added dashboard remediation verification freshness and closure gates so workspace cards match domain-level repair semantics.
- Added dashboard remediation verification plans in the API so workspace cards and domain queue cards share the same closure semantics.
- Added dashboard remediation verification counters for operator approval, sender review, reputation review, fresh-evidence checks, and missing provider values.
- Added dashboard remediation verification badges, failure modes, and evidence-needed summaries to keep closure guidance visible on each card.
- Added dashboard remediation summary breakdowns for approval waits, sender/reputation review, manual evidence checks, and missing provider values.
- Added dashboard remediation filters for approval verification, sender review, and report-evidence follow-up work.
- Added explicit domain-detail remediation state labels so approval-ready items do not expose raw internal state names.
- Added top-level domain remediation verification status, evidence-needed, and failure-mode context before the full remediation queue.
- Added next-remediation readiness context and verified-repair freshness gates so operators see the next safe action before opening or closing remediation work.
- Added dashboard remediation-card readiness reasons, blockers, and next-safe-action text so operators can triage fixes before opening the domain queue.
- Added dashboard remediation sorting, last-refresh context, a queue refresh control, and domain remediation filters for preview-ready, blocked, evidence-gated, manual, and reputation-review work.
- Added domain remediation queue sorting by priority, repair readiness, or severity, plus filters for notification-ready and operator-waiting work.
- Added an expandable domain remediation queue view so operators can open every matching item instead of only seeing the compact six-item list.
- Added fresh-evidence refresh paths to remediation items so operators can see whether DNS, reports, source intelligence, reputation, or provider values must be refreshed before closure.
- Added dashboard fresh-evidence counters and remediation-card refresh paths so workspace triage shows whether DNS, reports, reputation, or provider prerequisites should be handled next.
- Added dashboard remediation filters, sorting, compact/show-all controls, and matching empty states so operators can triage large remediation workspaces by preview readiness, fresh evidence, blockers, manual work, or reputation review before opening a domain.
- Added clearer dashboard remediation filter chips with compact counts, empty-filter affordances, and hover text that explains what each filtered queue would show.
- Added domain remediation fresh-evidence and provider-value queue filters plus freshness sorting so closure-blocking evidence work is easier to isolate on domain detail pages.
- Added stale-evidence remediation filters and direct dashboard links into the relevant domain evidence section, such as DNS records or sending sources.
- Fixed dashboard remediation state rendering so backend `approval_ready` queue items are labeled as needing approval and evidence anchors fall back safely if malformed.
- Added report-detail reputation filters and record-level reputation next steps so risky, listed, authentication-review, unchecked, and clean source records can be isolated without leaving the report.
- Added sending-source risk filters, compact reputation counters, activity badges, and logarithmic recent-volume bars on domain detail pages so current risky senders stand out from stale or low-volume history.
- Added domain-list DNS state badges for queued, cached, fallback, partial, stale, and failed DNS evidence so resolver uncertainty is visible instead of silently degrading scores.
- Added explicit remediation provider-repair plans so DNS queue items show preview availability, apply-after-approval readiness, apply blockers, provider-value prerequisites, record metadata, and manual fallback without changing live DNS behavior.
- Added remediation provider repair checklists so DNS repair items show before-apply checks, after-apply evidence checks, blast radius, and operator warnings before any provider write path is exposed.
- Added a domain remediation filter and summary counter for provider repair checklists so operator-review work can be isolated quickly.
- Added remediation provider apply-confirmation metadata and attempt-history placeholders so future live DNS repair controls have an explicit confirmation phrase, blocker list, and audit-trail slot before any write behavior is enabled.
- Added dashboard remediation notification profiles and payload previews so workspace filters can identify approval, manual-action, and investigation notifications from backend data before dispatch previews are attached.
- Added a dashboard remediation notification summary card so approval, manual-action, investigation, and summary-only notification profiles are visible before dispatch activity exists.
- Added domain-list remediation notification badges so per-domain approval, action, and investigation profiles are visible before dispatch activity exists.
- Added domain-list remediation notification totals so profile and summary-only counts match the dashboard notification summary card.
- Added dashboard stuck-work remediation filtering and next-action callouts so blocked provider values, apply prerequisites, dispatch blockers, and verification prerequisites are visible before opening a domain.
- Added remediation follow-up aging on dashboard cards and domain rows so stale operator follow-up is visible before opening a queue.
- Added an aging follow-up remediation filter and overdue styling so operator follow-up older than 24 hours or 7 days is easier to triage.
- Added aging follow-up counts to the dashboard health summary, dispatch activity card, and domain rows so stale manual work is visible without opening the remediation queue.
- Changed the dashboard dispatch follow-up sort to put older operator follow-ups ahead of fresher follow-ups within the same dispatch state.
- Added filter-specific empty states to the dashboard remediation cards so empty filter views explain the next useful operator action.
- Added a dashboard remediation empty-state reset control so operators can return from an empty filtered view to the full remediation card list.
- Added remediation empty-state context showing how many dashboard remediation cards exist outside the selected empty filter.
- Added domain remediation refresh result messages and clearer empty-queue states so operators can tell whether no work is open, recent verified repairs exist, or data has not loaded yet.
- Added domain remediation filter chip counts, empty-filter styling, and explanatory labels so queue filters behave consistently with dashboard remediation filters.
- Added remediation-loop completion gates on the dashboard and domain queue so parent roadmap issues are only considered ready after priority, evidence, action-plan, automation, approval, verification, notification, and summary criteria are represented.

### Changed
- Changed the dedicated provider-demo shell to use provider-specific navigation
  and the Sofia Weber site-manager persona instead of inheriting the single-user
  DMARQ navigation and local-admin identity.
- Changed the provider demo data contract from mixed organizations/workspaces to
  persisted provider-owned customer accounts so every drill-down uses the same
  scoped product APIs as a normal customer session.

- Domain detail, reports, and onboarding pages now lead with clearer primary
  CTAs, move secondary actions into overflow/progressive disclosure, and give
  empty/error states an explicit next step.
- Settings and workspace onboarding defaults now load existing rows in bulk,
  avoiding per-item database lookups while preserving idempotent setup behavior.
- Domain summary DNS refreshes now run with bounded concurrency instead of resolving each domain sequentially.
- Startup DNS cache prewarming now prioritizes domains with observed reports and message volume before empty monitored domains.
- Cloudflare OAuth profile selection now controls the requested scopes instead of being overridden by the legacy static scope setting.
- The full Cloudflare DNS repair profile now requests DNS write access plus Radar read access so one-click repair and IP enrichment can work from the same consent flow.
- Dashboard and domain detail pages now expose more actionable remediation context around DNS, DMARC, source authentication, and ownership state.
- Remediation queues now expose incident families, loop state, priority scores, operator decisions, and provider/self-hosted/manual tracks across the domain detail UI, public API, and MCP.
- Domain remediation cards now explain the verification method, freshness requirement, failure mode, and operator decision summary before an item can be treated as fixed.
- Dashboard remediation cards now use the same priority-band, remediation-track, risk, and operator-decision language as the domain detail queue.
- Domain remediation actions now capture optional operator notes and show every notification dispatch blocker instead of only the first reason.
- Domain remediation cards now show confidence and prerequisite context before the operator opens or approves a repair.
- Dashboard action-plan cards now deep-link to the selected domain remediation queue instead of the generic domain overview.
- Remediation queue summaries now expose hidden verified-repair counts separately from the visible compact list.
- Remediation notification payloads now include the same repair-progression gates shown in the UI, keeping webhook/ticket previews aligned with human review.
- Domain remediation pages now show repair-progression gates in the top next-remediation panel and render preview/verification states as operator-readable labels.
- Dashboard remediation-loop cards now expose the same repair-gate language and workspace counters for preview-ready, evidence-gated, and blocked repair work.
- Dashboard and domain remediation views now show repair-readiness counters and per-item readiness scores before an operator opens or dispatches remediation work.
- Dashboard, domain remediation queue, and sending-source reputation refreshes now keep previously loaded evidence visible while a manual refresh runs.
- Dashboard remediation rows now expose the top incident and fresh-evidence action directly in the workspace view, and the domain-compliance refresh control reloads the backend summary again.
- Domain remediation cards now offer focused read-only evidence refresh actions that reload the relevant backend data and rebuild the queue without applying DNS or provider writes.
- Public API and read-only MCP remediation queues now strip provider preview/apply endpoints from both item data and notification payload previews while keeping read-only provider-repair context visible.
- Public API and read-only MCP remediation queues now label provider repair approval gates as read-only and warn that provider write endpoints are intentionally omitted.
- Dashboard remediation notification filters now treat backend notification profiles as ready-to-notify candidates instead of requiring a dispatch preview object on every workspace card.
- Public API and read-only MCP remediation queues now also clear provider apply confirmation phrases and mark confirmation metadata as read-only blocked.
- Domain remediation provider-repair cards now show the operator confirmation prompt and current provider-apply history state alongside the existing pre/post apply checks.
- Domain remediation provider-repair cards now render provider apply audit entries with provider, record, timestamp, verification status, and detail when history exists.
- Domain remediation queues now include a provider-history filter so previously recorded provider apply attempts can be isolated from preview-only work.
- Dashboard remediation filters now mirror provider apply, apply-blocked, and provider-history states from domain remediation queues.
- Dashboard remediation summaries now count provider previews, apply-after-approval items, blocked applies, and missing provider values.
- Dashboard remediation summaries and domain rows now also surface provider apply attempts and verified provider applies.
- Dashboard remediation summaries and domain rows now surface notification dispatches and operator follow-up activity.
- Dashboard remediation cards can now be filtered and sorted by notification dispatch readiness, dispatched work, operator follow-up, and dispatch blockers.
- Dashboard remediation filters now receive a larger bounded working set from the backend instead of only the first compact card page.
- Domain remediation rows now show the latest operator or dispatch activity label and timestamp beside the active remediation workload.
- Domain remediation queue summaries now count provider apply attempts and verified provider applies from audit history.
- Reorganized repository: moved development docs (`AGENTS.md`, `ROADMAP.md`, `ISSUE_GENERATION_SUMMARY.md`, `generated_issues/`) into `docs/`
- Added root-level `CHANGELOG.md` and `TODO.md`
- Cleaned up root directory for clarity

### Fixed
- Fixed the greenfield Compose deployment contract so documented ports,
  database credentials, CORS parsing, setup behavior, health checks, and image
  selection match the running containers without undocumented maintainer input.
- Fixed provider drill-down for suspended customers so an exactly scoped,
  read-only support session can still inspect customer domains, organizations,
  and members without reactivating the tenant or permitting mutations.
- Fixed support-target defaults and labels so the console prefers a primary
  workspace owner and shows the role that will actually govern the customer
  session, instead of defaulting to a limited billing or analyst identity.
- Fixed provider support sessions leaking standalone demo statistics, TLS,
  forensic, mail-source, and DNS-policy fixtures into customer-scoped views.
- Fixed provider customer provisioning lookups after organization slug
  normalization and persisted initial domain and billing fields atomically.
- Fixed the provider console header showing an unrelated customer workspace
  selector and injecting that workspace into global provider API requests.
- TLSA parsing now preserves association data that contains whitespace after the
  first three TLSA fields, with focused tests for malformed and warning cases.
- Aggregate and TLS report pages now keep the last loaded data visible when a manual refresh or API retry fails.
- Retired stale roadmap issue-generator guidance and made the docs-site
  changelog point at the canonical root changelog.
- Fixed remediation verified-repair totals so older resolved items are counted
  from the latest lifecycle marker instead of a capped audit-row scan.
- Fixed domain posture scoring so optional MTA-STS/BIMI gaps stay visible as actions without collapsing otherwise healthy DMARC/SPF/DKIM domains to an F-grade impression.
- Fixed Docker release metadata so the in-product build SHA, ref, and date come from the checked-out image source instead of the workflow trigger commit.
- Fixed Cloudflare OAuth recovery so invalid-scope callbacks offer a read-only retry path and stale legacy scopes such as `user.read` are filtered from DMARQ-generated requests.
- Fixed report detail views so sender-IP reputation appears as a dedicated score and assessment column instead of being buried in source metadata.
- Fixed sending-source reputation visibility so checked age, listed/feed evidence, and recommended next steps are shown beside the source rows operators already review.
- Fixed DNS fallback behavior so independent public resolvers are checked in parallel before a transient timeout can make records appear missing.
- Fixed domain sending-source loading so PTR and network enrichment run in parallel instead of pushing report-backed source rows past the UI timeout.
- Fixed the remediation queue API schema so `repair_progression` is preserved in typed domain remediation responses.
- Fixed dashboard and domain remediation refresh failures so transient backend errors no longer blank already-loaded operator evidence.
- Fixed domain-list refresh failures so a transient DNS/API error no longer clears the previously loaded domain rows.
- Fixed sending-source refresh failures so existing source rows remain visible during date-window or reputation refresh retries.
- Fixed source-intelligence refresh failures so previously loaded region and anomaly evidence stays visible while the retry warning is shown.
- Fixed the Cloudflare permissions picker so selecting the full DNS repair profile no longer falls back to read-only scopes.
- Fixed the release modal coverage so recent operator-facing work is visible from inside the app.
- Fixed the remaining Settings page startup hook so CSP hardening no longer depends on template-level page initialization.
- Fixed several CSP-hardening regressions by moving legacy inline handlers, explicit page initialization, and styles out of templates.

### Security
- Cloudflare DNS write capabilities remain tied to explicit full-repair selection and human-confirmed DNS changes.
- Release metadata is sanitized for display and does not expose secrets.
- Domain-specific DMARC aggregate-report mailbox overrides now feed DNS lint and
  the mail-authentication wizard before falling back to the workspace default.
- The default browser policy no longer allows inline scripts; Alpine expression
  compatibility still keeps `unsafe-eval` until the CSP runtime migration is
  complete.

## [0.3.0] - 2026-02-09

### Added
- Database persistence with SQLAlchemy ORM (SQLite and PostgreSQL support)
- Database migrations with Alembic
- Persistent storage replacing in-memory data store

### Security
- Fixed missing authentication on admin endpoints (CRITICAL)
- Replaced default SECRET_KEY with secure auto-generation (CRITICAL)
- Replaced ElementTree with defusedxml to prevent XXE attacks (HIGH)
- Fixed IMAP credentials exposure in URL query parameters (HIGH)
- Added multi-layer file upload validation (HIGH)
- Added security headers middleware (CSP, X-Frame-Options, HSTS, etc.) (MEDIUM)
- Restricted CORS configuration (MEDIUM)
- Sanitized error responses to prevent information disclosure (MEDIUM)
- Added comprehensive security test suite

## [0.2.0] - 2026-01-15

### Added
- IMAP integration for automatic DMARC report fetching
- Background task scheduler for periodic mailbox polling
- IMAP configuration UI with connection testing
- Manual sync trigger and status indicators

## [0.1.0] - 2025-12-01

### Added
- Initial release of DMARQ
- DMARC XML report parsing (supports XML, ZIP, and GZIP formats)
- In-memory storage of report data for up to 5 domains
- Simple dashboard UI showing DMARC compliance statistics
- Report upload via web interface
- Domain overview with compliance rates and email statistics
- Docker Compose deployment support
- FastAPI backend with Jinja2 templates and Tailwind CSS
