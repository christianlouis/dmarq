# Changelog

All notable changes to DMARQ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- Added next-remediation readiness context and verified-repair freshness gates so operators see the next safe action before opening or closing remediation work.
- Added dashboard remediation-card readiness reasons, blockers, and next-safe-action text so operators can triage fixes before opening the domain queue.
- Added dashboard remediation sorting, last-refresh context, a queue refresh control, and domain remediation filters for preview-ready, blocked, evidence-gated, manual, and reputation-review work.
- Added domain remediation queue sorting by priority, repair readiness, or severity, plus filters for notification-ready and operator-waiting work.
- Added an expandable domain remediation queue view so operators can open every matching item instead of only seeing the compact six-item list.
- Added fresh-evidence refresh paths to remediation items so operators can see whether DNS, reports, source intelligence, reputation, or provider values must be refreshed before closure.
- Added dashboard fresh-evidence counters and remediation-card refresh paths so workspace triage shows whether DNS, reports, reputation, or provider prerequisites should be handled next.
- Added dashboard remediation filters, sorting, compact/show-all controls, and matching empty states so operators can triage large remediation workspaces by preview readiness, fresh evidence, blockers, manual work, or reputation review before opening a domain.
- Added domain remediation fresh-evidence and provider-value queue filters plus freshness sorting so closure-blocking evidence work is easier to isolate on domain detail pages.
- Added stale-evidence remediation filters and direct dashboard links into the relevant domain evidence section, such as DNS records or sending sources.
- Fixed dashboard remediation state rendering so backend `approval_ready` queue items are labeled as needing approval and evidence anchors fall back safely if malformed.
- Added report-detail reputation filters and record-level reputation next steps so risky, listed, authentication-review, unchecked, and clean source records can be isolated without leaving the report.
- Added sending-source risk filters, compact reputation counters, activity badges, and logarithmic recent-volume bars on domain detail pages so current risky senders stand out from stale or low-volume history.
- Added domain-list DNS state badges for queued, cached, fallback, partial, stale, and failed DNS evidence so resolver uncertainty is visible instead of silently degrading scores.

### Changed
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
- Reorganized repository: moved development docs (`AGENTS.md`, `ROADMAP.md`, `ISSUE_GENERATION_SUMMARY.md`, `generated_issues/`) into `docs/`
- Added root-level `CHANGELOG.md` and `TODO.md`
- Cleaned up root directory for clarity

### Fixed
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
