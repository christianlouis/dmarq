# DMARQ Milestones

Last updated: 2026-05-23

DMARQ is now past the original MVP phase. The current product can parse DMARC aggregate reports, import reports from mailboxes, persist data, and present domain/report summaries through the FastAPI/Jinja application. The next work should focus on making ingestion more reliable at production scale and turning the collected data into clearer operational reports.

## Milestone 1: Core DMARC Report Processing - Complete

Status: Complete

Delivered:
- DMARC aggregate XML parsing with namespace support.
- ZIP and GZIP report extraction.
- Upload endpoint for XML, ZIP, and GZIP reports.
- Upload safety checks for file type, file size, and compressed archive size.
- Domain/report summary storage and duplicate upload rejection.
- Parser and upload tests for valid, invalid, compressed, namespaced, and oversized reports.

## Milestone 2: Mailbox Ingestion - Complete

Status: Complete

Delivered:
- IMAP mail source configuration and connection testing.
- IMAP polling for DMARC attachments.
- Gmail OAuth mail source support.
- Gmail search query tuned for real DMARC report mail, including Google messages with subjects such as `Report domain: <domain> Submitter: google.com`.
- Gmail import fixed to use the shared parser path.
- Duplicate report protection for both Gmail and IMAP imports.
- Background polling and manual poll hooks for configured mail sources.

## Milestone 3: Database Foundation, Domain Management, and Auth Foundation - Complete

Status: Complete

Delivered:
- SQLAlchemy models and Alembic migrations.
- SQLite/PostgreSQL-compatible database configuration.
- Domain management APIs and UI.
- Report and source database models.
- Database-backed persistence for uploaded DMARC reports.
- Database-backed persistence for Gmail and IMAP imported reports.
- Duplicate report detection against persisted report data.
- Report/domain API reads can hydrate their dashboard projection from persisted reports after restart.
- Settings and mail source persistence.
- Logto-based auth integration plus an explicit local development auth-disabled mode.
- Security middleware, safer default secret generation, and security-focused tests.

Implementation note:
- The existing `ReportStore` remains as a compatibility projection for dashboard/report code, but persisted database rows are now the durable source for uploads and mailbox imports.

## Milestone 4: Reporting Quality and Import Confidence - Complete

Status: Complete

Goal: make reports trustworthy for day-to-day administration and make import failures obvious.

Delivered:
- Gmail import now handles real inbox metadata patterns and Google-style ZIP filenames.
- Gmail/IMAP imports skip duplicate report IDs to avoid inflated totals.
- Tests now cover a real Google-style ZIP attachment path rather than only mocked parser behavior.
- Mail source imports now persist sanitized import-history records for manual and scheduled polls.
- Uploaded, Gmail-imported, and IMAP-imported reports are now persisted to report/record tables and can be reloaded into report/domain views.
- Mail source import history is now visible from the Mail Sources UI.
- A single mail source can be manually imported from the Mail Sources UI, with the result recorded in import history.
- Import history now includes per-attachment details for imported reports, duplicates, parse errors, unsupported attachments, and imported report IDs.
- Mail sources can be backfilled from the UI with 7-day, 30-day, 90-day, or custom search windows.
- The current Alpine-based UI can run under the configured CSP, so dynamic tables render in real browsers.
- Source aggregation now keeps per-sender-IP SPF, DKIM, DMARC, and disposition totals instead of overwriting each IP with only the latest result.

Exit criteria:
- A user can connect a mailbox, run a backfill, see exactly what was imported or skipped, and trust that totals are not double-counted.

## Milestone 5: Dashboard and Meaningful Reports - Complete

Status: Complete

Goal: convert raw DMARC data into useful operational reporting.

Delivered:
- Dashboard trend charts for volume, compliance rate, and failure rate.
- Top sender/source reports with pass/fail breakdowns.
- Per-domain report timeline and daily rollups.
- Exportable reports for a selected domain and date range.
- Clear recommendations for common cases: unknown source, SPF-only pass, DKIM-only pass, full fail, and policy not enforced.
- What changed summaries for newly observed sources and sudden compliance drops.

Exit criteria:
- A domain owner can answer: who is sending as my domain, what is failing, what changed recently, and what should I fix next?

## Milestone 6: Production Secret Handling and Deployment Hardening - Complete

Status: Complete

Goal: make production deployments safer and easier to operate.

Delivered:
- 1Password-based secret injection flow for local, Docker Compose, and systemd deployments.
- Raw mailbox/OAuth secrets are redacted from mail-source diagnostics, import history, and OAuth error logs.
- Admin authentication contexts no longer carry raw API keys after validation.
- Production startup checks now fail early for missing stable secrets, missing auth configuration, auth-disabled mode, or disabled Logto TLS verification.
- Database backup and restore guidance now covers SQLite and PostgreSQL deployments, restore verification, and upgrade safety checks.
- A release checklist now covers pre-merge checks, migrations, release automation, smoke checks, and rollback readiness.

Exit criteria:
- A self-hosted deployment can be configured without copying secrets into source-controlled files or chat logs.

## Milestone 7: Notifications and Alert Rules

Status: Complete

Goal: notify administrators when action is needed.

Delivered:
- Apprise notification integration for newline-separated notification target URLs.
- Notification settings UI can save Apprise targets, stores target URLs encrypted, keeps target URLs redacted after save, and can send a test notification.
- Alert rules for new sender source, compliance drop, DMARC failures above threshold, and missing reports.
- Notification settings UI can evaluate active alerts and send the current alert summary on demand.
- Daily and weekly DMARC summary notifications, including scheduled delivery and manual preview/send controls.
- Alert history records active and resolved alerts with first-seen, last-seen, observed-count, and payload metadata.
- Outbound notifications are rate-limited, email addresses are redacted by default, and notification configuration changes are audited without raw secrets.

Exit criteria:
- A user can receive meaningful alerts without opening the dashboard daily.

## Milestone 8: DNS Health and Guidance

Status: Complete

Goal: connect report findings with DNS configuration guidance.

Delivered:
- DMARC/SPF/DKIM DNS checks with database-backed cached results.
- DKIM selector discovery from report data.
- Per-domain DNS health summary.
- Cloudflare read-only integration for automatic domain discovery and DNS record inspection.
- Import Cloudflare zones as monitored domains from Settings.
- Suggestions for missing, duplicate, or malformed DMARC/SPF/DKIM records.
- DNS record snapshots and change history for Cloudflare-managed records, including additions, modifications, and removals.
- Suggestions for moving from `p=none` to enforcement when compliance supports it.

Exit criteria:
- A user can see whether DNS records match the actual senders observed in DMARC reports.

## Milestone 9: Setup and Operations Polish

Status: Delivered

Goal: make first-run setup, maintenance, and troubleshooting straightforward.

Delivered:
- First-run setup status is persisted in the database instead of only memory.
- Setup now surfaces a checklist for monitored domains, enabled mail sources, and system health.
- Monitored domains can be created before any DMARC report has arrived.
- Domain summaries and detail pages include manually configured domains with no report history yet.
- Health page and API show database connectivity, scheduler state, report totals, latest import, and latest successful import.
- Mailbox connection tests return sanitized diagnostic categories and recovery suggestions.
- Mail Sources UI shows actionable recovery steps for common ingestion/auth failures.
- Operator runbooks cover Docker Compose, Coolify, manual systemd, Kubernetes/GitOps, upgrades, rollback, routine checks, and troubleshooting.

Exit criteria:
- A new user can deploy DMARQ, connect a mailbox, and confirm the system is healthy without reading code.

## Milestone 10: Forensic Report Support

Status: Complete

Goal: support DMARC RUF/forensic reports for individual failure investigation.

Delivered:
- Detect forensic report messages.
- Parse safe metadata from ARF/attached email formats.
- Store minimal incident details with privacy controls.
- Configure forensic report redaction for balanced, domain-only, and strict views.
- Keep forensic reports out of aggregate report statistics and ReportStore rollups.
- Expose authenticated forensic upload/list/detail APIs.
- Provide dedicated forensic report list/detail views for authentication failure investigation.
- Add privacy-preserving failure sample analysis with grouped causes, priorities, signals, and recommended actions.

Exit criteria:
- A security analyst can inspect individual failure reports without mixing them into aggregate statistics.

## Milestone 11: DMARC Format Compatibility (DMARCbis) and Standards Alignment

Status: Complete

Goal: keep DMARQ compatible with evolving DMARC report formats and nomenclature without breaking existing imports.

Delivered:
- Add parser compatibility for RFC 9990-style aggregate report namespaces, version detection, policy metadata, identifiers, override reasons, auth-result details, and namespaced extensions.
- Keep legacy RFC 7489-style reports backward compatible through fixture coverage.
- Persist and CSV-export newly introduced aggregate metadata with nullable, backward-safe database fields.
- Add a fixture-driven compatibility pack covering parser, upload, IMAP, and Gmail import paths with supported-format documentation.
- Verify domain report views and CSV exports render fixture-backed DMARCbis-style imports correctly.

Exit criteria:
- A DMARCbis-style aggregate report can be imported via upload/IMAP/Gmail and renders correctly in dashboards and exports.

## Milestone 12: Enterprise Mail Sources (Microsoft 365) and Connector Framework

Status: In progress

Goal: make mailbox ingestion work for the most common enterprise setups without relying on IMAP.

Planned:
- Microsoft 365 mail source using OAuth (Graph) with least-privilege scopes. Delivered for delegated `User.Read`, `Mail.Read`, and `offline_access` with encrypted token storage, manual import, scheduled polling, UI setup, and operator docs.
- Shared mailbox and folder selection support for DMARC report collection. Delivered with shared mailbox targeting, Microsoft Graph folder listing, folder-id based imports, UI selection, and mailbox/folder context in import history.
- Import-history parity with existing sources (auditable attachment outcomes, duplicates, parse failures). Delivered for Microsoft 365 imports.
- Backfill support with safe throttling and progressive search windows. Delivered with days-based Graph `receivedDateTime` filters, duplicate-safe reruns, and retry/backoff for throttled or temporarily unavailable Graph requests.
- Secret handling mirrors existing guidance (no raw secrets in logs; 1Password-friendly). Delivered with a shared connector protocol, sanitized import-result helpers, duplicate ID serialization helpers, and connector development guidance for future sources.

Exit criteria:
- A user can connect an Exchange Online mailbox, run an initial backfill, and then run scheduled polls with visible and trustworthy import history.

## Milestone 13: Email Security Posture (Beyond DMARC)

Status: Complete

Goal: turn DMARQ into a broader email authentication posture console (still privacy-first and self-hostable).

Planned:
- MTA-STS posture: delivered cached `_mta-sts` TXT checks, HTTPS policy validation, domain-detail evidence, and operator guidance for missing, invalid, or non-enforcing policies. Optional helper tooling remains a future enhancement.
- TLS reporting posture: delivered authenticated TLS-RPT upload for `.json`, `.json.gz`, and `.zip` attachments; duplicate-safe persistence by report ID and policy domain; daily session trends; top failure-cause grouping; affected-domain summaries; and explicit privacy controls that avoid storing message content or recipient data.
- BIMI posture: delivered default-selector BIMI TXT validation, HTTPS logo/certificate URL checks, DMARC enforcement readiness checks, domain-detail evidence, and operator guidance for missing or blocked BIMI prerequisites.
- Posture dashboard and operator playbooks: delivered a per-domain posture score, coverage cards for DMARC/SPF/DKIM/MTA-STS/BIMI, evidence-linked recommendations, provider-backed DNS drift summaries, and short remediation playbooks.
- Extended DNS checks that support the posture surface (e.g., MX/BIMI; optional DANE/TLSA where relevant).

Exit criteria:
- An operator can see “what’s missing” and “what’s risky” across email-auth posture in one place, with clear next actions.

## Milestone 14: Public API, Webhooks, and Core Integrations

Status: In progress

Goal: let DMARQ integrate cleanly into existing security and operations workflows.

Planned:
- A stable, documented read-only API surface for posture and reporting queries. Delivered with scoped `reports:read`, `posture:read`, and `tls-reports:read` API tokens, public read-only endpoints, and per-token usage audit fields.
- Webhook event delivery for key events (new sender source, compliance drop, missing reports, alert lifecycle).
- Integration templates for SIEM and ticketing workflows (export formats, payload schemas, examples).
- Token/scoping model for API access that matches governance needs (service accounts, least privilege).

Exit criteria:
- A user can automate downstream workflows without scraping HTML or reverse-engineering internal APIs.

## Milestone 15: Workspaces / MSP Mode (Multi-Org Governance)

Status: Backlog

Goal: support multi-org deployments (e.g., MSPs) with strong isolation, ownership, and operator ergonomics.

Planned:
- Workspace/tenant concept with clear domain ownership.
- Workspace-scoped RBAC and audit logs.
- Templates for onboarding new workspaces (domains + mail sources + notifications).
- Cross-workspace operator views for MSP admins, without weakening tenant isolation.

Exit criteria:
- A single deployment can safely manage multiple client domains with clear boundaries and governance.

## Milestone 16: Optional AI + MCP Automation Layer

Status: Backlog

Goal: provide opt-in assistance and agent-friendly automation without compromising privacy or safety.

Planned:
- Evidence-first summaries and remediation plans that link back to the underlying DMARC data.
- Pluggable model provider support with strong redaction and “no secrets in prompts” guarantees.
- A DMARQ MCP server that starts read-only (posture queries, reports, recommendations).
- Optional action tools (e.g., proposing DNS changes) gated behind explicit human confirmation and audit logging.

Exit criteria:
- Users can enable AI/agent workflows intentionally, understand what data is shared, and keep deployments safe by default.
