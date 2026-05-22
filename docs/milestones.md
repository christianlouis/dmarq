# DMARQ Milestones

Last updated: 2026-05-22

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

Status: In progress

Goal: notify administrators when action is needed.

Delivered:
- Apprise notification integration for newline-separated notification target URLs.
- Notification settings UI can save Apprise targets, keeps target URLs redacted after save, and can send a test notification.

Planned:
- Alert rules for new sender source, compliance drop, DMARC failures above threshold, and missing reports.
- Daily/weekly summary notifications.
- Alert history.

Exit criteria:
- A user can receive meaningful alerts without opening the dashboard daily.

## Milestone 8: DNS Health and Guidance

Status: Planned

Goal: connect report findings with DNS configuration guidance.

Planned:
- DMARC/SPF/DKIM DNS checks with cached results.
- DKIM selector discovery from report data.
- Per-domain DNS health summary.
- Suggestions for moving from `p=none` to enforcement when compliance supports it.
- Optional Cloudflare read-only integration for DNS record inspection.

Exit criteria:
- A user can see whether DNS records match the actual senders observed in DMARC reports.

## Milestone 9: Setup and Operations Polish

Status: Planned

Goal: make first-run setup, maintenance, and troubleshooting straightforward.

Planned:
- Guided setup flow for domains and mail sources.
- Better mailbox test output and recovery suggestions.
- Health page for scheduler status, last successful import, and database connectivity.
- Operator documentation for Docker Compose and manual deployments.

Exit criteria:
- A new user can deploy DMARQ, connect a mailbox, and confirm the system is healthy without reading code.

## Milestone 10: Forensic Report Support

Status: Backlog

Goal: support DMARC RUF/forensic reports for individual failure investigation.

Planned:
- Detect forensic report messages.
- Parse safe metadata from ARF/attached email formats.
- Store minimal incident details with privacy controls.
- Add a dedicated forensic report view.

Exit criteria:
- A security analyst can inspect individual failure reports without mixing them into aggregate statistics.
