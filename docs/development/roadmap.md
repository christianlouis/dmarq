# DMARQ Development Roadmap

Last updated: 2026-05-22

This roadmap tracks implementation status and near-term engineering priorities. The project has moved beyond the initial MVP and now needs production-grade import visibility, better reporting, and hardened operations.

## Current Status

Complete:
- Core DMARC aggregate parsing for XML, ZIP, and GZIP reports.
- Secure XML parsing with `defusedxml`.
- Upload validation and archive safety checks.
- IMAP mailbox ingestion.
- Gmail OAuth ingestion.
- Persistent database models and migrations for domains, reports, records, settings, users, and mail sources.
- Domain, report, settings, and mail source APIs.
- Dashboard and domain detail views.
- Logto auth integration and local development auth-disabled mode.
- DNS resolver foundation and DNS-related endpoint tests.

Recently improved:
- Gmail ingestion now matches the real Google DMARC report messages found in the connected inbox.
- Gmail import now uses the same parser path as uploads and IMAP.
- Gmail and IMAP imports now skip duplicate domain/report IDs.
- Tests cover Google-style DMARC ZIP attachment imports.
- Mail source imports now create sanitized import-history records for manual and scheduled polls.
- Parsed upload, Gmail, and IMAP reports are now persisted to `dmarc_reports` and `report_records`.
- Report/domain API reads can hydrate the dashboard projection from persisted data after restart.
- Mail source import history is visible in the Mail Sources UI.
- Individual mail sources can be manually imported from the Mail Sources UI.
- Import-history rows include sanitized per-attachment outcomes and imported report IDs.
- Mail source backfills can be launched from the UI with configurable search windows.
- The current Alpine-based UI is allowed by CSP and renders dynamic tables in real browsers.
- Sending-source summaries now retain SPF, DKIM, DMARC, and disposition pass/fail totals per IP instead of showing only the latest result.

Implementation note:
- The legacy `ReportStore` remains as a projection layer for existing report/dashboard code, but durable report data now lives in the database.

## Completed Milestone: Meaningful Reports

Objective: turn parsed DMARC data into administrator-friendly reports.

Delivered:
- Dashboard time-series charts show daily mail volume, compliance rate, and failure rate.
- Top sending sources show DMARC, SPF, and DKIM pass/fail breakdowns on the dashboard.
- Per-domain timelines include daily volume, pass, fail, compliance-rate, and failure-rate rollups.
- Domain reports can be exported to CSV for a selected date range.
- Source reports include actionable recommendations for unknown sources, SPF-only passes, DKIM-only passes, full failures, and unenforced policies.
- What changed summaries identify newly observed senders and sudden compliance drops.

Quality bar:
- A domain owner can understand who sends mail as their domain, which sources fail, and what to fix next.

## Completed Milestone: Reporting Quality and Import Confidence

Objective: make mailbox imports auditable and make report totals trustworthy.

Delivered:
- Duplicate skips are reported separately from parse failures.
- Import history exposes per-attachment results and sanitized errors.
- Individual sources can be manually imported and backfilled from the UI.
- Source rollups track pass/fail counts over time by sender IP.

Quality bar:
- Importing the same mailbox twice does not change aggregate totals, parse failures are visible, and source totals are not overwritten by the latest result.

## Production Hardening

Objective: make self-hosted deployments safer.

Priority tasks:
- Document a 1Password secret-injection deployment flow.
- Keep raw secrets out of diagnostics, logs, and UI responses.
- Add startup validation for production settings.
- Add backup and restore documentation.
- Add a release checklist covering migrations, tests, and smoke checks.

## Later Milestones

- Notifications and alert rules with Apprise.
- DNS health and Cloudflare read-only inspection.
- Guided setup and operator health screens.
- Forensic/RUF report support.

See [milestones.md](../milestones.md) for the full milestone breakdown and exit criteria.
