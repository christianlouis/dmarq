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
- Persistent database models and migrations.
- Domain, report, settings, and mail source APIs.
- Dashboard and domain detail views.
- Logto auth integration and local development auth-disabled mode.
- DNS resolver foundation and DNS-related endpoint tests.

Recently improved:
- Gmail ingestion now matches the real Google DMARC report messages found in the connected inbox.
- Gmail import now uses the same parser path as uploads and IMAP.
- Gmail and IMAP imports now skip duplicate domain/report IDs.
- Tests cover Google-style DMARC ZIP attachment imports.

## Active Milestone: Reporting Quality and Import Confidence

Objective: make mailbox imports auditable and make report totals trustworthy.

Priority tasks:
- Persist import attempts with message ID, source, attachment filename, outcome, and sanitized error details.
- Show import history on mail source detail pages.
- Report duplicate skips separately from parse failures.
- Add backfill controls for Gmail and IMAP sources.
- Improve source rollups so a source IP tracks pass/fail counts over time.

Quality bar:
- Importing the same mailbox twice must not change aggregate totals.
- Parse failures must be visible and actionable.
- The user should be able to tell whether a mail source is healthy without reading logs.

## Next Milestone: Meaningful Reports

Objective: turn parsed DMARC data into administrator-friendly reports.

Priority tasks:
- Add time-series charts for volume and compliance.
- Add per-domain daily rollups.
- Add sender/source breakdowns with SPF, DKIM, and disposition counts.
- Add "what changed" summaries for newly observed senders and sudden compliance drops.
- Add exportable reports for a domain and date range.

Quality bar:
- A domain owner can understand who sends mail as their domain, which sources fail, and what to fix next.

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
