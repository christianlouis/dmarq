# DMARQ Development Roadmap

Last updated: 2026-05-23

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

## Completed Milestone: Production Hardening

Objective: make self-hosted deployments safer.

Delivered:
- Documented a 1Password secret-injection deployment flow for local, Docker Compose, and systemd deployments.
- Redacted secret-like values from mail-source diagnostics, stored import history, OAuth error logs, and validated admin auth contexts.
- Added production startup validation for stable secrets, configured auth, auth-disabled mode, and Logto TLS verification.
- Added database backup and restore guidance for SQLite and PostgreSQL deployments.
- Added a release checklist covering migrations, tests, smoke checks, release automation, and rollback readiness.

Quality bar:
- A self-hosted deployment can be configured without copying secrets into source-controlled files or chat logs.

Follow-up:
- Use the production hardening docs in at least one real production upgrade and capture any gaps.

## Later Milestones

- Notifications and alert rules. Apprise delivery, test notifications, alert-rule evaluation, scheduled daily/weekly summaries, and alert history are in place.
- DNS health and Cloudflare read-only inspection.
- Guided setup and operator health screens.
- Forensic/RUF report support.

See [milestones.md](../milestones.md) for the full milestone breakdown and exit criteria.

## Roadmap Extension (Beyond the Current Milestones)

The milestone breakdown in `docs/milestones.md` is intentionally focused on exit criteria. This section adds a product-oriented view: a feature landscape (themes), priority, and a tentative release plan for what comes after the currently defined scope.

### Feature Landscape (Themes)

**Standards & coverage**
- Track DMARC report format changes and keep parsing/export stable across real-world variants.
- Expand to adjacent email-auth posture checks where that directly helps operators take action.

**Ingestion & reliability**
- Add connectors (notably Microsoft 365) and higher-volume import patterns.
- Improve import observability (auditable outcomes), retention controls, and backfill ergonomics.

**Remediation & change management**
- Strengthen DNS posture guidance and close the loop from “finding” to “fix plan”.
- Keep provider integrations read-only by default, with explicit and auditable change workflows when enabled.

**Integrations & automation**
- Add APIs and webhooks to feed security and operations workflows (SIEM, ticketing, chatops).

**Governance (teams / MSP)**
- Workspaces, domain ownership, audit trails, and operator-friendly management for multi-org deployments.

**Optional AI + MCP**
- Opt-in, privacy-preserving assistance for summarization and remediation planning.
- Provide a clean automation surface for agents (read-only first).

### Priority (Now / Next / Later)

- **Now**: finish Milestones 8–9 (DNS health guidance + setup/ops polish).
- **Next**: Milestones 10–12 (failure reports, DMARC format compatibility, Microsoft 365 ingestion).
- **Later**: Milestones 13–16 (posture suite beyond DMARC, public API/webhooks, MSP/workspaces, AI/MCP).

### Tentative Release Plan (Subject to Change)

| Release | Target window | Primary milestones |
| --- | --- | --- |
| `0.4.0` | 2026 Q3 | 8–9 |
| `0.5.0` | 2026 Q4 | 10–11 |
| `0.6.0` | 2027 Q1 | 12 |
| `0.7.0` | 2027 Q2 | 13–14 |
| `0.8.0` | 2027 Q3 | 15–16 |

Notes:
- Releases are planned as *themes*, not promises; reprioritize based on what production deployments surface.
- “AI + MCP” is explicitly opt-in and should default to safe, privacy-preserving, read-only behavior.

### Roadmap Tracking (GitHub)

- Release plan: #167
- Milestone 8: #158
- Milestone 9: #161
- Milestone 10: #166
- Milestone 11: #129
- Milestone 12: #133
- Milestone 13: #138
- Milestone 14: #143
- Milestone 15: #148
- Milestone 16: #153
