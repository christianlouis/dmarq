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

### Changed
- Cloudflare OAuth profile selection now controls the requested scopes instead of being overridden by the legacy static scope setting.
- The full Cloudflare DNS repair profile now requests DNS write access plus Radar read access so one-click repair and IP enrichment can work from the same consent flow.
- Dashboard and domain detail pages now expose more actionable remediation context around DNS, DMARC, source authentication, and ownership state.
- Remediation queues now expose incident families, loop state, priority scores, operator decisions, and provider/self-hosted/manual tracks across the domain detail UI, public API, and MCP.
- Domain remediation cards now explain the verification method, freshness requirement, failure mode, and operator decision summary before an item can be treated as fixed.
- Reorganized repository: moved development docs (`AGENTS.md`, `ROADMAP.md`, `ISSUE_GENERATION_SUMMARY.md`, `generated_issues/`) into `docs/`
- Added root-level `CHANGELOG.md` and `TODO.md`
- Cleaned up root directory for clarity

### Fixed
- Retired stale roadmap issue-generator guidance and made the docs-site
  changelog point at the canonical root changelog.
- Fixed remediation verified-repair totals so older resolved items are counted
  from the latest lifecycle marker instead of a capped audit-row scan.
- Fixed domain posture scoring so optional MTA-STS/BIMI gaps stay visible as actions without collapsing otherwise healthy DMARC/SPF/DKIM domains to an F-grade impression.
- Fixed Docker release metadata so the in-product build SHA, ref, and date come from the checked-out image source instead of the workflow trigger commit.
- Fixed Cloudflare OAuth recovery so invalid-scope callbacks offer a read-only retry path and stale legacy scopes such as `user.read` are filtered from DMARQ-generated requests.
- Fixed report detail views so sender-IP reputation appears as a dedicated score and assessment column instead of being buried in source metadata.
- Fixed DNS fallback behavior so independent public resolvers are checked in parallel before a transient timeout can make records appear missing.
- Fixed domain sending-source loading so PTR and network enrichment run in parallel instead of pushing report-backed source rows past the UI timeout.
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
