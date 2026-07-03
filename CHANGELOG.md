# Changelog

All notable changes to DMARQ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added a DMARC aggregate-report mailbox default so generated DNS guidance can use a central `rua=mailto:` address instead of always defaulting to `dmarc@<domain>`.
- Added in-product release metadata with version, image, git ref, build date, recent changes, and a link to the full changelog.
- Added Cloudflare OAuth rights profiles for read-only zone import, read-only plus Radar enrichment, and full DNS repair.
- Added source intelligence context for sending IPs, including provider recognition, network details, Radar links, and report activity history.
- Added human-approved DNS repair groundwork for provider-connected domains.
- Added self-hosted demo refinements focused on the single-user, multiple-domain workflow.

### Changed
- Cloudflare OAuth profile selection now controls the requested scopes instead of being overridden by the legacy static scope setting.
- The full Cloudflare DNS repair profile now requests DNS write access plus Radar read access so one-click repair and IP enrichment can work from the same consent flow.
- Dashboard and domain detail pages now expose more actionable remediation context around DNS, DMARC, source authentication, and ownership state.
- Reorganized repository: moved development docs (`AGENTS.md`, `ROADMAP.md`, `ISSUE_GENERATION_SUMMARY.md`, `generated_issues/`) into `docs/`
- Added root-level `CHANGELOG.md` and `TODO.md`
- Cleaned up root directory for clarity

### Fixed
- Fixed report detail views so sender-IP reputation appears as a dedicated score and assessment column instead of being buried in source metadata.
- Fixed DNS fallback behavior so independent public resolvers are checked in parallel before a transient timeout can make records appear missing.
- Fixed domain sending-source loading so PTR and network enrichment run in parallel instead of pushing report-backed source rows past the UI timeout.
- Fixed the Cloudflare permissions picker so selecting the full DNS repair profile no longer falls back to read-only scopes.
- Fixed the release modal coverage so recent operator-facing work is visible from inside the app.
- Fixed several CSP-hardening regressions by moving legacy inline handlers and styles out of templates.

### Security
- Cloudflare DNS write capabilities remain tied to explicit full-repair selection and human-confirmed DNS changes.
- Release metadata is sanitized for display and does not expose secrets.

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
