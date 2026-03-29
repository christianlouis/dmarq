# Changelog

All notable changes to DMARQ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This changelog is automatically maintained by
[python-semantic-release](https://python-semantic-release.readthedocs.io/).
See the root [CHANGELOG.md](https://github.com/christianlouis/dmarq/blob/main/CHANGELOG.md)
for the canonical version.

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