# TODO

This file tracks the delta between what the documentation promises and what is
actually implemented in the codebase. Use it as a guide for future development.

For the full development roadmap, see [docs/development/roadmap.md](docs/development/roadmap.md).
For detailed milestone specifications, see [docs/milestones.md](docs/milestones.md).

---

## Implemented (Working)

These features are documented and confirmed working in the codebase:

- [x] **DMARC Aggregate Report Parsing** — XML, ZIP, and GZIP formats supported
      via `defusedxml` (`backend/app/services/dmarc_parser.py`)
- [x] **Database Persistence** — SQLAlchemy ORM with SQLite and PostgreSQL support,
      Alembic migrations (`backend/app/core/database.py`, `backend/app/models/`)
- [x] **Report Upload** — Web interface for uploading DMARC reports with multi-layer
      file validation (`backend/app/api/api_v1/endpoints/reports.py`)
- [x] **IMAP Integration** — Auto-fetch reports from mailbox with background
      scheduler (`backend/app/services/imap_client.py`)
- [x] **Basic Dashboard** — Domain overview with compliance stats, Chart.js
      visualizations on domain detail page (`backend/app/templates/`)
- [x] **Security Hardening** — Authentication middleware, security headers (CSP,
      HSTS, X-Frame-Options), defusedxml for XXE protection, restricted CORS,
      sanitized error responses (`backend/app/middleware/security.py`,
      `backend/app/core/security.py`)
- [x] **Docker Deployment** — Docker Compose setup for production deployment
      (`docker-compose.yml`, `backend/Dockerfile`)
- [x] **Setup Wizard** — Basic guided onboarding endpoints, though in-memory only
      (`backend/app/api/api_v1/endpoints/setup.py`)

---

## Documented but NOT Implemented

The following features are described in the README, documentation, or roadmap but
have no working implementation in the codebase yet.

### Cloudflare Integration
- **Documented in**: README.md ("Cloudflare-integrated"), docs/development/roadmap.md (Milestone 8)
- **Current state**: Configuration variables exist in `backend/app/core/config.py`
  (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`) but no functional code uses them.
- [ ] Automatic domain discovery from Cloudflare account
- [ ] Fetch and analyze DNS records via Cloudflare API
- [ ] Suggest missing or malformed DNS entries
- [ ] Track configuration changes over time

### Alerts & Notifications (Apprise)
- **Documented in**: README.md ("Integration with Apprise"), docs/development/roadmap.md (Milestone 6)
- **Current state**: `apprise>=1.4.5` is listed in `backend/requirements.txt` but
  is never imported or used anywhere in the codebase.
- [ ] Apprise integration for multi-channel notifications
- [ ] Email, Slack, webhook alert delivery
- [ ] Alert on new failures, compliance drops, or unknown senders
- [ ] Customizable alert rules and notification preferences
- [ ] Alert history and management

### Forensic Reports (RFC 6591)
- **Documented in**: README.md ("Forensic Reports: Analyze failure samples (RFC 6591 support)")
- **Current state**: The DMARC parser (`backend/app/services/dmarc_parser.py`) only
  handles aggregate reports. There is no forensic report parsing, UI, or storage.
- [ ] Forensic report parsing
- [ ] Failure sample analysis
- [ ] PII redaction options
- [ ] Detailed authentication failure views

### DNS Record Health Checks
- **Documented in**: README.md ("Inspect SPF, DKIM, DMARC, MX, and BIMI records"),
  docs/development/roadmap.md (Milestone 8)
- **Current state**: The `/api/v1/domains/{domain_id}/dns` endpoint
  (`backend/app/api/api_v1/endpoints/domains.py`) returns hardcoded mock data.
  `dnspython>=2.3.0` is in `requirements.txt` but is never imported or used.
- [ ] Real DNS lookups for SPF, DKIM, DMARC, and MX records
- [ ] BIMI record support (zero code exists)
- [ ] Identify missing, broken, or invalid records
- [ ] Provider-specific fix suggestions (Google, Microsoft, etc.)
- [ ] DNSSEC validation

### User Authentication & Multi-User Support
- **Documented in**: README.md ("Built-in authentication via FastAPI Users"),
  docs/development/roadmap.md (Milestone 5)
- **Current state**: A `User` model exists (`backend/app/models/user.py`) and
  `fastapi-users[sqlalchemy]` is in requirements, but FastAPI-Users is never wired
  up. There are no registration, login, or password-reset endpoints. Admin auth is
  API-key based only.
- [ ] User registration and login endpoints
- [ ] JWT-based session authentication for end users
- [ ] Password reset functionality
- [ ] Role-based access control (RBAC) per domain
- [ ] Multi-factor authentication (MFA)
- [ ] Email verification

### Dashboard Visualizations (Real Data)
- **Documented in**: README.md ("Track pass/fail rates over time", "Volume & Trends")
- **Current state**: Stats endpoints (`backend/app/utils/stats_summarizer.py`,
  `backend/app/api/api_v1/endpoints/domains.py`) now query real data from the
  database and in-memory ReportStore. Chart.js visualizations display actual
  compliance trends derived from uploaded DMARC reports.
- [x] Historical trend charts with real data
- [x] Compliance rate visualizations from actual reports
- [x] Volume and sender analytics based on stored data
- [x] Time-series data from database
- [x] Domain comparison views

### Advanced Rule Engine
- **Documented in**: docs/development/roadmap.md (Milestone 7)
- **Current state**: Not implemented at all.
- [ ] Custom alert conditions
- [ ] Threshold-based triggers
- [ ] New sender detection
- [ ] Anomaly detection

### Advanced Analytics & Reporting
- **Documented in**: docs/development/roadmap.md (Milestone 10)
- **Current state**: Not implemented at all.
- [ ] Historical trend analysis
- [ ] Comparative reporting
- [ ] Export capabilities (PDF, CSV)
- [ ] Scheduled reports
- [ ] Custom dashboards

### Enterprise Features
- **Documented in**: docs/development/roadmap.md (Milestone 11)
- **Current state**: Not implemented at all.
- [ ] Multi-tenant architecture
- [ ] API rate limiting (beyond basic)
- [ ] Advanced RBAC
- [ ] SSO integration (SAML, OAuth)
- [ ] Compliance reporting (SOC 2, GDPR)

### Real-Time Features
- **Documented in**: README.md ("real-time insights")
- **Current state**: No WebSocket or real-time push functionality exists.
- [ ] WebSocket or SSE for live dashboard updates

---

## Partially Implemented

### Setup Wizard
- **Status**: Endpoints exist (`/api/v1/setup/status`, `/api/v1/setup/admin`,
  `/api/v1/setup/system`) but store data in memory only. Not persisted to database.
- [ ] Persist setup configuration to database
- [ ] Complete guided onboarding flow in the UI

### IMAP Credential Security
- **Status**: IMAP integration works but credential storage needs improvement.
- [ ] Encrypt IMAP credentials at rest
- [ ] Add vault integration for secure credential storage
- [ ] Audit logging for IMAP operations

---

## Housekeeping

- [ ] Remove unused `apprise` from `requirements.txt` or implement alerts
- [ ] Remove unused `dnspython` from `requirements.txt` or implement DNS checks
- [ ] Remove or wire up `fastapi-users` (currently installed but unused)
- [x] Replace mock data in stats endpoints with real database queries
- [ ] Replace mock DNS data with actual DNS lookups
- [ ] Add CI/CD pipeline
- [ ] Reach >80% test coverage
