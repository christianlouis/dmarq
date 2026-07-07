# DMARQ

**DMARQ** is a modern, privacy-conscious mail health platform built for
professionals who want to understand and improve domain sending posture without
giving up control of their reports, DNS, and infrastructure.

- 🌐 [Live Demo](https://demo.dmarq.org)
- 🔒 Self-hosted. Secure. Beautifully visual.
- 🛠️ Docker-deployable. DNS posture checks with optional, approved DNS remediation.
- 📬 Aggregate, forensic/failure, and SMTP TLS report support.

---

## 💡 What is DMARQ?

DMARQ ingests and visualizes DMARC (Domain-based Message Authentication,
Reporting & Conformance) reports — primarily aggregate (RUA) reports today — to
help domain owners understand who is sending emails on their behalf and whether
those messages are properly authenticated using SPF and DKIM.

The product direction is broader than reporting alone: DMARQ should become a
human-in-the-loop mail health assistant. It observes DMARC and mail-delivery
signals, explains what is unhealthy, prepares safe fixes, and tells the operator
what changed. Automatic detection and guidance are encouraged; hidden DNS or
mail-server changes are not.

No more guessing. See which services are passing DMARC, which are failing, which
senders may be risky, and how to fix the underlying issue — all in one clear
dashboard.

---

## 🚀 Current Status

DMARQ currently focuses on parsing reports and helping operators configure and
lint DMARC-related DNS settings. It supports aggregate DMARC monitoring,
failure/forensic samples, SMTP TLS reports, mailbox ingestion, persistence,
reporting, DNS checks, and notifications.

Included:

- ✅ DMARC aggregate XML report parsing (XML, ZIP, GZIP)
- ✅ Upload ingestion + mailbox ingestion (IMAP + Gmail OAuth)
- ✅ Database persistence (SQLite/PostgreSQL) + migrations
- ✅ Dashboard trends, domain timelines, and sender/source analytics
- ✅ Import history + backfills for mail sources
- ✅ Alerts & notifications via Apprise (test send, alert rules, daily/weekly summaries)
- ✅ DNS checks (DMARC/SPF/DKIM) with DKIM selector discovery from report data
- ✅ DNS linting, change plans, approved Cloudflare writes, and modular provider write adapters
- ✅ Forensic/failure report ingestion with redacted metadata and grouped analysis
- ✅ SMTP TLS report ingestion, trends, and top failure summaries
- ✅ Best-effort passive DANE/TLSA MX checks with bounded live probing and read-only TLSA suggestions
- ✅ Public demo mode with rolling synthetic `dmarq.org` and `dmarq.com` data
- 🔭 Roadmap: deeper human-approved repair loops, DNS/mail provider imports,
  direct report intake workers, ecosystem integrations, richer reputation feeds,
  and localized remediation guidance

Protocol boundary:

- **Supported now:** DMARC aggregate reports, inbound DMARC failure/RUF reports,
  SMTP TLS/TLS-RPT reports, DMARC/SPF/DKIM DNS linting, MTA-STS, BIMI, and
  best-effort passive DANE/TLSA guidance with bounded live probing.
- **Passive context only:** ARC headers found in failure-report samples are
  retained as redacted diagnostics, but DMARQ does not validate ARC chains or
  use ARC as a substitute for DMARC alignment.
- **Out of scope today:** outbound ARF/RUF generation and receiver-side report
  rate limiting. DMARQ consumes reports for domain operators; it is not a mail
  receiver generating third-party reports.

---

## ✨ Key Features

### 📊 Dashboard & Reports
- **DMARC Compliance Rate**: Track pass/fail rates over time
- **Volume & Trends**: Identify traffic spikes and anomalies
- **Top Sending Sources**: Detect unknown or unauthorized senders
- **Forensic Reports**: Review redacted failure samples and grouped diagnoses
- **SMTP TLS Reports**: Track TLS-RPT sessions, failures, and affected domains
- **Actionable Recommendations**: Prioritize what to fix next
- **Export**: CSV export for selected domains and date ranges

### 🛡 DNS Record Health
- Inspect **SPF**, **DKIM**, and **DMARC** records
- Discover likely **DKIM selectors** from report data
- Show which records are missing, broken, or invalid
- Generate risk-reviewed change plans with rollback notes
- Apply safe TXT/CNAME remediation through Cloudflare after explicit confirmation
- Use the modular DNS provider layer for API-backed providers via Lexicon-backed adapters
- 🔒 No background changes — all DNS updates require explicit operator confirmation

### 🧭 Mail Health Direction
- **Health Score & Grade**: Make domain sending health visible at a glance
- **Evidence History & Exports**: Keep score history, report evidence, and
  export paths available for audit and migration workflows
- **Human-in-the-loop Repair**: Detect automatically, explain clearly, apply only after approval
- **Provider & Self-hosted Guidance**: Work for Google/Microsoft/Postmark/SES-style senders and custom MTAs
- **Sender Reputation**: Surface blacklist and reputation risks for sending IPs
- **Localized Advice**: Make remediation guidance understandable to the operator receiving it

### 🌐 Cloudflare Integration
- Optional domain discovery, DNS inspection, and approved DNS record updates
- Import Cloudflare zones as monitored domains from Settings
- Suggestions for missing or malformed entries
- Track configuration changes over time

### 🧪 Public Demo Mode
- `DEMO_MODE=true` seeds deterministic, rolling demo data for `dmarq.org` and `dmarq.com`
- Demo data fills the dashboard, domain details, DNS posture, aggregate reports,
  forensic reports, TLS reports, exports, and linting views
- The public demo presents the self-hosted, single-user, multi-domain experience
- Account-management, ISP, and multi-tenant demos live behind the separate
  `/provider-demo` surface and require `PROVIDER_DEMO_ENABLED=true`
- A guided dashboard tour walks through the opinionated product flow from domain
  posture to sender evidence and DNS remediation
- The public demo is read-only so visitors can explore without modifying data

### ⚙️ Web-Based Setup Wizard
- Guided onboarding experience (no CLI setup required)
- Store all configuration in a secure internal database
- Seed config with environment variables for headless deployment

### 🚨 Alerts & Notifications
- Integration with [Apprise](https://github.com/caronc/apprise)
- Email, Slack, webhook, and more
- Alert on new senders, compliance drops, elevated failures, or missing reports
- Daily and weekly DMARC summaries
- Alert history for active and resolved alerts

### 🔐 Authentication
- Logto-based authentication integration
- Explicit auth-disabled mode for local development

---

## 🚀 Getting Started

You can deploy DMARQ in minutes using Docker Compose:

```bash
git clone https://github.com/YOUR_USERNAME/dmarq.git
cd dmarq
cp .env.example .env
docker compose up --build
```

Then visit [http://localhost](http://localhost) to access the dashboard and upload your DMARC reports.

### Development Setup

For development without Docker:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

Then visit [http://localhost:8080](http://localhost:8080)

---

## 🚨 Integration with Apprise

DMARQ sends notifications through Apprise target URLs configured in
**Settings** > **Notifications**. Add one target URL per line, enable
notifications, and use **Send Test** to verify delivery. Target URLs are
encrypted in the database and redacted in API responses. Apprise supports email,
Slack, Teams, Discord, generic webhooks, and many other targets.

Notification settings include alert-rule toggles and thresholds for:

- New sending sources
- Compliance-rate drops
- DMARC failures above a daily threshold
- Missing reports for monitored domains

DMARQ can also send daily and weekly summaries. Use **Preview Summary** to see
the current summary payload, **Send Summary Now** for an immediate message, and
the daily/weekly toggles to enable scheduled delivery. Outbound messages are
rate-limited by the configured cooldown and email addresses are redacted by
default before delivery.

Alert history is available in **Settings** > **Notifications** after alerts have
been evaluated or sent. History rows track active/resolved status, first seen,
last seen, observed count, and alert metadata. Notification and alert-rule
configuration changes are recorded in the configuration audit trail without
storing raw notification secrets.

See [Settings](docs/user_guide/settings.md) and
[Configuration](docs/deployment/configuration.md) for examples and available
settings.

---

## 📦 Requirements

- DMARC aggregate reports (XML, ZIP, or GZIP format)
- Docker + Docker Compose (for production deployment)
- Python 3.13+ (for development)

---

## 🧭 Development Roadmap

DMARQ's product scope is deliberately focused: parse standards-based reports,
explain the results, and help operators improve DMARC-adjacent DNS and mail
sending health. Future work should strengthen that loop rather than turn DMARQ
into a general-purpose mail gateway or a hidden automation platform.

Current shipped surfaces include health scoring, A-F style posture grading,
score history, evidence exports, sender/source analytics, reputation indicators,
and read-only public API/MCP access for evidence-linked automation.

The active roadmap is organized around:

- **Trustworthy report ingestion and DNS linting**
- **Prioritized, human-approved DNS and provider repair workflows**
- **Provider discovery, domain imports, and direct report intake**
- **Deeper sender identity, commercial reputation feeds, and blacklist monitoring**
- **API/MCP automation beyond the current read-only scope**
- **Localized guidance, starting with German as the first non-English target**

See the full [Roadmap](docs/development/roadmap.md) and [Milestones](docs/milestones.md).
The [Ecosystem Integration Matrix](docs/reference/ecosystem-integrations.md)
tracks where DNS providers, mail services, hosting panels, report intake,
ticketing/chatops, SIEM, identity, and automation belong in the product.

---

## 📘 License

MIT License — you are free to use, modify, and host DMARQ for any purpose.

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue to discuss major features or design ideas before submitting code. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

Roadmap feedback is especially useful around provider integrations, DNS repair
safety, reputation data sources, localization, and real-world migration paths
from commercial DMARC tools.

This project uses [Conventional Commits](https://www.conventionalcommits.org/) and
[python-semantic-release](https://python-semantic-release.readthedocs.io/) for
automated versioning and changelog generation.

---

## 🛡 Why DMARQ?

Unlike most commercial DMARC tools, DMARQ gives you:
- 🔍 Full visibility without third-party access to your reports
- 🧠 Intelligence-driven suggestions, not just raw data
- 🎨 A beautiful, intuitive dashboard with actionable insights
- 💻 Self-hosted flexibility with modern developer practices

Let's build better email security — together.
