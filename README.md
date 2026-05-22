# DMARQ

**DMARQ** is a modern, privacy-conscious DMARC monitoring and analysis platform built for professionals who want deep visibility into their email authentication posture — without giving up control or relying on third-party SaaS providers.

🌐 [Live Demo (soon)](https://app.dmarq.org)  
🔒 Self-hosted. Secure. Beautifully visual.  
🛠️ Docker-deployable. DNS posture checks with optional Cloudflare inspection.
📬 Aggregate report support (failure/forensic reports planned).

---

## 💡 What is DMARQ?

DMARQ ingests and visualizes DMARC (Domain-based Message Authentication, Reporting & Conformance) reports — primarily aggregate (RUA) reports today — to help domain owners understand who is sending emails on their behalf and whether those messages are properly authenticated using SPF and DKIM.

No more guessing. See which services are passing DMARC, which are failing, and how to fix them — all in one clear dashboard.

---

## 🚀 Current Status (Milestones 1–8 Complete)

DMARQ currently supports end-to-end aggregate DMARC monitoring with mailbox ingestion, persistence, reporting, DNS checks, and notifications.

Included:

- ✅ DMARC aggregate XML report parsing (XML, ZIP, GZIP)
- ✅ Upload ingestion + mailbox ingestion (IMAP + Gmail OAuth)
- ✅ Database persistence (SQLite/PostgreSQL) + migrations
- ✅ Dashboard trends, domain timelines, and sender/source analytics
- ✅ Import history + backfills for mail sources
- ✅ Alerts & notifications via Apprise (test send, alert rules, daily/weekly summaries)
- ✅ DNS checks (DMARC/SPF/DKIM) with DKIM selector discovery from report data
- ✅ Cloudflare read-only domain discovery, DNS inspection, recommendations, and change tracking

Up next:

- 🔜 Setup and operations polish (Milestone 9)
- 🧊 Failure/forensic report support (RUF) (Milestone 10)

---

## ✨ Key Features

### 📊 Dashboard & Reports
- **DMARC Compliance Rate**: Track pass/fail rates over time
- **Volume & Trends**: Identify traffic spikes and anomalies
- **Top Sending Sources**: Detect unknown or unauthorized senders
- **Actionable Recommendations**: Prioritize what to fix next
- **Export**: CSV export for selected domains and date ranges

### 🛡 DNS Record Health
- Inspect **SPF**, **DKIM**, and **DMARC** records
- Discover likely **DKIM selectors** from report data
- Show which records are missing, broken, or invalid
- 🔒 No automatic changes — all DNS updates require explicit confirmation (when remediation workflows are added)

### 🌐 Cloudflare Integration
- Optional read-only domain discovery and DNS inspection
- Import Cloudflare zones as monitored domains from Settings
- Suggestions for missing or malformed entries
- Track configuration changes over time

### ⚙️ Web-Based Setup Wizard (Planned / In Progress)
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

- ✅ **Milestones 1–8**: Parsing, ingestion (upload/IMAP/Gmail), persistence, reporting, notifications, production hardening, DNS health, Cloudflare read-only inspection
- 🔜 **Milestone 9**: Setup and operations polish
- 🧊 **Milestone 10**: Failure/forensic report support (RUF)
- 🧠 **Milestones 11–16**: DMARC format compatibility, Microsoft 365 ingestion, broader email posture, APIs/webhooks, workspaces/MSP, AI/MCP (see docs)

See the full [Roadmap](docs/development/roadmap.md) and [Milestones](docs/milestones.md).

---

## 📘 License

MIT License — you are free to use, modify, and host DMARQ for any purpose.

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue to discuss major features or design ideas before submitting code. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

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
