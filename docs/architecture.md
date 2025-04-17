# DMARQ – Architecture & Tech Stack Overview

**Project:** DMARQ  
**Host:** https://app.dmarq.org  
**Purpose:** Self-hosted, full-featured DMARC monitoring tool with support for Cloudflare integration, alerting, and visual dashboards.

---

## 🧱 System Architecture

DMARQ uses an integrated architecture with:

- **Unified Backend** (FastAPI with Jinja2 templates)
- **Modern UI** (Jinja2 + Tailwind CSS + shadcn/ui)

The application is deployed via Docker with a PostgreSQL database storing parsed reports, domain configurations, DNS snapshots, and user information.

Optional services (e.g., Apprise for alerts) are included via container or integrated via API calls.

---

## 🧩 Tech Stack

| Component           | Stack / Tooling                             |
|--------------------|---------------------------------------------|
| **Frontend**        | Jinja2 Templates + HTMX + Tailwind CSS + shadcn/ui |
| **Charts**          | Chart.js with Alpine.js integration         |
| **Routing/Auth**    | FastAPI routing + JWT auth (FastAPI Users)  |
| **Backend**         | FastAPI + SQLAlchemy                        |
| **ORM & DB**        | SQLAlchemy ORM, PostgreSQL                  |
| **IMAP**            | `imap-tools`, `aioimaplib`                  |
| **DMARC Parsing**   | `defusedxml`, `lxml`, `zipfile`, `mail-parser` |
| **Cloudflare API**  | `cloudflare` Python SDK or raw REST client |
| **DNS Resolution**  | `dnspython`                                 |
| **Authentication**  | FastAPI Users (JWT + optional OAuth later) |
| **Alerting**        | [Apprise](https://github.com/caronc/apprise) |
| **Testing**         | `pytest`, `coverage`, `pytest-mock`         |
| **CI/CD (optional)**| GitHub Actions, Docker Hub                  |
| **Deployment**      | Docker, Docker Compose                      |
| **Config Mgmt**     | `dynaconf` (ENV + DB integration)           |

---

## 📦 Application Structure

```
dmarq/
├── app/
│   ├── api/               # REST API endpoints (v1)
│   ├── core/              # App config, security, constants
│   ├── models/            # SQLAlchemy ORM models
│   ├── services/          # Mail parsing, DNS, CF integrations
│   ├── static/            # CSS (Tailwind), JS, images
│   │   ├── css/           # Generated Tailwind styles
│   │   ├── js/            # Alpine.js and other frontend scripts
│   │   └── img/           # Images and icons
│   ├── tasks/             # Scheduled tasks (polling, DNS sync)
│   ├── templates/         # Jinja2 templates
│   │   ├── components/    # Reusable UI components
│   │   ├── dashboard/     # Dashboard views
│   │   ├── layouts/       # Base layouts
│   │   ├── reports/       # Report-specific templates
│   │   └── wizard/        # Setup wizard templates
│   ├── tests/             # Unit + integration tests
│   └── main.py            # FastAPI application entrypoint
├── Dockerfile
├── docker-compose.yml
├── config/
│   └── seed_env.py        # Load ENV vars into DB
├── .env.example
├── README.md
└── ARCHITECTURE.md
```

---

## 🌐 Functional Modules

### 1. **Config Wizard (Web-Based)**
- First step of app usage
- Collects:
  - Admin user creation
  - IMAP mailbox login
  - Cloudflare API token
  - Optional alert channels
- Saves config into DB
- Optionally seeded from `.env`

---

### 2. **Email Processing**
- IMAP polling for inbox (e.g. `dmarc@yourdomain.com`)
- Download zipped aggregate XML or forensic reports
- Parse with validation and deduplication
- Store:
  - Reporting org
  - Source IPs, volume
  - SPF/DKIM result
  - Applied disposition (none, quarantine, reject)
  - Forensics: failed messages, sample data

---

### 3. **Cloudflare DNS Sync**
- List zones and domains via API
- Pull DNS records:
  - DMARC
  - SPF
  - DKIM
  - MX
  - BIMI (optional)
- Validate correctness and format
- Generate actionable **fix suggestions**
- DNS updates require manual user approval

---

### 4. **Alerting (via Apprise)**
- Alert on:
  - New forensic reports
  - New source IPs failing SPF/DKIM
  - Compliance drops (configurable)
- Supports:
  - Email
  - Slack
  - Discord
  - Webhooks
  - Matrix
- Configurable via web wizard and/or user dashboard

---

### 5. **User Authentication**
- FastAPI Users backend
- JWT token auth
- Server-side sessions with secure cookies
- Admin-only access to DNS fix or config modules

---

## 🧪 Testing Strategy

- **Unit Tests:** All parsing, validation, config, services
- **Mock External Services:** IMAP, Cloudflare, DNS
- **Frontend:** Testing Jinja templates with pytest-html
- **E2E (later):** Playwright or Selenium

Run with:
```bash
docker compose exec app pytest
```

---

## 🧑‍🎨 UI Implementation

### Frontend Technology

DMARQ uses an integrated approach with:

1. **Jinja2 Templates**: Server-side rendering of HTML
2. **Tailwind CSS**: Utility-first CSS framework for styling
3. **shadcn/ui**: Component library adapted for server-rendered templates
4. **Alpine.js**: Minimal JavaScript framework for enhanced interactivity
5. **HTMX**: For AJAX requests without writing JavaScript
6. **Chart.js**: For data visualization components

This approach offers several advantages:
- Eliminates API-related complexity
- Reduces JavaScript bundle size
- Improves initial page load performance
- Simplifies deployment (single container)
- Server-side rendering improves SEO

### UI Components Structure

- **Layouts**: Base templates that define the page structure
- **Components**: Reusable UI elements like cards, tables, and forms
- **Pages**: Full page templates for dashboard, reports, settings, etc.

The components follow shadcn/ui design patterns but are implemented as Jinja2 macros or includes rather than React components.

---

## 🧑‍🎨 Branding & UI Design

- **Logo:** Stylized shield with "Q" + monogram "D+Q"
- **Colors:**
  - Deep Blue `#1A237E`
  - Teal `#00ACC1`
  - Orange `#FF7043`
  - Light Gray `#F5F5F5`, Dark Gray `#212121`
- **Fonts:** Montserrat (headings), Open Sans (body)
- **Style:** Minimal, modern, flat icons — inspired by EasyDMARC

---

## 🚧 Known Constraints

- Single-instance deployment (no horizontal scaling)
- Target performance: 50–100 domains per instance
- Database optimization is secondary
- Multitenancy is not supported (yet)

---

## 📘 License

Apache License 2.0 — Free for personal or commercial use with attribution.

**License Compatibility:**  
All major dependencies and tools used in DMARQ (including FastAPI, SQLAlchemy, Tailwind CSS, shadcn/ui, Alpine.js, HTMX, Chart.js, Apprise, and others) are distributed under permissive licenses (MIT, BSD, Apache 2.0, ISC, or similar) and are compatible with the Apache 2.0 license.

---

This document serves as the technical foundation for the implementation of DMARQ.