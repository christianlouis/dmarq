# Provider Console and Demo

DMARQ ships one provider workflow backed by the normal organization, workspace,
membership, domain, report, billing, subscription, entitlement, and audit models.
The dedicated provider demo and a production ISP/MSP installation use the same
console and support-session APIs; only data seeding and write policy differ.

## Deployment Profiles

### Dedicated provider demo

Use this profile only for a public synthetic demo:

```env
DEMO_MODE=true
PROVIDER_DEMO_ENABLED=true
MULTI_WORKSPACE_UI_ENABLED=true
PROVIDER_DISPLAY_NAME="Northstar ISP"
PROVIDER_SLUG="northstar-isp"
```

The startup hook idempotently seeds six synthetic customer organizations, their
workspaces, plans, billing accounts, subscriptions, entitlements, users,
memberships, domains, aggregate reports, import status, health history, and audit
events into the normal database tables. `/` redirects to `/provider-demo`.

Provider-side form changes are kept in browser session storage so visitors can
exercise the workflow without changing the seeded database. Customer support
sessions are signed and workspace-scoped but always read-only. DNS answers for
the synthetic `.example` domains are deterministic; live DNS/provider writes and
external mailbox polling remain disabled.

### Production provider installation

Use this profile for a persistent ISP/MSP deployment:

```env
DEMO_MODE=false
PROVIDER_DEMO_ENABLED=false
MULTI_WORKSPACE_UI_ENABLED=true
PROVIDER_DISPLAY_NAME="CKLNet"
PROVIDER_SLUG="cklnet"
PROVIDER_OPERATOR_EMAILS="operator@cklnet.com"
PROVIDER_BOOTSTRAP_DEFAULT_PLANS=true
```

Configure the normal production database, authentication, stable `SECRET_KEY`,
mail ingestion, and any DNS integrations separately. The provider entry point is
`/provider`. No synthetic customer data is created. Provider provisioning and
membership/billing actions write to the normal product tables and are audited.
Only identities listed in `PROVIDER_OPERATOR_EMAILS`, deployment admin
credentials, and properly scoped provider machine tokens can cross tenant
boundaries. `MULTI_WORKSPACE_UI_ENABLED` alone never grants site-manager access.
The optional plan bootstrap creates only missing plans and leaves an existing
catalog and custom prices untouched.

Keep `MULTI_WORKSPACE_UI_ENABLED=false` for a self-hosted single-workspace
installation that should not expose provider or workspace-management navigation.

## Site-Manager Workflow

`GET /api/v1/operator/provider-console` builds the account list directly from
persisted provider-billed organizations. Each account includes:

- lifecycle and health state, primary contact, plan, onboarding state, and next action;
- domain policy, report volume, authentication compliance, sources, and findings;
- active users, roles, MFA state, and eligible support-session targets;
- billing owner, invoice path/reference, billing contact, monthly amount, and limits;
- recent reports, import status, settings, and workspace audit activity.

The console can provision customer organizations through
`POST /api/v1/provider/customers`, including an initial workspace, plan, primary
domain, report mailbox, billing contact, invoice reference, and monthly price.
Active provider plans are supported; provider deployments are not limited to the
default starter plan. A fresh installation can opt into the default provider
catalog or manage its own persisted plans.

## Customer Support Sessions

`Kundenansicht öffnen` requires a target user and support reason, then calls:

- `POST /api/v1/operator/support-session` to start a signed, time-boxed session;
- `GET /api/v1/operator/support-session` to inspect the active session;
- `DELETE /api/v1/operator/support-session` to exit and return to the console.

The token binds operator, organization, workspace, target user, target role,
reason, customer number, and plan for 30 minutes. While active, the regular DMARQ
dashboard and APIs resolve as the selected customer user and force every request
to the token's workspace, even if a different workspace header is supplied.

The customer UI is the normal DMARQ product: dashboard, domains, reports,
forensics, TLS, members, onboarding, and settings. A persistent banner shows the
operator context, customer, target user, role, plan, reason, access mode, and exit
action. Support start and end are customer-visible workspace audit events.

Public provider demos force read-only access. A production provider operator may
request role-scoped access; the target user's normal RBAC still applies. Read-only
sessions can inspect membership and mail-source status but cannot invite users,
change roles, alter connectors, mutate domains, or perform provider/DNS writes.

## Safety Boundaries

- The provider console never uses the selected customer workspace switcher.
- Customer APIs remain constrained to one workspace for the full support session.
- Demo TLS/forensic/mail-source fixtures are not mixed into provider customers.
- Provider and DNS mutations require the normal product permissions and approval gates.
- Demo mode blocks external writes regardless of the selected target role.
- A stable production `SECRET_KEY` is required so support-session tokens remain valid.
- Secrets belong in the deployment secret store, never in Git.

The standard `demo.dmarq.org` deployment remains the separate self-hosted,
single-user story. The multi-tenant provider demo belongs on its own hostname.
