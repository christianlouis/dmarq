# Workspace Foundations

DMARQ uses a workspace as the tenant boundary for multi-organization and MSP
deployments. Milestone 15 starts with a default single-tenant workspace so
existing deployments have a clear migration path before workspace RBAC and MSP
views are added.

## Default Workspace

Existing installs are migrated into:

```text
slug: default
name: Default Workspace
```

The migration attaches legacy domains, users, and mail sources to this default
workspace. New domain rows created by the API also default to this workspace.

## Ownership Boundaries

The initial workspace model relates these core records to a workspace:

- monitored domains
- mail sources
- users

Domain, mail-source, and user query helpers scope reads to a workspace by
default. This prevents cross-tenant reads in new M15 surfaces and gives later
RBAC work a single ownership field to enforce.

## Roles And Permissions

DMARQ defines these workspace roles as the RBAC vocabulary for MSP mode:

| Role | Intended operator |
|------|-------------------|
| `workspace_owner` | Full workspace administrator |
| `domain_admin` | Domain and mail-source administrator |
| `operator` | Day-to-day operations and notification management |
| `analyst` | Reporting and posture reader |
| `auditor` | Audit and report reader |

The role catalog is available from `GET /api/v1/audit/roles`. Current admin
sessions and admin API keys map to `workspace_owner` until membership management
screens are added.

## Audit Logs

The `workspace_audit_logs` table stores sanitized records for sensitive
workspace actions. `GET /api/v1/audit/logs` returns recent audit events for the
default workspace and can filter by `action` or `entity_type`.

Current audit coverage includes:

- API token creation and revocation
- mail-source creation, update, deletion, enable/disable toggles, and OAuth
  connect/disconnect actions
- notification and forensic setting changes
- webhook creation, update, disable, and test actions
- manual DKIM selector add/remove actions

Audit details redact secret-like fields such as passwords, OAuth tokens, API
keys, and webhook signing secrets.

## Migration Story

The migration creates the `workspaces` table, inserts the default workspace, and
adds nullable `workspace_id` ownership columns to existing domain, user, and
mail-source tables. Nullable columns keep upgrades safe for older databases and
for import paths that may be backfilled in stages; runtime helpers attach
legacy rows to the default workspace when needed.

The RBAC/audit migration adds `workspace_memberships` for role assignments and
`workspace_audit_logs` for workspace-scoped change history.

## Onboarding Templates

Workspace onboarding templates give MSP operators a repeatable way to create a
new client workspace with minimal manual configuration. The template API can:

- preview a rendered onboarding plan before anything is saved
- create or reuse a workspace
- seed monitored domains and manual DKIM selectors
- seed disabled mail-source shells for IMAP, Gmail, or Microsoft 365
- seed safe notification defaults without storing notification target secrets
- return an operator checklist for DNS validation, mailbox connection, initial
  import, and notification testing

Available templates are exposed from `GET /api/v1/onboarding/templates`.
Operators render a plan with `POST /api/v1/onboarding/preview` and apply it
with `POST /api/v1/onboarding/apply`.

The onboarding response and audit records redact secret-like fields, including
passwords, OAuth secrets, tokens, and API keys. Existing domains and mail
sources are treated idempotently; duplicate domains owned by another workspace
are rejected to keep ownership unambiguous.

Notification defaults currently seed the existing notification settings table.
They intentionally avoid Apprise target URLs, so operators still add and test
delivery targets explicitly after onboarding.

## MSP Operator Views

MSP operator endpoints provide cross-workspace summaries without returning raw
DMARC report rows across tenant boundaries. `GET /api/v1/operator/workspaces`
returns one summary per active workspace:

- workspace identity and active state
- health status derived from domains, enabled mail sources, active alerts,
  recent failed imports, and missing import history
- domain counts and names
- mail-source counts and the most recent import status
- aggregate report counts
- current retention controls
- recent workspace audit events as drift indicators

`GET /api/v1/operator/workspaces/{workspace_id}` returns the same summary for
one workspace.

Workspace retention controls are stored on the workspace row:

| Field | Purpose | Default |
| --- | --- | --- |
| `report_retention_days` | Aggregate DMARC report retention target | 400 |
| `forensic_retention_days` | Forensic report retention target | 90 |
| `tls_report_retention_days` | SMTP TLS report retention target | 400 |

Operators can update these controls with
`PUT /api/v1/operator/workspaces/{workspace_id}/retention`. Updates are written
to the workspace audit log as `workspace.retention_updated`.

The current implementation keeps domain names globally unique. That matches the
existing single-domain ownership model and avoids ambiguous ownership while MSP
RBAC and onboarding controls are built out.
