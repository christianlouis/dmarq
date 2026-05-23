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

## Migration Story

The migration creates the `workspaces` table, inserts the default workspace, and
adds nullable `workspace_id` ownership columns to existing domain, user, and
mail-source tables. Nullable columns keep upgrades safe for older databases and
for import paths that may be backfilled in stages; runtime helpers attach
legacy rows to the default workspace when needed.

The current implementation keeps domain names globally unique. That matches the
existing single-domain ownership model and avoids ambiguous ownership while MSP
RBAC and onboarding controls are built out.
