# Provider Demo

DMARQ keeps the public demo focused on the self-hosted, single-user, multiple-domain story.
ISP, MSP, account-management, and multi-tenant workflows are shown through a separate
provider demo surface.

## Enablement

Set `PROVIDER_DEMO_ENABLED=true` on a dedicated demo deployment and expose `/provider-demo`
through the desired hostname. The page reads synthetic deployment data from
`/api/v1/operator/demo/multi-user`, so the deployment must also be configured for demo data.

Do not enable this surface on the standard public demo unless the desired visitor journey is
the provider/operator story.

## Included Personas

- Single-user account owner managing `dmarq.org` and `dmarq.com`.
- Managed-service analyst reviewing account, billing, and workspace context.
- ISP operator reviewing customer workspaces and provider-billed usage.
- Customer admin shown through explicit demo-only support access.
- Self-hosted admin comparing local billing ownership and workspace operations.

## Operator Flow

The demo path is intentionally action-led:

1. Start in an owned domain view for `dmarq.org`.
2. Compare account ownership and billing context for `dmarq.com`.
3. Zoom out to provider customer health and usage.
4. Start a demo-only audited support session for a selected customer tenant.
5. Compare the same workflow with the self-hosted deployment model.

The provider view includes tenant-health segments for healthy, monitoring, and
misconfigured customers. Selecting a segment or customer drills into the matching
workspace and shows the next recommended operator action.

## Safety Boundaries

- The page is read-only.
- Support impersonation is displayed as synthetic audited state only and can
  generate a demo audit event through `POST /api/v1/operator/demo/support-session`.
- Customer and billing data are generated demo fixtures, not real tenants.
- DNS/provider writes remain outside this demo surface.
