# Provider Integrations

DMARQ can be operated as a provider-billed service for ISP, MSP, and hosting
control-panel environments. In this mode, the provider owns the commercial
relationship and DMARQ stores external customer and subscription identifiers
instead of requiring Stripe customer records for every end customer.

Provider endpoints live under `/api/v1/provider`. Administrators can use the
normal admin session/API key, while ISP/MSP automation should use global
provider-scoped machine tokens with `provider:read` and/or `provider:write`.

## Provider Machine Tokens

```text
GET /api/v1/provider/api-tokens
POST /api/v1/provider/api-tokens
DELETE /api/v1/provider/api-tokens/{token_id}
```

Token management requires administrator access. Provider tokens are global,
not workspace-scoped, and are intended for trusted provider control panels,
billing runs, and hosting-management integrations.

Request:

```json
{
  "name": "ISP control panel",
  "scopes": ["provider:read", "provider:write"]
}
```

The raw token is returned only once. Store it in the provider-side secret store
and send it as `X-API-Key` when calling provider lifecycle and usage endpoints.
Use `provider:read` for usage exports and `provider:write` for customer
provisioning or subscription state changes.

## Provision A Customer

```text
POST /api/v1/provider/customers
```

Required token scope: `provider:write`.

Request:

```json
{
  "provider_id": "isp-demo",
  "external_customer_id": "cust_123",
  "external_subscription_id": "sub_123",
  "external_event_id": "evt_123",
  "organization_slug": "customer-one",
  "organization_name": "Customer One",
  "workspace_slug": "customer-one-primary",
  "workspace_name": "Customer One Primary",
  "plan_code": "starter"
}
```

The endpoint creates or refreshes:

- an active organization
- a default workspace for the customer
- a provider-resale billing account with `invoice_delivery_mode=provider_invoice`
- a provider-resale subscription with the external subscription id
- starter entitlements
- an auditable `provider.customer_provisioned` billing event

`external_event_id` makes provisioning safe to retry. If the same provider event
is received again, DMARQ returns the existing customer summary with
`idempotent_replay=true` and does not create duplicate tenant records.

## Update Subscription State

```text
POST /api/v1/provider/subscriptions/{external_subscription_id}/state
```

Required token scope: `provider:write`.

Request:

```json
{
  "status": "suspended",
  "provider_id": "isp-demo",
  "external_event_id": "evt_456",
  "payload_summary": "provider reported overdue invoice"
}
```

Supported states are `trialing`, `active`, `past_due_provider_reported`,
`suspended`, `canceled`, and `terminated`. Each update records a billing event
without storing the raw provider payload.

## Monthly Usage Export

```text
GET /api/v1/provider/billing/usage?period=2026-06
GET /api/v1/provider/billing/accounts/{external_customer_id}/usage?period=2026-06
```

Required token scope: `provider:read`.

Usage exports are deterministic for a billing period and include workspace,
domain, aggregate report, message volume, forensic report, and active user
metrics. The payload is intended for provider-side monthly invoicing, including
WHMCS-style billing runs or custom ISP account-management systems.
