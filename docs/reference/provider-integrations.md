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

## WHMCS Integration Contract

DMARQ does not require an end-customer Stripe record when the billing account
uses `provider_resale`, `provider_whmcs`, or `provider_tmf`. WHMCS remains the
system of record for invoices, payment state, taxes, credits, and customer
communications. DMARQ stores only the provider identifiers needed to reconcile
the tenant, subscription, and usage period.

Recommended WHMCS module mapping:

| WHMCS module action | DMARQ endpoint | Required scope | Provider fields |
| --- | --- | --- | --- |
| CreateAccount | `POST /api/v1/provider/customers` | `provider:write` | `provider_id`, `external_customer_id`, `external_subscription_id`, `external_event_id` |
| SuspendAccount | `POST /api/v1/provider/subscriptions/{external_subscription_id}/state` | `provider:write` | `status=suspended`, `external_event_id` |
| UnsuspendAccount | `POST /api/v1/provider/subscriptions/{external_subscription_id}/state` | `provider:write` | `status=active`, `external_event_id` |
| TerminateAccount | `POST /api/v1/provider/subscriptions/{external_subscription_id}/state` | `provider:write` | `status=terminated`, `external_event_id` |
| Usage billing cron | `GET /api/v1/provider/billing/accounts/{external_customer_id}/usage?period=YYYY-MM` | `provider:read` | `period` |
| Provider-wide reconciliation | `GET /api/v1/provider/billing/usage?period=YYYY-MM` | `provider:read` | `period` |

Use the WHMCS service id or subscription id as `external_subscription_id`, and
the WHMCS client id as `external_customer_id`. Use a stable WHMCS hook or module
event id as `external_event_id`; if WHMCS does not provide one, construct a
stable value from the action, service id, target state, and invoice or run id.

The WHMCS module should not store the raw DMARQ provider token in module logs,
ticket notes, admin activity text, or client-visible custom fields. Store it in
the provider control-panel secret store and rotate it by creating a replacement
provider token before revoking the old one.

## ISP And OSS/BSS Mapping

For mid-sized ISP and telco deployments, DMARQ should sit behind the provider's
existing customer portal, billing stack, and operations tooling. The provider
portal owns customer identity and commercial state; DMARQ owns DMARC report
ingestion, DNS posture, workspace isolation, and auditable lifecycle events.

The following mapping keeps DMARQ aligned with common TM Forum Open API style
systems without requiring DMARQ to implement those standards directly:

| Provider concept | DMARQ field or endpoint | Notes |
| --- | --- | --- |
| Product catalog offer | `plan_code`, `external_product_code` | Map DMARQ Starter/Pro/Business/ISP bundles to provider product catalog entries. |
| Customer account | `external_customer_id` on the billing account | Keep legal customer and invoice ownership in the provider system. |
| Billing account | `invoice_delivery_mode=provider_invoice` | DMARQ usage exports feed the provider invoice or monthly bill. |
| Product or service order | `POST /api/v1/provider/customers` | Provision the organization and first workspace from an accepted provider order. |
| Product inventory item | `external_subscription_id` | Use this as the durable DMARQ subscription reference for suspend/reactivate/cancel. |
| Service state | subscription `status` | Push `active`, `past_due_provider_reported`, `suspended`, `canceled`, or `terminated` from the provider system. |
| Customer bill usage | monthly usage export endpoints | Import deterministic per-period usage into the provider billing run. |

TM Forum-aligned environments commonly model these areas through customer,
product catalog, product ordering, product inventory, account management, and
customer bill management APIs. DMARQ's provider API is intentionally narrower:
it accepts the resulting identifiers and state transitions, then returns usage
that the provider can attach to its own invoice lines.

## Billing And Lifecycle Rules

Provider-billed accounts should follow these rules:

- DMARQ must not create Stripe customers for provider-billed end customers.
- Provider events must include `external_event_id` so retries are idempotent.
- DMARQ should store a sanitized `payload_summary`, not raw provider webhook
  bodies.
- Suspended accounts remain auditable and recoverable; terminated accounts are
  treated as closed subscriptions and should not receive new ingestion work.
- Usage export jobs may be rerun for the same period without changing totals
  unless new source data for that period was imported after the prior export.
- Provider-side invoice disputes should be resolved in the provider billing
  system; DMARQ can regenerate the period usage payload for reconciliation.

## Minimal Provider Module Flow

1. Create one provider machine token with `provider:read` and `provider:write`.
2. Store the token in the provider control-panel secret store.
3. On service activation, call `POST /api/v1/provider/customers`.
4. Save the returned DMARQ organization, workspace, billing account, and
   subscription ids in provider-side service metadata.
5. On overdue payment, cancellation, or manual operator action, call the
   subscription state endpoint with a fresh `external_event_id`.
6. During the monthly billing run, fetch account usage for each active provider
   subscription and attach the returned metrics to the provider invoice.
7. Run the provider-wide usage export as a reconciliation report after billing.
