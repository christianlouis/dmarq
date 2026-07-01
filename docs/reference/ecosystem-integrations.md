# Ecosystem Integration Matrix

DMARQ should fit into the systems where operators already manage domains,
DNS, mail sending, hosting, tickets, and customer lifecycle. Integrations are
not a reason to hide automation from users. They should reduce copy/paste work,
improve evidence quality, and prepare safe fixes that an operator can review
before anything changes.

This matrix is the product boundary for ecosystem work. Implementation issues
can add providers one by one, but each provider should still answer the same
questions: why the integration exists, when users should connect it, what
credentials are required, which operations are read-only, which operations are
approval-only, and what stays out of scope.

## Integration Principles

- Prefer read-only discovery before write capability.
- Require exact diff preview, explicit confirmation, verification, audit log,
  and rollback guidance before any DNS or provider write.
- Keep self-hosted operation first-class. Integrations must be optional unless
  they are part of a separately documented hosted or provider deployment.
- Store scoped credentials only in server-side secret storage or deployment
  secrets. Never store provider tokens in browser storage or logs.
- Keep DNS record values, selectors, domains, IPs, and protocol tags exact even
  when operator-facing guidance is localized.
- Treat provider conflicts as a safety stop unless the operator explicitly
  overrides the mismatch.

## Integration Matrix

| Ecosystem | Why it matters | First useful behavior | Credentials and scopes | Read capability | Write boundary | Roadmap links |
| --- | --- | --- | --- | --- | --- | --- |
| DNS providers: Cloudflare, Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, Hetzner, PowerDNS, registrar DNS, hosting-panel DNS | DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and BIMI fixes usually live in DNS. | Detect authoritative provider, import zones, inspect records, create safe change plans. | Provider API token limited to zone read first; DNS edit scope only when the user enables repair. | Zones, record sets, TTLs, DNS snapshots, provider metadata. | Approval-only TXT/CNAME create/update first; no hidden deletions, wildcard changes, or ambiguous SPF rewrites. | [#379](https://github.com/christianlouis/dmarq/issues/379), [#380](https://github.com/christianlouis/dmarq/issues/380), [#381](https://github.com/christianlouis/dmarq/issues/381) |
| Mail services: Postmark, Twilio SendGrid, Mailgun, Amazon SES, Microsoft 365, Google Workspace, SMTP relays | Sender domains and required DKIM/return-path DNS records often originate in mail-service dashboards. | Import verified sender domains and provider-required DNS records, then map them into DMARQ DNS linting. | Mail-service account token with sender/domain read scope; write scopes only for provider-specific setup actions. | Verified sender domains, required DNS records, DKIM selectors, bounce/return-path state, provider status. | Read-only by default. Provider setup or DNS repair stays approval-only through the normal DNS/provider change flow. | [#378](https://github.com/christianlouis/dmarq/issues/378), [#382](https://github.com/christianlouis/dmarq/issues/382), [#384](https://github.com/christianlouis/dmarq/issues/384) |
| Self-hosted MTAs and relays: Postfix, Exim, OpenSMTPD, Haraka, rspamd, custom relays | Self-hosted operators need the same mail-health explanation without assuming a SaaS sender. | Identify observed source IPs, alignment failures, DNS/rDNS gaps, TLS posture, and reputation risk. | Usually none for first slice; optional SSH/API integrations must be separately designed and explicitly enabled. | DMARC report evidence, DNS/rDNS lookups, TLS-RPT evidence, blacklist/cache state. | Manual guidance first. No mail-server configuration changes until a dedicated integration defines exact commands, rollback, and audit semantics. | [#384](https://github.com/christianlouis/dmarq/issues/384), [#385](https://github.com/christianlouis/dmarq/issues/385) |
| Hosting and control panels: ISPConfig, cPanel/WHM, Plesk, WHMCS, HostBill, Blesta | SMB users often manage DNS, mailboxes, billing, and support in hosting panels instead of separate DNS/mail tools. | Provision DMARQ tenants, import customer domains, export usage, and show support-safe evidence links. | Provider machine token for DMARQ plus control-panel token stored in the provider system. | Customer/domain inventory, subscription state, usage export, optional DNS panel records. | Provider-scoped approval. Customer lifecycle writes are auditable; DNS writes still need explicit repair confirmation or provider-side approval. | [#12](https://github.com/christianlouis/dmarq/issues/12), [#243](https://github.com/christianlouis/dmarq/issues/243), [Provider Integrations](provider-integrations.md) |
| Ticketing, chatops, and SIEM: Slack, Teams, webhooks, Jira, GitHub Issues, PSA/RMM, Splunk, Elastic, Sentinel | Operators need workflows and evidence trails, not another dashboard to poll manually. | Send deduplicated events with domain, evidence, severity, owner, and suggested action. | Webhook URL, bot token, SIEM endpoint, or API token with message/event create scope. | Alert rules, remediation status, audit events, normalized evidence envelopes. | Notify/read-only by default. Creating tickets or chat messages is allowed; resolving incidents or applying fixes requires separate approval. | [Ticketing and Chatops](ticketing-chatops-integrations.md), [SIEM Integrations](siem-integrations.md), [#384](https://github.com/christianlouis/dmarq/issues/384) |
| Direct report intake: Cloudflare Email Routing Workers, AWS SES receipt/Lambda, generic webhook intake | Polling a mailbox is simple, but hosted intake can be more reliable for new deployments and provider packaging. | Receive aggregate and forensic reports by HTTPS webhook, verify signatures/secrets, and attach import evidence. | Inbound shared secret, HMAC key, or provider event signature configuration. | Incoming MIME/XML attachments, delivery metadata, source provider event id. | No DNS writes. Intake workers only transform and deliver reports into DMARQ. | [#383](https://github.com/christianlouis/dmarq/issues/383), [Cloudflare Email Worker Webhook](../cloudflare-email-worker-inbound-webhook.md) |
| Identity and tenant lifecycle: OIDC, SCIM, provider SSO handoff, support access | Hosted and ISP/OEM deployments need clear boundaries for users, tenants, support, and audit. | OIDC login, organization/workspace memberships, provider provisioning, and auditable support access. | OIDC client, SCIM bearer token, provider machine token, support-access policy. | User profile, groups, memberships, lifecycle state, support-session audit events. | Admin actions only. Support impersonation must be time-bound, reason-coded, and logged. | [#12](https://github.com/christianlouis/dmarq/issues/12), [#243](https://github.com/christianlouis/dmarq/issues/243), [Workspaces](workspaces.md) |
| Public API and MCP automation | Operators and agents need evidence-linked read access and carefully bounded automation. | Read health posture, reports, findings, actions, and DNS plans through stable APIs and read-only MCP tools. | API token scoped to workspace and capability; MCP should inherit the same read/write limits. | Reports, posture, action plans, audit events, provider templates. | Read-only first. Any write tool must route through the same preview, confirmation, audit, and verification flow as the UI. | [#309](https://github.com/christianlouis/dmarq/issues/309), [AI and MCP Automation](ai-mcp-automation.md) |

## First Practical Paths

### Self-hosted DMARQ

Self-hosted users usually need fast value without enterprise setup. The first
practical integration path should be:

1. Import reports from IMAP, Gmail, Microsoft 365, direct upload, or webhook
   intake.
2. Auto-create observed domains from reports.
3. Detect authoritative DNS provider from NS records.
4. Import zones from the connected DNS provider when the user chooses to.
5. Import verified sender domains and required DNS records from connected mail
   services such as Postmark or SendGrid.
6. Produce evidence-linked remediation plans with exact DNS values.
7. Allow approved DNS repair only when a scoped DNS provider connector exists
   and the operator confirms the exact change.

### Provider, ISP, MSP, and OEM Deployments

Provider deployments need account lifecycle and billing integration before
fine-grained repair automation. The first practical path should be:

1. Provision organization/workspace/subscription from the provider portal or
   hosting system.
2. Import the customer's known domains from the provider inventory.
3. Connect provider-owned DNS or mail-service context where available.
4. Export monthly usage to the provider billing system.
5. Send support-safe findings into ticketing/chatops tools.
6. Let provider staff or the customer approve repairs according to the
   provider's control-panel policy.

## Boundary Classes

| Boundary | Meaning | Examples |
| --- | --- | --- |
| Read-only | DMARQ can inspect, import, correlate, and explain, but cannot change the external system. | Mail-service sender import, SIEM export templates, direct report intake. |
| Approval-only | DMARQ can prepare a change and apply it only after explicit operator confirmation. | Safe DNS TXT/CNAME repair, provider-required DKIM CNAME setup. |
| Provider-scoped | A provider or ISP system can provision tenants or update billing state using a machine token. | WHMCS CreateAccount, subscription suspension, monthly usage export. |
| Manual guidance | DMARQ explains what to do, but does not apply changes because the risk or environment is too broad. | Self-hosted MTA configuration, ambiguous SPF flattening, blacklist delisting. |
| Out of scope | DMARQ should not own this workflow unless a future issue changes the product boundary. | Acting as a general mail gateway, silently delegating DNS, unsupervised remediation, storing raw provider secrets in the browser. |

## Open Implementation Threads

- [#380](https://github.com/christianlouis/dmarq/issues/380) should continue
  safe one-click DNS repair across provider plugins.
- [#383](https://github.com/christianlouis/dmarq/issues/383) should continue
  direct report intake through hosted mail and webhook workers.
- [#384](https://github.com/christianlouis/dmarq/issues/384) should group raw
  findings into a prioritized remediation queue with automation eligibility.
- [#385](https://github.com/christianlouis/dmarq/issues/385) should add sender
  IP reputation and blacklist signals as health inputs.
- [#387](https://github.com/christianlouis/dmarq/issues/387) should localize
  the operator-facing guidance produced by these integrations.
