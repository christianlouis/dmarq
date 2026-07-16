# Microsoft 365 Graph Connector Contract

This contract defines the supported boundary for Microsoft 365 mail sources. The
connector exists only to import DMARC aggregate report attachments through
Microsoft Graph and to return sanitized operational metadata that matches the
shared mail-source import history shape.

## Scope

The connector must remain read-only:

- It may list messages in the configured mailbox and folder.
- It may list and read `fileAttachment` payloads for messages that look like
  DMARC aggregate report mail.
- It must not delete, move, mark read, label, forward, or otherwise mutate
  Microsoft 365 mailbox content.
- It must pass supported `.xml`, `.zip`, `.gz`, and `.gzip` attachments through
  the same aggregate DMARC parser used by upload, IMAP, and Gmail imports.

## Authentication and Permissions

DMARQ supports delegated and application authentication as explicit, separate
source modes.

Delegated mode uses:

| Permission | Purpose |
|------------|---------|
| `offline_access` | Receive refresh tokens for scheduled polling. |
| `User.Read` | Identify the authorized account during OAuth setup. |
| `Mail.Read` | List messages and read report attachments from the authorized account. |
| `Mail.Read.Shared` | Read report messages and attachments in shared or delegated mailboxes. |

Application mode uses the tenant-specific client-credentials token endpoint,
the `https://graph.microsoft.com/.default` scope, and the Microsoft Graph
`Mail.Read` **application permission**. It must not use a redirect URI, user
sign-in, `/me`, or refresh tokens. A concrete tenant and explicit target mailbox
are mandatory.

Because Entra `Mail.Read` application permission is tenant-wide by default, the
operator must limit the service principal to the report mailbox with Exchange
Online RBAC for Applications and verify the effective scope. DMARQ's mailbox
field is a request target, not an authorization boundary. New deployments
should not use legacy Application Access Policies when Exchange RBAC for
Applications is available.

## Mailbox and Folder Selection

Delegated mode supports two mailbox targets:

- Blank mailbox or `me`: read the authorized account through `/me`.
- User principal name: read a delegated or shared mailbox through `/users/{upn}`.

The authorized account must already have Exchange Online read access to any
shared mailbox or folder. DMARQ does not grant mailbox permissions.

Application mode supports only an explicit user principal name and always uses
`/users/{upn}`. Blank, `me`, `common`, `organizations`, and `consumers` values
must fail validation before polling begins.

Folder selection should prefer Microsoft Graph folder ids returned by **Load
folders**. Folder ids are stable across localized or renamed folders. Manually
entered folder names are accepted for well-known folders such as `INBOX`, but
operators should prefer folder ids for dedicated DMARC report folders.

## Backfill and Search Window

All manual imports, scheduled imports, and backfills must use the shared
connector search-window clamp:

- default: 7 days
- minimum: 1 day
- maximum: 365 days

The Graph request must include a `receivedDateTime ge ...` filter for the
requested window and should order by newest messages first. Connectors must keep
already-ingested Graph message ids and avoid reprocessing the same message on
later runs.

## Import Result Shape

Microsoft 365 imports must return the same safe shape as other mailbox
connectors:

| Field | Meaning |
|-------|---------|
| `success` | Whether the provider request and import loop completed. |
| `processed` | Messages inspected for import. |
| `reports_found` | New aggregate reports persisted. |
| `forensic_reports_found` | Reserved for future RUF metadata, separate from aggregate totals. |
| `duplicate_reports` | Aggregate reports skipped because the report id already exists. |
| `duplicate_forensic_reports` | Reserved for future forensic/RUF support. |
| `new_domains` | Domains introduced by newly persisted aggregate reports. |
| `errors` | Sanitized provider or attachment failures. |
| `new_ingested_ids` | Graph message ids that can be persisted for dedupe. |
| `details` | Sanitized per-message or per-attachment outcomes. |
| `target_mailbox` | Operator-safe mailbox label, never a token or secret. |
| `target_folder` | Operator-safe folder label or folder id. |
| `search_window_days` | Effective clamped search window. |

This result shape is what `record_import_attempt` stores in sanitized import
history. It must remain compatible with IMAP and Gmail import semantics.

## Throttling and Retries

Graph responses with `429`, `503`, or `504` are retryable. The connector should:

- honor `Retry-After` when present,
- use bounded exponential backoff otherwise,
- cap waits to a short operational delay,
- return a sanitized failed import result if Graph remains unavailable.

## Redaction Rules

The connector may store or return:

- mailbox labels,
- folder labels or ids,
- Graph message ids,
- attachment filenames,
- aggregate report domains and report ids,
- sanitized provider error categories or messages.

The connector must never store or return:

- access tokens,
- refresh tokens,
- client secrets,
- raw OAuth responses,
- raw message bodies,
- raw attachment content,
- full provider errors containing secrets.

Short-lived application access tokens may be persisted in the same encrypted
column as delegated access tokens for diagnostics and request reuse. Their
presence is not required for readiness because application mode can acquire a
new token during test, folder listing, manual import, scheduled polling, and
backfill. Client secrets and all token values remain encrypted at rest and
redacted from responses.

Operators should keep Microsoft 365 secrets in 1Password or the deployment
secret manager and inject them into the authorized deployment process. DMARQ
should only receive those secrets through configured runtime settings or
encrypted database fields, never through logs or issue comments.
