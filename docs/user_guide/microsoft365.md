# Microsoft 365 Mail Sources

DMARQ imports DMARC aggregate report attachments from Exchange Online through
Microsoft Graph. Microsoft 365 sources support two authentication modes:

- **User sign-in (delegated)**: an operator signs in interactively. This is a
  good fit when an existing licensed user already has access to the report
  mailbox.
- **Application access (client credentials)**: DMARQ authenticates unattended
  as an Entra application. This is the recommended mode for a dedicated shared
  report mailbox because it needs no redirect URI, interactive user, or refresh
  token.

Both modes are read-only. DMARQ lists folders and messages and downloads report
attachments; it never moves, deletes, labels, forwards, or marks messages read.

## Prerequisites

You need an organizational Microsoft Entra tenant with Exchange Online and a
target mailbox containing DMARC aggregate reports. A consumer Microsoft 365
Personal/Family or Outlook.com mailbox is not an Exchange Online mailbox in an
organizational tenant and is not suitable for application access.

For a minimal test tenant, one Exchange Online Plan 1 user is sufficient. The
target can initially be that user's mailbox. A shared mailbox can then be added
without a separate license under Microsoft's normal shared-mailbox limits.

## Application Access (Recommended for Shared Mailboxes)

### 1. Register the Entra Application

Create an app registration in the Microsoft Entra admin center. Record:

- Directory (tenant) ID or a verified tenant domain
- Application (client) ID
- A new client secret value

Under **API permissions**, add Microsoft Graph **Application permission**
`Mail.Read` and grant tenant-wide admin consent. Do not add a redirect URI;
client-credential authentication does not use one.

`Mail.Read` application permission can read every mailbox in the tenant unless
Exchange Online limits it. Do not rely on the mailbox field in DMARQ as the
authorization boundary.

### 2. Limit the Application in Exchange Online

Use **Exchange Online RBAC for Applications** to grant the service principal a
mail-read role scoped to only the report mailbox. Microsoft recommends RBAC for
Applications for new configurations. Legacy Application Access Policies are
documented by Microsoft but are not the preferred design for a new deployment.

Important: Exchange RBAC grants and broad Entra application grants are
additive. Verify the effective permissions and do not leave an unscoped Entra
`Mail.Read` grant that defeats the intended Exchange scope.

Follow Microsoft's current procedures:

- [Role Based Access Control for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [Microsoft identity platform client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)

### 3. Configure DMARQ

1. Open **Mail Sources** and add **Microsoft 365 (Graph)**.
2. Select **Application access**.
3. Enter the tenant ID, client ID, client secret, and the explicit target
   mailbox user principal name, for example `dmarc-reports@example.com`.
4. Save the source, edit it, and select **Test application access**.
5. Load folders and choose the dedicated report folder when applicable.
6. Run **Import now**, then run a bounded historical backfill.

Application mode rejects `common`, `organizations`, `consumers`, a blank
mailbox, and `me`. Every Graph mailbox request uses `/users/{mailbox}/...`.
DMARQ obtains short-lived tokens from the tenant-specific token endpoint with
the `https://graph.microsoft.com/.default` scope and obtains a new token when
needed. No refresh token is expected.

## User Sign-in (Delegated)

### 1. Register the Entra Application

Create an Entra app registration with:

- Platform: Web
- Redirect URI:
  `https://<your-dmarq-host>/api/v1/mail-sources/<source-id>/m365/callback`
- Delegated permissions: `User.Read`, `Mail.Read`, and `offline_access`
- A client secret stored in your deployment secret manager

DMARQ also requests `Mail.Read.Shared` so the signed-in user can read a shared
mailbox to which Exchange Online has already granted that user access.

### 2. Configure DMARQ

1. Add **Microsoft 365 (Graph)** and select **User sign-in**.
2. Enter `common`, `organizations`, or a concrete tenant ID, plus client ID and
   client secret.
3. Leave **Mailbox** blank for the signed-in user's mailbox, or enter a shared
   mailbox that the user can read.
4. Save, select **Connect Microsoft 365**, and complete the sign-in.
5. Load folders, test the connection, import current reports, and run a backfill.

Delegated mode persists encrypted access and refresh tokens so scheduled polls
can continue without another sign-in. If consent is revoked or the refresh
token expires, DMARQ surfaces a reconnect action in Mail Sources and operations
health.

## Folder and Import Behavior

Folder selection should prefer the Graph folder IDs returned by **Load
folders**. Folder IDs remain stable when display names are localized or
renamed. A manually entered well-known name such as `INBOX` is also accepted.

DMARQ filters messages by the selected search window, detects likely DMARC
report mail, and passes `.xml`, `.zip`, `.gz`, and `.gzip` file attachments
through the same parser and persistence path used by upload, IMAP, and Gmail.
Imported Graph message IDs prevent repeated processing. Import history records
processed messages, new reports, duplicates, parse failures, and safe
mailbox/folder context.

Manual imports and scheduled imports use bounded date windows. Historical
backfills are resumable, duplicate-safe jobs with progress, retry, cancel, and
provider-throttling handling.

## Acceptance Test

A Microsoft 365 application source is ready for production only after all of
the following succeed:

1. **Test application access** reads the configured mailbox.
2. **Load folders** returns folders for that mailbox.
3. **Import now** finds a known DMARC report attachment.
4. A backfill imports older reports without creating duplicate reports.
5. Scheduled polling acquires a new application token without user interaction.
6. Exchange Online confirms that the service principal cannot read an unrelated
   mailbox.

Use a non-production tenant or narrowly scoped test mailbox while validating
permissions. Never paste the client secret into issue comments or commit it to
the repository.

## Troubleshooting

- **Tenant-specific ID required**: replace `common` or `organizations` with the
  directory tenant ID or verified tenant domain.
- **Application token request failed**: confirm the client ID, active secret,
  tenant, `Mail.Read` application permission, and admin consent.
- **Access denied**: verify both Entra consent and the effective Exchange Online
  RBAC assignment for the exact target mailbox.
- **Mailbox not found**: use the mailbox's Exchange Online user principal name,
  not a display name or consumer Microsoft account.
- **Delegated authorization expired**: reconnect the source interactively.
- **Throttling**: wait for the bounded retry or increase the polling interval.
