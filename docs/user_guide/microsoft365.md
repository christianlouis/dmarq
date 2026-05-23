# Microsoft 365 Mail Sources

DMARQ can import DMARC aggregate report attachments from Exchange Online through Microsoft Graph. Use this source type when IMAP is disabled or unavailable in a Microsoft 365 tenant.

## App Registration

Create an app registration in Microsoft Entra admin center:

- Platform: Web
- Redirect URI: `https://<your-dmarq-host>/api/v1/mail-sources/<source-id>/m365/callback`
- Delegated API permissions:
  - `User.Read`
  - `Mail.Read`
  - `offline_access`
- Client secret: create a secret for the web app and store it in your deployment secret manager.

`Mail.Read` is the least-privilege delegated Graph permission DMARQ needs to list messages and read file attachments. `offline_access` is requested so Microsoft returns a refresh token for scheduled polling.

## DMARQ Setup

1. Open **Mail Sources**.
2. Add a source with method **Microsoft 365 (Graph OAuth2)**.
3. Enter the tenant ID (`organizations`, `common`, or a tenant GUID), client ID, and client secret.
4. Leave **Mailbox** empty to read the authorised account, or enter a user principal name for a shared/delegated mailbox that the authorised user can read.
5. Save the source.
6. Use **Connect Microsoft 365** and approve the read-only mailbox access request.
7. Run **Test connection** and **Run import now**.

## Import Behavior

DMARQ reads recent messages in the configured folder, filters for messages that look like DMARC reports, downloads Graph `fileAttachment` items, and sends `.xml`, `.zip`, `.gz`, and `.gzip` attachments through the same parser and persistence path used by upload, IMAP, and Gmail imports.

Imported Graph message IDs are stored on the mail source so scheduled polling does not reprocess the same message. Import history records processed messages, imported reports, duplicates, parse failures, and attachment-level details.

## Troubleshooting

- **Not authorised**: reconnect the source from Mail Sources.
- **Permission error**: confirm the app registration has delegated `Mail.Read` and the authorised account can read the target mailbox.
- **Throttling**: wait and retry, or increase the polling interval.
- **Mailbox/folder not found**: leave Mailbox blank for `/me`, use a valid user principal name for delegated/shared mailboxes, and keep the default `INBOX` folder unless reports are delivered elsewhere.
