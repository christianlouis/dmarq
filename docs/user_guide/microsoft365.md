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
7. If DMARC reports are delivered to a dedicated folder, click **Load folders** and choose the folder. If folder loading is unavailable, enter a well-known folder name such as `INBOX`.
8. Run **Test connection** and **Run import now**.

## Shared Mailboxes and Folders

DMARQ uses delegated Microsoft Graph access. That means the authorised Microsoft 365 user must be able to read the mailbox and folder you configure:

- For the authorised user's own mailbox, leave **Mailbox** blank.
- For a shared mailbox, enter the shared mailbox user principal name, for example `dmarc-reports@example.com`.
- The authorised user must have mailbox or folder-level read access in Exchange Online before DMARQ can list folders or messages.
- Folder selection stores the Microsoft Graph folder id when you choose a folder from **Load folders**. This is safer for localized or renamed folders than typing a display name.
- If you type a folder manually, use a well-known Graph folder name such as `INBOX` unless your tenant has confirmed a custom folder identifier.

## Import Behavior

DMARQ reads recent messages in the configured folder, filters for messages that look like DMARC reports, downloads Graph `fileAttachment` items, and sends `.xml`, `.zip`, `.gz`, and `.gzip` attachments through the same parser and persistence path used by upload, IMAP, and Gmail imports.

Imported Graph message IDs are stored on the mail source so scheduled polling does not reprocess the same message. Import history records processed messages, imported reports, duplicates, parse failures, attachment-level details, and the mailbox/folder target used for the attempt.

## Troubleshooting

- **Not authorised**: reconnect the source from Mail Sources.
- **Permission error**: confirm the app registration has delegated `Mail.Read` and the authorised account can read the target mailbox.
- **Throttling**: wait and retry, or increase the polling interval.
- **Mailbox/folder not found**: leave Mailbox blank for `/me`, use a valid user principal name for delegated/shared mailboxes, confirm the authorised user has access, and reload folders after changing the target mailbox.
