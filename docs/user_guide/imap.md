# IMAP Integration

DMARQ can retrieve DMARC aggregate reports from a mailbox on a schedule. IMAP
is the simplest Gmail-compatible option when you do not want to configure a
Google Cloud OAuth client.

## Before You Start

You need:

1. A mailbox that receives DMARC aggregate reports from the `rua=` address in
   your domain's DMARC record.
2. IMAP access to that mailbox.
3. A provider-specific App Password when normal password authentication is
   disabled or the account uses MFA. Never enter the normal Google account
   password into DMARQ.

For Gmail, use:

| Field | Value |
|-------|-------|
| Method | `IMAP` |
| Server | `imap.gmail.com` |
| Port | `993` |
| SSL/TLS | enabled |
| Username | full Gmail address |
| Password | Google App Password |
| Folder | `INBOX`, or the folder/label receiving reports |

## Add A Mail Source

1. Open **Mail Sources**.
2. Choose **Add mail source**.
3. Enter a recognizable source name.
4. Select **IMAP** and fill in server, port, username, password, TLS, and folder.
5. Choose a polling interval. The minimum is 15 minutes.
6. Keep the source enabled.
7. Select **Test Connection** before saving.
8. Save the source, then select **Fetch now**.

The connection test checks authentication and mailbox access. **Fetch now**
creates an import-history entry and processes supported DMARC attachments.

## Verify The First Import

After the first fetch:

1. Open the source's **Import history**.
2. Confirm that the attempt completed and review its parsed, duplicate, skipped,
   and failed counts.
3. Open **Reports** and confirm the expected reporting organization and domain.
4. Compare report message totals and date range with the source XML.
5. Run **Fetch now** again. An unchanged mailbox should produce duplicate or
   no-new-report results without increasing existing report totals.

Use **Backfill** when reports exist outside the normal recent polling window.
Start with a small date range, inspect the result, and widen it only when
needed.

## Scheduled Polling

Enabled sources are checked by the application scheduler according to their
polling interval. A successful connection test alone does not prove scheduled
polling. Leave the instance running through at least one interval and confirm a
new scheduled entry appears in import history.

The application must have only the intended scheduler topology. If multiple
application replicas each run the in-process scheduler, they can perform the
same mailbox check. Use the deployment's documented worker/scheduler strategy
before scaling an ingestion instance horizontally.

## Credential Storage And Rotation

DMARQ encrypts persisted mailbox credentials using the deployment
`SECRET_KEY`. Keep that key stable across restarts and upgrades. If it changes,
previously stored credentials cannot be decrypted and the source must be
re-entered.

For an ephemeral acceptance test, revoke the App Password after testing. For a
maintained instance, store and rotate it according to the deployment's secret
policy. Passwords and tokens are never returned by the Mail Sources API.

## Pause, Edit, Or Remove A Source

- Toggle a source off to stop scheduled checks without deleting its history.
- Edit the source to change its folder, interval, or credentials. Leave the
  password blank only when the form explicitly says the stored password will be
  retained.
- Test again after changing credentials or folders.
- Delete a source only when its configuration and operational history are no
  longer needed. Imported DMARC reports are separate persisted records.

## Troubleshooting

Run **Test connection** first. DMARQ returns a diagnostic category and recovery
steps for common failures:

| Category | Action |
|----------|--------|
| `authentication` | Verify the full username and generate a fresh App Password. Re-enter it without spaces. |
| `connectivity` | Confirm server, port, TLS, DNS, and outbound firewall access from the DMARQ host. |
| `mailbox_not_found` | Match the folder name and nested separator exactly. |
| `folder_search` | Confirm reports reach that folder, then run a bounded backfill. |
| `parsing` | Inspect import details for malformed XML or corrupt ZIP/GZIP attachments. |
| `duplicate_only` | Normal for an unchanged mailbox; investigate delivery only when fresh reports are expected. |

An expired or revoked App Password appears as an authentication failure and
requires a new password. Gmail API OAuth sources instead expose authorization
health and request reconnection when refresh access is missing or rejected.
Check **Operations** and the source's import history for the latest actionable
diagnostic before reviewing container logs.
