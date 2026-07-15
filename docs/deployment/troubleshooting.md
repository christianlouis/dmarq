# Troubleshooting Playbooks

Use these playbooks when DMARQ is running but an operator workflow is not behaving as expected. Keep sensitive values redacted. When you need to test credentials, inject them into the authorized process from 1Password or your deployment secret manager instead of copying them into commands or notes.

## Quick Triage

Start with these checks:

```bash
curl -fsS https://your-dmarq-host.example.com/healthz
curl -fsS https://your-dmarq-host.example.com/api/v1/health
```

For Docker Compose:

```bash
docker compose ps
docker compose logs --tail=100 app
```

For systemd:

```bash
sudo systemctl status dmarq
sudo journalctl -u dmarq -n 100
```

Then check the UI:

1. Dashboard loads and shows domains.
2. Domain details load DNS health, reports, and sending sources.
3. Mail Sources shows recent import history.
4. Settings saves and test notifications work if enabled.

## App Does Not Start

Likely causes:

- Missing or weak `SECRET_KEY`.
- Database connection failure.
- PostgreSQL credentials or host changed.
- SQLite path is not writable.
- Production startup checks blocked unsafe settings.

Actions:

1. Check the last 100 log lines.
2. Confirm required environment variables are present in the deployment process.
3. Confirm secrets are injected, not present only in your shell.
4. For PostgreSQL, verify network access from the app host to the database host.
5. For SQLite, verify the data directory exists and is writable by the app user.
6. Restart after fixing configuration.

## Login Or Setup Fails

Likely causes:

- Identity-provider redirect URL does not match the deployed public URL.
- OAuth mail-source redirects are built from an internal `http://` proxy URL instead of the public `https://` URL.
- `PUBLIC_BASE_URL` or the identity-provider callback URL does not match the public hostname.
- `SECRET_KEY` changed unexpectedly, invalidating sessions.
- `AUTH_DISABLED`, `LOGTO_SKIP_SSL_VERIFY`, or `OIDC_SKIP_SSL_VERIFY` is set incorrectly for the environment.

Actions:

1. Confirm `PUBLIC_BASE_URL` and the identity-provider callback use the host users open in the browser.
2. Confirm Logto, Authentik, or generic OIDC callback URLs match the DMARQ callback URL exactly.
3. Confirm `SECRET_KEY` is stable across restarts.
4. Clear browser cookies after intentional auth changes.
5. Set `PUBLIC_BASE_URL=https://<your-public-host>` if Gmail, Microsoft 365, or identity-provider callbacks show `http://` behind a proxy.
6. Keep `AUTH_DISABLED=false`, `LOGTO_SKIP_SSL_VERIFY=false`, and `OIDC_SKIP_SSL_VERIFY=false` in production.

## Mailbox Test Fails

Open **Mail Sources**, run **Test connection**, and use the diagnostic category shown in the result.

| Diagnostic | What it means | Recovery |
|------------|---------------|----------|
| `auth_required` | Gmail OAuth was not completed. | Use **Connect Gmail** and authorize the mailbox that receives DMARC reports. |
| `auth_expired` | OAuth token was revoked, expired, or rejected. | Reconnect the source and approve the requested scope again. |
| `authentication` | Username, password, app password, or token was rejected. | Verify credentials. For IMAP providers with MFA, create a provider app password. |
| `permissions` | The account is connected but lacks mailbox access. | Grant mailbox read access or reconnect Gmail with the requested read-only scope. |
| `connectivity` | DMARQ cannot reach the provider. | Check hostname, port, TLS setting, firewall, DNS, and provider availability. |
| `mailbox_not_found` | The configured folder cannot be opened. | Use one of the returned mailbox names and match capitalization/separators exactly. |
| `folder_search` | The mailbox is reachable, but the selected folder or search window has no new DMARC reports. | Confirm reports arrive in that folder, then run a wider backfill if needed. |
| `parsing` | DMARQ reached messages but could not parse one or more report attachments. | Inspect import details, then validate with a known-good XML, ZIP, or GZIP aggregate report. |
| `duplicate_only` | The latest run found only reports DMARQ already imported. | No action is needed for quiet mailboxes; otherwise confirm fresh reports are arriving in the configured folder. |
| `throttling` | Provider is rate limiting requests. | Wait, retry, and increase the polling interval if failures repeat. |
| `missing_config` | Required settings are absent. | Fill in server, username, password, or complete OAuth authorization. |
| `not_configured` | No enabled mailbox source is available. | Add or enable a source, then run **Test connection** before relying on scheduled imports. |

Never paste mailbox passwords or OAuth tokens into logs or issue comments. If a provider error contains a token-like value, redact it before sharing.

## Reports Are Not Importing

Likely causes:

- DMARC reports are sent to a different mailbox than the configured source.
- The folder setting points to the wrong mailbox.
- Provider search is throttled or delayed.
- Messages have already been imported and are skipped as duplicates.
- Attachments are malformed, empty, encrypted, or not XML/ZIP/GZIP.

Actions:

1. Run **Test connection** and verify the selected folder exists.
2. Run a manual fetch from Mail Sources.
3. Open import history and inspect processed count, reports found, duplicates, errors, and details.
4. Search the mailbox manually for recent DMARC aggregate report subjects.
5. Upload a known-good report through the Reports page to confirm parsing still works.
6. Check logs for attachment parse errors or provider throttling.

## Gmail API Source Is Connected But Fetch Fails

Actions:

1. Reconnect the Gmail source.
2. Confirm the connected account email is the mailbox receiving reports.
3. Confirm the Google OAuth app still has the Gmail read-only scope configured.
4. Check whether the Google project or OAuth consent configuration changed.
5. Retry after a few minutes if the failure looks like quota or throttling.

DMARQ treats Gmail sources without a refresh token as requiring reauthorization.
The Mail Sources page, Dashboard report-intake card, and System Health page show
this as a reconnect action because scheduled polling and backfills need a refresh
token to continue after the short-lived access token expires.

## Webhook Imports Fail

Likely causes:

- `WEBHOOK_SECRET` mismatch between DMARQ and the email worker.
- Worker sends malformed base64 or raw message payload.
- The email has no supported DMARC attachment.
- Public URL or routing changed.

Actions:

1. Confirm `WEBHOOK_SECRET` is set in both systems through the secret manager.
2. Check DMARQ logs for webhook rejection reasons.
3. Confirm the worker points to the current DMARQ public URL.
4. Send a test message with a known-good DMARC aggregate attachment.
5. Rotate the webhook secret if it may have been exposed.

## DNS Health Looks Wrong

Actions:

1. Open the domain details page and refresh DNS health.
2. Check whether the DNS result is cached. Wait 15 minutes or use a refresh action after DNS changes.
3. Confirm the domain exists as a monitored domain even if no reports have arrived yet.
4. Add missing DKIM selectors manually when reports do not reveal all selectors.
5. For Cloudflare-managed domains, confirm the API token can read the zone.

## Database Or Migration Problems

Actions:

1. Stop the app before making manual database changes.
2. Confirm the latest backup exists and passes the relevant validation check.
3. For PostgreSQL, test connection from the app host using the same injected environment.
4. For SQLite, check file ownership and disk space.
5. Restore from [Database Backup and Restore](backups.md) if the app cannot safely continue.

## Notifications Do Not Send

Actions:

1. Open **Settings** > **Notifications** and send a test notification.
2. Confirm Apprise URLs are saved through the UI and are redacted in API responses.
3. Check logs for provider rejection or rate limiting.
4. Confirm outbound network access from the DMARQ host.
5. Rotate notification credentials if a target was exposed.

## When To Escalate

Open a follow-up issue with:

- Deployment mode and image tag or commit SHA.
- Health check result.
- Sanitized log excerpt.
- Mail source diagnostic category, if ingestion is involved.
- Whether a recent upgrade, migration, credential rotation, or DNS change happened.

Do not include raw secrets, mailbox contents, OAuth tokens, API tokens, database passwords, or full report files unless they have been sanitized.
