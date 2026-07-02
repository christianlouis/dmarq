# Cloudflare Email Worker Inbound Webhook

This guide shows how to route DMARC aggregate and failure report mail through
Cloudflare Email Routing into DMARQ's inbound webhook. Credit: inspired by
[yscheef/dmarq](https://github.com/yscheef/dmarq) and
[scheef-tech/dmarq](https://github.com/scheef-tech/dmarq) Cloudflare Email
Worker work, including commit `d19721f523`.

## Flow

```text
DMARC reporter mailbox
        |
        v
Cloudflare Email Routing (catch-all or address rule)
        |
        v
Cloudflare Email Worker (transform + POST)
        |
        v
DMARQ POST /api/v1/webhook/email  or  /api/v1/webhook/email/raw
        |
        v
DMARC attachment import (no DNS writes)
```

1. Configure Email Routing for the address that receives DMARC reports (for
   example `dmarc-reports@example.com`).
2. Bind an Email Worker to that route.
3. The Worker forwards the raw message to DMARQ with `X-Webhook-Secret`.
4. DMARQ parses supported DMARC attachments (`.xml`, `.zip`, `.gz`, `.gzip`)
   and imports aggregate reports into the database.

This webhook **imports reports only**. It does not publish or modify DNS
records, including Cloudflare-managed DMARC, SPF, or DKIM records. Cloudflare
DNS integration in DMARQ remains read-only unless an operator changes records
manually outside this flow.

## Prerequisites

- DMARQ deployed with a reachable HTTPS URL (for example
  `https://dmarq.example.com`).
- `WEBHOOK_SECRET` set in the DMARQ environment. See
  [Configuration](deployment/configuration.md#cloudflare-integration) and
  [Secret Handling with 1Password](deployment/secrets.md).
- Optional: `WEBHOOK_MAX_EMAIL_SIZE_MB` if your report attachments require a
  limit other than the 25 MB default.
- A Cloudflare zone with Email Routing enabled.
- An Email Worker bound to the DMARC report address.

Generate a secret (example only — store the real value server-side):

```bash
openssl rand -hex 32
```

Set the same value in DMARQ (`WEBHOOK_SECRET`) and in the Worker (for example
`env.WEBHOOK_SECRET`). Never commit secrets to git, Worker source repos, or
deployment notes.

## DMARQ webhook endpoints

Both routes require the `X-Webhook-Secret` header. The value must match
`WEBHOOK_SECRET` using a constant-time comparison.

| Route | Body | Purpose |
|-------|------|---------|
| `GET /api/v1/webhook/status` | Admin-authenticated JSON | Intake readiness, accepted endpoints, and payload limit without exposing the secret |
| `POST /api/v1/webhook/email` | JSON | Base64-encoded RFC 822 message |
| `POST /api/v1/webhook/email/raw` | Raw bytes | RFC 822 message as request body |

### JSON payload (`/api/v1/webhook/email`)

Required and optional fields match `EmailWebhookPayload` in the API:

| Field | Required | Description |
|-------|----------|-------------|
| `raw_email` | Yes | Base64-encoded RFC 822 bytes (`validate=True`) |
| `subject` | No | Subject fallback when the message has no usable `Subject` header |
| `from_address` | No | Informational; not required for import |
| `to_address` | No | Informational; not required for import |

Example request shape (placeholders only):

```json
{
  "raw_email": "<base64-encoded-rfc822-bytes>",
  "subject": "Report domain: example.com"
}
```

### Raw payload (`/api/v1/webhook/email/raw`)

Send the RFC 822 bytes as the HTTP request body. No JSON wrapper.

### Authentication and errors

| Condition | HTTP status | Detail |
|-----------|-------------|--------|
| `WEBHOOK_SECRET` unset in DMARQ | `503` | `Webhook ingestion is not configured.` |
| Missing or wrong `X-Webhook-Secret` | `401` | `Invalid webhook secret.` |
| Message body larger than `WEBHOOK_MAX_EMAIL_SIZE_MB` | `413` | `Webhook email payload is too large.` |
| Invalid base64 in `raw_email` | `400` | `raw_email must be valid base64.` |
| Unparseable email (raw path) | `400` | `Error processing email.` |

### Success response

On success (`200`), DMARQ returns:

```json
{
  "success": true,
  "subject": "DMARC Aggregate Report",
  "reports_found": 1,
  "imported": 1,
  "duplicates": 0,
  "errors": []
}
```

- `reports_found` — supported DMARC attachments detected.
- `imported` — new reports stored.
- `duplicates` — attachments matching an existing report id.
- `errors` — attachment filenames that failed parsing.

## Worker secret storage

Store secrets in Cloudflare Worker **secrets** or **vars** (encrypted), not in
committed Worker source:

```bash
# Example: set Worker secrets (replace names/values with your deployment)
wrangler secret put WEBHOOK_SECRET
wrangler secret put DMARQ_URL
```

Bind `DMARQ_URL` to your public DMARQ base URL (no trailing slash), for example
`https://dmarq.example.com`.

## Worker examples

Replace placeholders before deploy:

- `env.DMARQ_URL` — your DMARQ base URL
- `env.WEBHOOK_SECRET` — same value as DMARQ `WEBHOOK_SECRET`

### Option A — base64 JSON to `/api/v1/webhook/email`

```javascript
export default {
  async email(message, env, ctx) {
    const raw = new Uint8Array(await new Response(message.raw).arrayBuffer());
    let binary = "";
    for (const byte of raw) {
      binary += String.fromCharCode(byte);
    }
    const rawEmail = btoa(binary);

    const response = await fetch(`${env.DMARQ_URL}/api/v1/webhook/email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Webhook-Secret": env.WEBHOOK_SECRET,
      },
      body: JSON.stringify({
        raw_email: rawEmail,
        subject: message.headers.get("subject") || undefined,
        from_address: message.from,
        to_address: message.to,
      }),
    });

    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`DMARQ webhook failed (${response.status}): ${detail}`);
    }
  },
};
```

### Option B — raw RFC 822 to `/api/v1/webhook/email/raw`

```javascript
export default {
  async email(message, env, ctx) {
    const rawEmail = await new Response(message.raw).arrayBuffer();

    const response = await fetch(`${env.DMARQ_URL}/api/v1/webhook/email/raw`, {
      method: "POST",
      headers: {
        "Content-Type": "message/rfc822",
        "X-Webhook-Secret": env.WEBHOOK_SECRET,
      },
      body: rawEmail,
    });

    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`DMARQ webhook failed (${response.status}): ${detail}`);
    }
  },
};
```

Option B avoids base64 size overhead and is usually simpler for large ZIP/GZIP
attachments.

## Cloudflare Email Routing setup

1. In the Cloudflare dashboard, open **Email** > **Email Routing** for the zone.
2. Add or confirm the destination address (for example
   `dmarc-reports@example.com`).
3. Create an **Email Worker** route that sends matching mail to the Worker
   script above.
4. Confirm the Worker has secrets `WEBHOOK_SECRET` and `DMARQ_URL`.
5. Send a test message with a DMARC aggregate attachment and verify DMARQ
   returns `200` with `"imported": 1` or `"duplicates": 1`.

Supported aggregate formats are documented in
[DMARC Format Compatibility](reference/dmarc-compatibility.md).

## Local test

Run these from the `backend/` directory with DMARQ listening on
`http://localhost:8080` and `WEBHOOK_SECRET` set in the environment. Uses the
fixture pack at `app/tests/fixtures/dmarc_aggregate/rfc7489-google.xml`.

```bash
export WEBHOOK_SECRET=your-webhook-secret-here

python3 - <<'PY'
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from pathlib import Path

msg = MIMEMultipart()
msg["Subject"] = "DMARC Aggregate Report"
xml = Path("app/tests/fixtures/dmarc_aggregate/rfc7489-google.xml").read_bytes()
part = MIMEApplication(xml, _subtype="xml")
part.add_header(
    "Content-Disposition",
    "attachment",
    filename="google.com!example.com!1597449600!1597535999.xml",
)
msg.attach(part)
Path("/tmp/dmarc-webhook-test.eml").write_bytes(msg.as_bytes())
print("Wrote /tmp/dmarc-webhook-test.eml")
PY

# Raw RFC 822 endpoint
curl -sS -X POST "http://localhost:8080/api/v1/webhook/email/raw" \
  -H "X-Webhook-Secret: ${WEBHOOK_SECRET}" \
  --data-binary @/tmp/dmarc-webhook-test.eml

# Base64 JSON endpoint
B64=$(base64 < /tmp/dmarc-webhook-test.eml | tr -d '\n')
curl -sS -X POST "http://localhost:8080/api/v1/webhook/email" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: ${WEBHOOK_SECRET}" \
  -d "{\"raw_email\":\"${B64}\",\"subject\":\"DMARC Aggregate Report\"}"
```

Expected success body includes `"success": true` and `"reports_found": 1`.

## Troubleshooting

### `401 Invalid webhook secret`

- Confirm the Worker sends header `X-Webhook-Secret` (exact name, case
  insensitive).
- Confirm the value matches DMARQ `WEBHOOK_SECRET` with no extra whitespace.
- Rotate both sides if the secret may have been exposed.

### `503 Webhook ingestion is not configured`

- Set `WEBHOOK_SECRET` in DMARQ and restart the application so settings reload.

### `400 raw_email must be valid base64`

- Ensure the JSON field is named `raw_email` (not `raw` or `email`).
- Encode the full RFC 822 bytes with standard base64 and no invalid characters.
- On macOS/Linux, strip newlines when embedding in JSON:
  `base64 < file.eml | tr -d '\n'`.

### `200` with `"reports_found": 0`

- The message may have no attachment, or the filename extension is not
  `.xml`, `.zip`, `.gz`, or `.gzip`.
- Confirm the attachment uses `Content-Disposition: attachment`.

### `200` with `"errors": ["filename.xml"]`

- The attachment was recognized but failed parsing. Validate the XML against the
  fixture pack in `backend/app/tests/fixtures/dmarc_aggregate`.

### Cloudflare route or Worker binding issues

- Confirm Email Routing is active for the zone and the address receives mail.
- Confirm the Worker route matches the inbound address or catch-all rule.
- Check Worker logs in the Cloudflare dashboard for fetch errors to DMARQ.
- Confirm `DMARQ_URL` is reachable from Cloudflare (public HTTPS, valid TLS).

For general webhook import failures, see
[Webhook Imports Fail](deployment/troubleshooting.md#webhook-imports-fail).

## Related documentation

- [Configuration — Cloudflare Integration](deployment/configuration.md#cloudflare-integration)
- [DMARC Format Compatibility](reference/dmarc-compatibility.md)
- [Webhook Imports Fail](deployment/troubleshooting.md#webhook-imports-fail)
