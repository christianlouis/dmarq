# Cloudflare DMARC Email Relay

This Email Worker provides a low-dependency Cloudflare intake path for an
existing DMARQ mailbox source:

```text
DMARC reporter -> dmarc@example.com -> Email Worker -> connected mailbox -> DMARQ
```

The Worker preserves the original RFC 822 message and its XML, ZIP, or GZIP
attachments. It only accepts the configured collector recipient and forwards
to a destination address that has already been verified in Cloudflare Email
Routing.

## Configure

1. Copy `wrangler.jsonc` and replace both example addresses.
2. Verify `DESTINATION_ADDRESS` in Cloudflare Email Routing.
3. Deploy the Worker with `npx wrangler deploy`.
4. Create a custom Email Routing rule from `COLLECTOR_ADDRESS` to the Worker.
5. Add the collector to each domain's DMARC `rua` tag without removing existing
   destinations.
6. For an external collector domain, publish the required authorization TXT
   record at `<policy-domain>._report._dmarc.<collector-domain>` with the exact
   TXT value `v=DMARC1;`.
7. Trigger the connected DMARQ mailbox source and confirm the report is
   imported.

Run the isolated unit tests with `npm test`.

## Direct webhook alternative

For installations that should not depend on a mailbox, use the authenticated
raw-message Worker documented in
[`docs/cloudflare-email-worker-inbound-webhook.md`](../../../docs/cloudflare-email-worker-inbound-webhook.md).
That mode requires the same `WEBHOOK_SECRET` in DMARQ and the Worker.
