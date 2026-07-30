# Report intake options

DMARQ can analyze an existing aggregate report immediately or monitor a report
destination continuously. The guided setup ranks the supported paths from the
operator's saved goals, data-path preference, setup-effort preference, known
mail provider, and persisted intake state. It does not create a mailbox, change
DNS, deploy a Worker, or authorize a provider automatically.

The recommendation is deterministic and secret-free. It reports who processes
the data, which credentials or scopes are needed, whether DMARQ must be publicly
reachable, expected failure modes, and one bounded connection test. Alternatives
remain available under **Compare alternatives**.

## First-report journey

The setup distinguishes these states:

- **Setup required**: no continuous source is enabled.
- **Waiting**: a source is enabled, but no aggregate report has arrived yet.
  Low-volume domains may remain here until a participating receiver observes
  mail and sends its next aggregate report.
- **Working**: at least one aggregate report is stored.
- **Duplicate**: DMARQ received a report it had already stored and safely did
  not add its message totals again.
- **Rejected**: the intake reached DMARQ, but the message or attachment could
  not be parsed. Import history contains the bounded error evidence.

An intake path is verified when its component connection succeeds, DMARQ
accepts or safely deduplicates a report, and the operator can open the first
interpretation. Authentication reports are not proof that a particular message
was delivered, bounced, placed in spam, or read.

This chooser covers DMARC **aggregate** reports. Failure or forensic reports
can include message-specific headers, addresses, subjects, or samples depending
on the sender and receiver. Treat their collection as a separate privacy and
retention decision; selecting an aggregate-report intake path does not enable
failure-report collection.

## Existing report upload

Upload an XML, ZIP, or GZIP aggregate report when evaluating DMARQ or when no
continuous mailbox is available. No credentials or public DMARQ URL are needed.
Later reports must be uploaded again.

## Local or self-hosted IMAP

DMARQ polls a dedicated report mailbox over plain IMAP, STARTTLS, or implicit
TLS according to the source settings. Scope the credentials to that mailbox.
DMARQ does not need a public URL, but it must be able to reach the IMAP server.

## Proton Mail Bridge

Proton Mail Bridge exposes a Proton mailbox through a local IMAP endpoint.
DMARQ uses Bridge-generated credentials, not the Proton account password. The
Bridge must run continuously close enough to DMARQ for its local endpoint to be
reachable. Guided setup recommends this path only when the operator confirms
that a local Bridge is available.

## Gmail OAuth

Gmail OAuth provides revocable delegated access without storing a mailbox
password in DMARQ. Configure the OAuth callback for the deployed URL, authorize
the report mailbox, test the source, and run a bounded backfill.

## Microsoft 365 Graph

Microsoft 365 can use delegated access or unattended Entra application access.
Application access needs a tenant ID, application ID, credential, and Exchange
Online mailbox scope. Restrict `Mail.Read` to the report mailbox with Exchange
Online RBAC or an application access policy instead of granting unrestricted
tenant-wide mailbox access.

## Cloudflare Email Routing and Worker

Cloudflare Email Routing can pass the raw RFC-822 report message to an Email
Worker. The Worker then posts it to DMARQ's authenticated raw-email endpoint.
This path requires a publicly reachable HTTPS DMARQ URL and a dedicated inbound
webhook secret. The Worker needs no DNS write permission.

The existing [Cloudflare Email Worker guide](../cloudflare-email-worker-inbound-webhook.md)
contains the deployment and connection test. The intake recommendation remains
unavailable until public HTTPS is configured; this prevents a setup path that
cannot complete its own smoke test.

## AWS SES Receipt and Lambda

Amazon SES can receive report mail in a supported region and invoke a Lambda
function that forwards the raw RFC-822 message to DMARQ. This requires a
verified SES domain, receipt rule, bounded IAM roles, retry handling, a public
HTTPS DMARQ endpoint, and a dedicated webhook secret. Use this path when the
AWS operating model is already intentional; it is more complex than mailbox
intake.

## Generic authenticated raw-email webhook

An existing mail gateway may send complete RFC-822 messages to DMARQ's raw
inbound endpoint. The gateway owns message transformation, payload limits,
retry behavior, and delivery evidence. DMARQ requires reachable HTTPS and a
separate `X-Webhook-Secret` for this endpoint.

## Security boundaries

- API responses never contain source passwords, OAuth tokens, client secrets,
  or the webhook secret.
- Choosing an option stores only its stable identifier and non-secret setup
  preferences in the versioned workspace profile.
- Reading a recommendation needs report-read access. Updating preferences
  needs workspace-write access.
- No recommendation grants provider permissions, performs a live connection,
  changes DNS, or enables an unavailable public endpoint.
