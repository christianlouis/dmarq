# Protocol Coverage Plan

DMARQ's core scope remains DMARC report ingestion, DNS posture guidance, and
human-approved remediation. Adjacent protocols are useful when they improve mail
health evidence for domain owners, but they should not turn DMARQ into a hosted
mail-transfer service.

## In Scope Now

### DANE/TLSA

DMARQ supports passive DANE posture checks for SMTP delivery:

- discover MX hosts for a monitored domain.
- query `_25._tcp.<mx-host>` TLSA records.
- lint TLSA syntax for certificate usage, selector, matching type, and
  hexadecimal association data.
- show missing, partial, invalid, and syntactically valid coverage in DNS lint.
- expose a read-only API endpoint at `GET /domains/{domain_id}/dns/dane`.
- when MX STARTTLS is reachable, derive optional TLSA `3 1 1` SPKI SHA-256
  suggestions from the presented certificate.
- compare existing DANE-EE/SPKI/SHA-256 TLSA records with the live certificate
  and flag stale data.
- generate manual remediation steps and target-record shape without applying
  DNS writes.

Boundaries:

- DMARQ does not yet validate DNSSEC chains.
- DMARQ does not automatically publish TLSA records.

DANE is therefore a hygiene and readiness signal, not a delivery guarantee.

### ARF for DMARC Failure Reports

DMARQ already consumes DMARC forensic/RUF failure reports that arrive as
`multipart/report` messages with `message/feedback-report` parts. It stores
redacted metadata needed for DMARC operations and avoids raw message-body
storage.

Supported metadata includes RFC 9991 failure fields, redacted original-message
headers, canonicalized-DKIM presence flags, and passive ARC header presence from
the redacted original header sample when receivers include it.

Boundaries:

- DMARQ consumes inbound reports; it does not generate outbound ARF reports for
  other receivers.
- Generic abuse-desk ARF processing is out of scope unless the report contains
  DMARC/RUF-relevant evidence.
- DMARQ records ARC metadata as diagnostic context only. ARC does not override
  aggregate DMARC pass/fail evidence or change domain health scoring.

## Next Design Slices

### ARC

ARC support starts as message/report metadata analysis, not DNS automation.
The shipped first slice records ARC header presence in RUF/forensic metadata.
Useful follow-up slices:

- explain when ARC may affect forwarded mail interpretation.
- keep ARC separate from DMARC pass/fail scoring unless DMARQ has explicit
  receiver-side evidence.

### Deeper DANE Validation

Future DANE work can add:

- DNSSEC validation evidence.
- live SMTP STARTTLS certificate retrieval.
- TLSA hash comparison against the presented certificate or SPKI.
- certificate rotation warnings.

Those features require network-safety controls and should remain read-only until
operators explicitly approve any DNS changes.
