# DMARC Format Compatibility

DMARQ imports DMARC aggregate reports from direct uploads, IMAP attachments, Gmail API attachments, and the Cloudflare Email Worker webhook. Compatibility is locked by the fixture pack in `backend/app/tests/fixtures/dmarc_aggregate`.

## Supported Aggregate Inputs

- Plain XML files with a `.xml` extension.
- ZIP archives containing an XML report.
- GZIP archives with `.gz` or `.gzip` extensions.
- RFC 7489-compatible aggregate reports without XML namespaces.
- Namespaced aggregate reports using `urn:ietf:params:xml:ns:dmarc-2.0`.
- RFC 9990-style reports with optional metadata such as `version`, `generator`, `extra_contact_info`, repeated `error` values, `np`, `fo`, `testing`, `discovery_method`, `envelope_to`, policy override reasons, `human_result`, SPF `scope`, and namespaced extension elements.

## Supported Failure Report Inputs

DMARQ consumes inbound DMARC failure reports through its forensic/RUF pipeline. This is RFC 9991 receiver-side support for operators who receive reports, not outbound generation of failure reports.

- `multipart/report` messages with `report-type=feedback-report`.
- ARF feedback parts using `message/feedback-report`.
- Original-message metadata supplied as `text/rfc822-headers` or `message/rfc822`; message bodies are not stored.
- RFC 9991 DMARC failure metadata including `Auth-Failure: dmarc`, `Identity-Alignment`, `Delivery-Result`, `DKIM-Domain`, `DKIM-Identity`, `DKIM-Selector`, `SPF-DNS`, and `Reported-URI`.
- Canonicalized DKIM header/body fields are treated as sensitive content. DMARQ records presence flags for diagnostics but does not persist their values.

## Forensic/RUF Privacy Model

Forensic/RUF reports can contain fragments of real user messages. DMARQ
therefore treats them as a metadata-only signal for receiver-side diagnostics.

DMARQ may persist:

- report identifiers generated from hashed `Message-ID` values or one-way
  content hashes.
- reporter address after the configured redaction policy is applied.
- reported domain, source IP, authentication failure type, delivery result, and
  arrival date.
- redacted original envelope/header metadata such as `Original-Mail-From`,
  `From`, `To`, `Subject`, and hashed `Message-ID`.
- RFC 9991 diagnostic metadata such as alignment, DKIM domain, DKIM selector,
  SPF DNS text, and `Reported-URI`.
- boolean flags that canonicalized DKIM header/body fields were present.

DMARQ must not persist:

- raw message bodies.
- raw original-message MIME payloads from `message/rfc822` or
  `text/rfc822-headers` parts.
- raw canonicalized DKIM header or body values.
- raw local-parts when the configured redaction policy would mask them.
- long opaque tokens found in subjects or headers when token redaction is
  enabled.
- OAuth tokens, mailbox passwords, webhook secrets, or provider error payloads
  containing secrets.

Unsupported or non-forensic messages fail closed: the forensic parser rejects
empty, oversized, and non-DMARC payloads, while accepting only messages that
match the supported DMARC failure-report signals above. Those signals include
ARF feedback parts, `text/rfc822-headers` with DMARC context, or DMARC
failure/forensic/RUF subject metadata. Accepted forensic/RUF reports are counted
separately from aggregate report totals through `forensic_reports_found` and
`duplicate_forensic_reports`.

## Supported Policy Discovery

Live DNS checks parse DMARC policy records according to RFC 9989:

- `v=DMARC1` must be the first tag and keeps its case-sensitive value.
- Multiple valid DMARC policy records at the same DNS target are treated as ambiguous and ignored.
- Active DMARCbis tags are parsed for diagnostics: `p`, `sp`, `np`, `psd`, `t`, `rua`, `ruf`, `fo`, `adkim`, and `aspf`.
- Historic tags such as `pct`, `rf`, and `ri` are not treated as active DMARCbis policy tags.
- Subdomain checks fall back to the bounded RFC 9989 DNS Tree Walk, including `psd=n` and `psd=y` stop conditions.
- Records with a valid aggregate reporting URI but no valid `p` tag are treated as monitoring mode for policy extraction.
- External `rua` and `ruf` destinations are linted for the required DNS authorization TXT record at `<policy-domain>._report._dmarc.<destination-domain>`.
- Typed DNS guidance endpoints expose stable finding codes and target records for DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and BIMI readiness without applying DNS changes automatically.

## Preserved Metadata

Newer optional fields are parsed without changing the legacy response shape that existing screens use. When a database is configured, DMARQ also persists the optional aggregate report metadata, policy metadata, record identifiers, policy override reasons, extension payloads, and redacted failure-report diagnostics so exports and future views can use them.

CSV exports include the most useful aggregate metadata for operators:

- `subdomain_policy`
- `non_subdomain_policy`
- `adkim`
- `aspf`
- `failure_options`
- `testing`
- `discovery_method`
- `schema_version`
- `report_variant`
- `generator`

## Known Edge Cases

- Unknown namespaced extension fields are preserved as best-effort key/value data after namespace prefixes are stripped by the XML parser.
- Malformed optional timestamps and counts use safe defaults so one bad optional value does not reject the whole report.
- Reports with no `<record>` elements import with a zero-count summary.
- Unsupported attachments are skipped by IMAP and Gmail import paths and recorded in import details when stats are available.
- For duplicate detection, DMARQ uses the domain and `report_id` pair. Fixture report IDs must remain unique within a single test import run.
- RFC 9991 describes report generation duties such as outbound rate limiting and external `ruf` destination verification for Mail Receivers. DMARQ currently implements report-consumer parsing and analysis, not report generation.
- The product-scope backlog for parser, analyzer, DNS guidance, and DNS linting work is tracked in `docs/development/dmarc-scope-open-items.md`.

## Fixture Pack

The current fixture pack covers:

- `rfc7489-google.xml`: legacy no-namespace aggregate report.
- `rfc9990-namespaced-legacy-fields.xml`: namespaced aggregate report that keeps legacy fields working.
- `rfc9990-treewalk-extension.xml`: RFC 9990-style policy metadata, treewalk discovery, `envelope_to`, override reasons, auth-result details, and report/record extensions.
- `rfc9990-multi-auth-overrides.xml`: multiple records, multiple DKIM auth results, policy override reasons, PSD-style discovery, and nested vendor extensions.

The compatibility tests exercise every fixture through parser extraction, upload import, IMAP attachment import, Gmail attachment import, dashboard projection, CSV export, and unknown safe extension handling.

## Adding Fixtures

1. Add the XML file under `backend/app/tests/fixtures/dmarc_aggregate`.
2. Add its expected metadata to `DMARC_COMPATIBILITY_FIXTURES` in `backend/app/tests/test_data.py`.
3. Include a unique `report_id`, stable domain, expected variant, expected total count, and any policy fields that should be asserted.
4. Run `pytest backend/app/tests/test_dmarc_compatibility_fixtures.py backend/app/tests/test_dmarc_parser.py backend/app/tests/test_reports_api.py`.
