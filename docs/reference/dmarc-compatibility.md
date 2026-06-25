# DMARC Aggregate Format Compatibility

DMARQ imports DMARC aggregate reports from direct uploads, IMAP attachments, Gmail API attachments, and the Cloudflare Email Worker webhook. Compatibility is locked by the fixture pack in `backend/app/tests/fixtures/dmarc_aggregate`.

## Supported Aggregate Inputs

- Plain XML files with a `.xml` extension.
- ZIP archives containing an XML report.
- GZIP archives with `.gz` or `.gzip` extensions.
- RFC 7489-compatible aggregate reports without XML namespaces.
- Namespaced aggregate reports using `urn:ietf:params:xml:ns:dmarc-2.0`.
- RFC 9990-style reports with optional metadata such as `version`, `generator`, `extra_contact_info`, repeated `error` values, `np`, `fo`, `testing`, `discovery_method`, `envelope_to`, policy override reasons, `human_result`, SPF `scope`, and namespaced extension elements.

## Supported Policy Discovery

Live DNS checks parse DMARC policy records according to RFC 9989:

- `v=DMARC1` must be the first tag and keeps its case-sensitive value.
- Multiple valid DMARC policy records at the same DNS target are treated as ambiguous and ignored.
- Active DMARCbis tags are parsed for diagnostics: `p`, `sp`, `np`, `psd`, `t`, `rua`, `ruf`, `fo`, `adkim`, and `aspf`.
- Historic tags such as `pct`, `rf`, and `ri` are not treated as active DMARCbis policy tags.
- Subdomain checks fall back to the bounded RFC 9989 DNS Tree Walk, including `psd=n` and `psd=y` stop conditions.
- Records with a valid aggregate reporting URI but no valid `p` tag are treated as monitoring mode for policy extraction.

## Preserved Metadata

Newer optional fields are parsed without changing the legacy response shape that existing screens use. When a database is configured, DMARQ also persists the optional report metadata, policy metadata, record identifiers, policy override reasons, and extension payloads so exports and future views can use them.

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

## Fixture Pack

The current fixture pack covers:

- `rfc7489-google.xml`: legacy no-namespace aggregate report.
- `rfc9990-namespaced-legacy-fields.xml`: namespaced aggregate report that keeps legacy fields working.
- `rfc9990-treewalk-extension.xml`: RFC 9990-style policy metadata, treewalk discovery, `envelope_to`, override reasons, auth-result details, and report/record extensions.
- `rfc9990-multi-auth-overrides.xml`: multiple records, multiple DKIM auth results, policy override reasons, PSD-style discovery, and nested vendor extensions.

The compatibility tests exercise every fixture through parser extraction, upload import, IMAP attachment import, and Gmail attachment import.

## Adding Fixtures

1. Add the XML file under `backend/app/tests/fixtures/dmarc_aggregate`.
2. Add its expected metadata to `DMARC_COMPATIBILITY_FIXTURES` in `backend/app/tests/test_data.py`.
3. Include a unique `report_id`, stable domain, expected variant, expected total count, and any policy fields that should be asserted.
4. Run `pytest backend/app/tests/test_dmarc_compatibility_fixtures.py backend/app/tests/test_dmarc_parser.py backend/app/tests/test_reports_api.py`.
