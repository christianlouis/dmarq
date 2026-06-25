# DMARC Scope Open Items

DMARQ's DMARC scope is report parsing, report analysis, DNS configuration guidance,
and DNS linting. DMARQ does not act as a Mail Receiver and should not implement
DMARC message enforcement or outbound aggregate/failure report generation.

## In Scope

- [x] Parse RFC 9989 policy records and discover effective DMARC policy with DNS Tree Walk.
- [x] Parse RFC 9990 aggregate reports while preserving useful optional metadata.
- [x] Parse inbound RFC 9991 failure reports without retaining message bodies.
- [x] Lint external `rua` / `ruf` destinations for required DNS authorization records.
- [x] Add a first-class DNS lint endpoint with typed findings and stable machine-readable codes.
- [x] Add DNS-setting generation helpers for DMARC, SPF include/all choices, DKIM selector checks, MTA-STS, TLS-RPT, and BIMI readiness.
- [x] Add UI sections that show lint findings next to the current DNS records and suggested target records.
- [x] Add bulk domain linting and export for managed-domain reviews.
- [x] Expand aggregate fixture coverage for representative RFC 9990/DMARCbis variants and unknown-but-safe fields.
- [ ] Expand fixture coverage with additional real-world aggregate/failure samples from more report generators.

## Implemented DNS Guidance Surfaces

- `GET /api/v1/domains/{domain}/dns/lint` returns typed findings and target records for one domain.
- `GET /api/v1/domains/dns/lint` returns bulk typed findings for monitored domains.
- `GET /api/v1/domains/dns/lint/export` exports bulk findings as CSV for managed-domain review.

## Out of Scope

- Mail Receiver-side DMARC enforcement.
- Outbound DMARC aggregate report generation.
- Outbound DMARC failure report generation.
- Receiver-side failure-report rate limiting.
