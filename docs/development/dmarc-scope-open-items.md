# DMARC Scope Open Items

DMARQ's DMARC scope is report parsing, report analysis, DNS configuration guidance,
and DNS linting. DMARQ does not act as a Mail Receiver and should not implement
DMARC message enforcement or outbound aggregate/failure report generation.

## In Scope

- [x] Parse RFC 9989 policy records and discover effective DMARC policy with DNS Tree Walk.
- [x] Parse RFC 9990 aggregate reports while preserving useful optional metadata.
- [x] Parse inbound RFC 9991 failure reports without retaining message bodies.
- [x] Lint external `rua` / `ruf` destinations for required DNS authorization records.
- [ ] Add a first-class DNS lint endpoint with typed findings and stable machine-readable codes.
- [ ] Add DNS-setting generation helpers for DMARC, SPF include/all choices, DKIM selector checks, MTA-STS, TLS-RPT, and BIMI readiness.
- [ ] Add UI sections that show lint findings next to the current DNS records and suggested target records.
- [ ] Add bulk domain linting and export for managed-domain reviews.
- [ ] Expand fixture coverage with real-world DMARCbis aggregate/failure samples from more report generators.

## Out of Scope

- Mail Receiver-side DMARC enforcement.
- Outbound DMARC aggregate report generation.
- Outbound DMARC failure report generation.
- Receiver-side failure-report rate limiting.
