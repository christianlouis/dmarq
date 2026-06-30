# Migrating from another DMARC platform

DMARQ supports a safe parallel-reporting migration. Keep the current DMARC
monitoring platform active, add DMARQ as an additional aggregate-report
destination, compare the overlap window, and only then remove old routes or
delegations.

## Parallel-reporting checklist

1. Add DMARQ as an additional `rua` destination in the existing DMARC record.
2. Keep the current tool active for at least 14 distinct report days.
3. Compare report volume, sending sources, alignment rates, and policy posture.
4. Resolve or explicitly defer DNS lint findings before decommissioning the old
   platform.
5. Export DMARQ report CSV and health evidence before changing the old tool's
   DNS routing.

The domain detail page includes a **Migration Readiness** panel. It tracks the
parallel-reporting window, aggregate report count, observed sending sources,
DNS lint status, and export availability for each domain.

The same panel includes **Migration Parity**. Enter values from the same date
window in the current DMARC platform to compare:

- aggregate report count
- message volume
- observed sending sources
- alignment or compliance rate
- DMARC policy posture

If no legacy baseline is entered, DMARQ marks the comparison as
`baseline_needed` rather than claiming parity. Keep dual `rua` reporting active
until the parity signals are either matched, explained, or intentionally
accepted.

## Historical export preview

Use the read-only migration import preview before relying on historical exports
from another DMARC platform. The preview accepts CSV or JSON content, detects
common export columns, normalizes a sample of rows, and suggests baseline values
for the Migration Parity panel:

- aggregate report count
- message volume
- observed sending source count
- compliance or alignment rate
- most common DMARC policy
- first and last observed dates where present

The preview does not create domains, write aggregate reports, or modify DNS.
It is intentionally safe to run against vendor exports while planning a
cutover. Review warnings for missing columns, rows from other domains, or
truncated previews before using the suggested baseline values.

## Platform-specific notes

For Valimail, EasyDMARC, dmarcian, PowerDMARC, DMARCguard, and manual mailbox
workflows, prefer adding DMARQ as a second `rua` receiver first. Avoid switching
MX, mailbox, or delegated reporting DNS in one step unless you already have a
separate rollback plan.

When the previous platform used hosted reporting addresses or DNS delegation,
document the old route before removal. Some platforms require removing a
delegated `_dmarc` or reporting authorization record after the overlap period.

## Data portability

DMARQ currently provides these portable exports for migration and offboarding:

- domain aggregate report CSV from the domain detail page
- domain health evidence as CSV or JSON
- workspace health evidence as CSV or JSON
- DNS lint CSV for managed-domain reviews

These exports intentionally avoid raw message bodies and forensic content.
They are meant for parity checks, audit evidence, and rollback decisions.

## Import limitations

DMARQ can ingest standard DMARC aggregate reports through upload, IMAP, Gmail,
and Microsoft 365 mail sources. Vendor-specific historical export persistence is
tracked as follow-up work. Until a write importer exists, use the migration
preview and parity dashboard as comparison artifacts while DMARQ builds its own
evidence from newly received aggregate reports.
