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

### Cutover decision gates

Do not remove the previous DMARC platform just because the first DMARQ report
arrived. Use these gates instead:

| Gate | Ready when | Keep both tools when |
| --- | --- | --- |
| Reporting overlap | DMARQ has at least 14 report days for active domains | reports are sparse, delayed, or missing major receivers |
| Volume parity | DMARQ and the previous tool show explainable message-volume differences | one tool has materially higher volume with no known cause |
| Sender parity | Active legitimate senders appear in both tools or are explained | a provider, self-hosted MTA, or forwarding path is missing |
| Alignment parity | Pass/fail rates are close enough for the same date window | failures differ and no receiver/reporting explanation exists |
| DNS posture | DMARC, SPF, DKIM, MTA-STS/TLS-RPT/BIMI findings are reviewed | unresolved DNS lint findings affect legitimate mail |
| Rollback evidence | Old routes, reporting addresses, and delegated records are documented | the old platform uses managed DNS or opaque hosted routes |

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

The domain detail page includes a **Historical Export Preview** panel for this
flow. Paste a CSV or JSON export, or load the sample export in demo mode, then
review the detected columns, warnings, row status, duplicate counts, and
suggested parity baseline. Use **Use suggested baseline** to copy those values
into Migration Parity for the same domain.

The preview does not create domains, write aggregate reports, or modify DNS.
It is intentionally safe to run against vendor exports while planning a
cutover. Review warnings for missing columns, duplicate rows, rows from other
domains, or truncated previews before using the suggested baseline values.

Preview responses also include an import plan with stable identifiers:

- `batch_fingerprint` identifies the normalized export sample.
- `row_key` identifies each normalized row.
- `report_import_key` identifies the aggregate report a row would belong to.
- `import_status` shows whether a row is `planned`, already covered by an
  `existing_report`, or blocked as `needs_report_id`.

Use those values to verify that a vendor export can be handled idempotently.
Rows marked `existing_report` are already present for the selected workspace,
and rows marked `needs_report_id` should not be used for a confirmed import
until the source export provides a stable report identifier.

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

## Current implementation status

The safe migration workflow is complete for planning, parity review, preview,
and offboarding evidence:

- parallel-reporting guidance and cutover gates
- domain-detail migration readiness
- migration parity baseline comparison
- read-only CSV/JSON historical export preview
- stable row and report import keys for idempotency review
- CSV/JSON evidence exports for leaving DMARQ

DMARQ does not yet persist vendor-specific historical exports into aggregate
report storage. That should remain a separate explicit feature because it needs
operator-confirmed field mapping, duplicate handling, and rollback behavior.

## Import limitations

DMARQ can ingest standard DMARC aggregate reports through upload, IMAP, Gmail,
and Microsoft 365 mail sources. Vendor-specific historical export persistence is
tracked as follow-up work. Until a write importer exists, use the migration
preview and parity dashboard as comparison artifacts while DMARQ builds its own
evidence from newly received aggregate reports.
