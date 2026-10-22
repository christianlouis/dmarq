# Timestamp wire and display contract

DMARQ stores and compares instants in UTC. Existing naive database `datetime`
values represent UTC, not the operating system or browser timezone. This change
does not migrate stored timestamps or change polling/backfill duration math.

## API and exports

- Serialize datetime instants with `app.core.app_timezone.ensure_utc(value).isoformat()`
  at dictionary/export boundaries, retaining nulls as null. It emits ISO 8601
  with an explicit UTC offset.
- Mail-source, import-history and backfill response builders normalize stored
  datetimes with `ensure_utc` before Pydantic serialization. They carry UTC;
  consumers render those instants using `APP_TIMEZONE`, not the browser zone.
- Keep calendar dates (`YYYY-MM-DD`), integer Unix timestamps, durations, and
  identity/idempotency keys in their existing formats. Do not apply the datetime
  serializer to date-only values or add timezone offsets to duration counts.
- Incoming backfill values still normalize to UTC before persistence. Existing
  request parsing and stored audit details are not rewritten retroactively.

## UI

`localization.js`, loaded before `base-layout.js` and page scripts, owns the
shared date parser/formatter. The existing datetime helper in `base-layout.js`
delegates to it when available:

- `dmarqFormatDateTime(value, fallback)` formats instants in `APP_TIMEZONE` and the
  selected locale, independent of the browser's timezone.
- `dmarqFormatDate(value, options)` formats instant dates in the same application
  timezone, but preserves `YYYY-MM-DD` calendar labels without day shifts.
- Pass original ISO strings, epoch milliseconds, or already-correct `Date`
  objects. Do not parse naive ISO timestamps with browser-local `new Date(...)`
  before calling the formatter. Legacy offset-free ISO datetime strings are
  explicitly interpreted as UTC by the shared parser.
- IANA timezone rules handle winter/summer time and DST transitions. No fixed
  UTC offset is applied. Invalid timezone configuration falls back to UTC.

## Audited surfaces

The audited outbound datetime paths include mail-source status, history and
backfills; operational health; DNS posture/baselines/changes; alert and audit
history; delivery/forensic/TLS report metadata; incident and webhook history;
API-token/export metadata; workspace/operator and usage-export metadata;
process poll status and statistics-cache creation metadata.
Their corresponding active page displays use the shared application-zone
formatters, including the settings page's inline timestamp labels.

Intentional exclusions:

- Database columns, scheduler comparisons, retention calculations, duration
  counters, and internal persisted DNS provenance remain unchanged.
- Daily report/health buckets, calendar filter labels, billing period identity
  keys, and date-only CSV columns remain calendar values.
- Already-aware upstream/provider timestamps remain valid; no arbitrary string
  rewriting or response middleware is used.
- The separate report epoch/import conversion work tracked in PR #993 is not
  duplicated here. The unused legacy `dashboard.js` SPA is not loaded by active
  templates and is not changed.

Regression coverage includes real mail-source/history/backfill JSON responses,
UTC export boundaries and unchanged identity keys, naive legacy values,
winter/summer offsets, both DST transitions, day rollover, null/invalid values,
browser timezones that differ from the application timezone, and non-UTC
server clocks.
