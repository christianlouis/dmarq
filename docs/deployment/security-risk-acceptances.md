# Security Risk Acceptances

This register documents temporary dependency risks that cannot be removed safely
in the currently supported runtime. An entry is not a permanent exception. It
must have an owner, a review deadline, and concrete conditions that end the
acceptance.

## Debian `perl-base` in the Python runtime image

| Field | Decision |
| --- | --- |
| Status | Temporarily accepted |
| Recorded | 2026-07-16 |
| Review by | 2026-08-16, or the next base-image refresh, whichever comes first |
| Affected image | Official `python:3.13-slim` runtime base on Debian 13 (trixie) |
| Affected package | `perl-base` `5.40.1-6` |
| Tracked CVEs | CVE-2026-57432, CVE-2026-57433, CVE-2026-13221 |
| Owner | DMARQ maintainers |

### Rationale

- DMARQ does not execute Perl in its application, entrypoint, health checks, or
  scheduled report-ingestion paths. The package is inherited from the official
  Debian-based Python image.
- At the time of this decision, Debian's security tracker lists the trixie
  package as affected. CVE-2026-57432 and CVE-2026-57433 are fixed only in newer
  Debian suites, while CVE-2026-13221 has no fixed trixie package. See the
  Debian tracker entries for
  [CVE-2026-57432](https://security-tracker.debian.org/tracker/CVE-2026-57432),
  [CVE-2026-57433](https://security-tracker.debian.org/tracker/CVE-2026-57433),
  and [CVE-2026-13221](https://security-tracker.debian.org/tracker/CVE-2026-13221).
- Pulling the current official `python:3.13-slim` image does not remove the
  findings. Mixing packages from Debian testing or unstable into the trixie
  runtime would create a larger, unsupported dependency risk.
- The findings were reported as low severity. DMARQ's application, entrypoint,
  health checks, and supported HTTP surface do not invoke Perl or expose an
  arbitrary process-execution feature.

### Required controls

- Continue rebuilding release images from the current official Python base so a
  fixed Debian package is inherited as soon as it becomes available.
- Retain `no-new-privileges` in the supported Docker Compose deployment and the
  equivalent privilege-escalation restriction in Kubernetes deployments.
- Scan the immutable release image during the release gate and compare the
  installed `perl-base` version with the Debian tracker.
- Do not add Perl scripts or user-controlled process execution to the runtime
  while this acceptance is active.

### Exit conditions

End this acceptance and rebuild all published image tags when any of the
following occurs:

1. Debian trixie or the official Python slim image publishes a fixed package.
2. A scanner raises the severity above low or shows an application-reachable
   exploit path.
3. DMARQ begins invoking Perl in a supported runtime path.
4. The review deadline is reached without a fresh documented assessment.

## Debian `libsqlite3-0` in the Python runtime image

| Field | Decision |
| --- | --- |
| Status | Temporarily accepted and tracked in [issue #805](https://github.com/christianlouis/dmarq/issues/805) |
| Recorded | 2026-07-15 |
| Review by | 2026-08-16, or the next base-image refresh, whichever comes first |
| Affected image | Official `python:3.13-slim` runtime base on Debian 13 (trixie) |
| Affected package | `libsqlite3-0` `3.46.1-7+deb13u1` |
| Tracked CVEs | CVE-2026-50812, CVE-2026-50813 |
| Owner | DMARQ maintainers |

### Rationale

- Snyk reported both findings as low severity in the inherited runtime package.
- DMARQ uses SQLite through Python and SQLAlchemy for supported single-container
  installations; removing SQLite would break the documented deployment mode.
- A recheck of `ghcr.io/christianlouis/dmarq:docker-latest` on 2026-07-18
  found the same installed version as Debian's current trixie candidate.
- No fixed Debian trixie package or safe application-side remediation was
  available at the last review. Mixing packages from another Debian suite
  would create a larger, unsupported runtime dependency risk.

### Required controls

- Rebuild release images from the current official Python base so a fixed
  package is inherited as soon as Debian publishes one.
- Scan immutable release images during the release gate and record the
  installed `libsqlite3-0` version against issue #805.
- Keep the documented PostgreSQL deployment option available for operators
  who require a database without the embedded SQLite runtime package.
- Do not expose SQLite or arbitrary SQL execution through the HTTP surface.

### Exit conditions

End this acceptance and rebuild all published image tags when any of the
following occurs:

1. Debian trixie or the official Python slim image publishes a fixed package.
2. A supported base image contains a fixed SQLite version without cross-suite
   package mixing.
3. A scanner raises the severity or shows an application-reachable exploit path.
4. The review deadline is reached without a fresh documented assessment.
