# Release Checklist

Use this checklist for every DMARQ release or production upgrade. It focuses on the work that most often causes avoidable downtime: database migrations, test coverage, release automation, and smoke checks.

For the full deploy, verification, rollback, and routine operations runbook, see [Operator Runbook](operations.md). For incident-specific recovery steps, see [Troubleshooting Playbooks](troubleshooting.md).

## Before Merging

Confirm the release candidate is ready:

- The pull request describes user impact, operator impact, and any migration or configuration changes.
- Local tests pass with `PYTHONPATH=backend python -m pytest`.
- Formatting and lint checks pass, or the PR explains any advisory-only lint warnings.
- New or changed environment variables are documented in deployment docs.
- New secrets are stored through the deployment secret manager, not committed to files or copied into PR text.
- Database model changes include Alembic migration coverage or a clear reason no migration is needed.
- The database backup guide has been followed for production upgrades.

## Migration Review

Before merging a change that touches database models, migrations, import paths, or report persistence:

1. Inspect the migration files and confirm they match the model change.
2. Test a fresh database with `alembic upgrade head`.
3. Test an existing database upgrade from the current released version when possible.
4. Confirm downgrade or rollback expectations are documented if the change is risky.
5. Create a fresh production backup before deployment.

## Merge And Release

DMARQ releases from the `main` branch through GitHub Actions.

1. Use a conventional merge commit subject:
   - `fix:` for patch releases.
   - `feat:` for minor releases.
   - `feat!:` or `BREAKING CHANGE` for major releases.
   - `docs:` for documentation-only changes that do not need a new app version.
2. Watch the Release workflow.
3. Watch the CI workflow through lint, tests, security scan, CodeQL, Docker build, and preprod manifest update.
4. If the preprod manifest update fails because the k8s state repo moved during the run, rerun the failed job after confirming the image build succeeded.
5. Pull tags locally after release automation completes.

## Smoke Checks

Run these checks after the deployment updates:

```bash
curl -fsS https://your-dmarq-host.example.com/health
curl -fsS https://your-dmarq-host.example.com/api/v1/health
```

Then verify in the browser:

- The login or setup page loads as expected.
- The dashboard loads without server errors.
- Domain totals and recent reports are visible.
- Mail Sources opens and recent import history is visible.
- A manual mailbox fetch can be triggered in preprod or another safe environment.
- CSV export works for at least one domain with reports.

Check logs after smoke testing:

```bash
docker compose logs --tail=100 backend
```

For systemd deployments:

```bash
sudo journalctl -u dmarq -n 100
```

There should be no repeated database, migration, authentication, or mailbox polling failures.

## Rollback Readiness

Before promoting a release to production, make sure these are known:

- The previous DMARQ version or image tag.
- The backup file created before deployment.
- The database restore command for the active database type.
- The operator who can update the deployment manifest or systemd service.
- The smoke check results from preprod.

If a rollback requires restoring the database, stop the app before restoring and verify the restored app with the same smoke checks.

## After Release

Record:

- Released version or commit SHA.
- Whether a database migration ran.
- Backup file location or backup job identifier.
- CI and release workflow result.
- Smoke check result.
- Any follow-up issues found during deployment.
