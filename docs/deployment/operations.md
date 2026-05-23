# Operator Runbook

This runbook is for people who deploy and operate DMARQ. It focuses on repeatable actions: deploy, verify, upgrade, back up, and recover. Keep secrets in 1Password or your deployment secret manager; do not paste raw values into tickets, pull requests, chat, or deployment notes.

## Deployment Modes

### Docker Compose

Use Docker Compose for a single-host deployment or a small production instance.

1. Put configuration in the project `.env` file, preferably mounted from a 1Password Environment.
2. Use PostgreSQL for production. SQLite is acceptable for local or low-volume personal deployments.
3. Start the stack:

   ```bash
   docker compose up -d
   ```

4. Verify:

   ```bash
   docker compose ps
   docker compose logs --tail=100 backend
   curl -fsS http://localhost:8000/health
   curl -fsS http://localhost:8000/api/v1/health
   ```

### Coolify

Use Coolify when you want Git-based Docker deployment with managed environment variables.

1. Create a Docker Compose application from the DMARQ repository.
2. Configure persistent storage for:
   - PostgreSQL data if Coolify manages the database.
   - `/app/data` when using SQLite or file-backed runtime data.
3. Add environment variables in Coolify or inject them from 1Password. Keep `SECRET_KEY`, database credentials, mailbox passwords, OAuth secrets, `WEBHOOK_SECRET`, and Cloudflare tokens concealed.
4. Deploy the app and confirm the backend container stays healthy.
5. Verify the public URL with `/health`, `/api/v1/health`, the dashboard, and Mail Sources.

Do not mount the source tree over the production container. Production containers should run the image contents, not a local development volume.

### Manual Systemd

Use manual installation when Docker is not available.

1. Install Python 3.13 and dependencies in a virtual environment.
2. Configure a systemd unit with a restricted service user.
3. Reference an environment file mounted from 1Password or managed by the host secret store.
4. Run behind Nginx or another TLS reverse proxy.
5. Verify:

   ```bash
   sudo systemctl status dmarq
   sudo journalctl -u dmarq -n 100
   curl -fsS http://127.0.0.1:8000/health
   ```

### Kubernetes Or GitOps

Use Kubernetes when DMARQ is deployed through a cluster-state repository.

1. Store secrets in the cluster secret manager, not in manifests.
2. Pin the image tag to the release or commit being promoted.
3. Apply database migrations through the normal release workflow before routing traffic.
4. Watch rollout status and pod logs.
5. Confirm the preprod manifest update from CI before promoting the same image to production.

## First Deployment Verification

After a new deployment:

1. Open `/health` and `/api/v1/health`.
2. Complete the initial setup flow or confirm login works.
3. Add one monitored domain.
4. Upload a known-good DMARC aggregate report.
5. Confirm the dashboard shows domain totals and compliance.
6. Open the domain details page and verify DNS Health Summary loads.
7. Add or connect a Mail Source, then run **Test connection**.
8. Trigger a manual fetch in a safe mailbox and confirm import history records the attempt.
9. Check logs for repeated database, authentication, DNS, or mailbox polling errors.

## Upgrade Procedure

Use this sequence for every production upgrade:

1. Read the release notes and check for migration or configuration changes.
2. Follow [Database Backup and Restore](backups.md) to create and verify a fresh backup.
3. Record the current image tag, commit SHA, database type, and deployment target.
4. Pull or deploy the new image.
5. Apply database migrations if the release includes them.
6. Restart the app.
7. Run the smoke checks in [Release Checklist](release-checklist.md).
8. Confirm background polling still works by checking Mail Sources import history.
9. Keep the previous image tag and backup available until the deployment has been stable through at least one polling interval.

## Routine Operations

### Daily

- Check the dashboard for report volume and compliance drops.
- Review Mail Sources import history for repeated failures.
- Confirm notifications are being delivered if alerts are enabled.

### Weekly

- Verify the most recent database backup.
- Review unresolved DNS health warnings for monitored domains.
- Check app logs for repeated provider throttling, authentication, or database errors.

### Monthly

- Rotate credentials according to your policy.
- Confirm the restore procedure still works in a temporary environment.
- Review `ALLOWED_HOSTS`, Logto redirect URLs, Cloudflare tokens, and mailbox access.

## Rollback

Rollback is safest when the database schema did not change. If a migration ran, prefer a full restore into the previous application version unless the release notes explicitly say downgrade is supported.

1. Stop DMARQ.
2. Restore the pre-upgrade database backup if needed.
3. Repoint the deployment to the previous image tag or commit.
4. Start DMARQ.
5. Run health checks, dashboard checks, and Mail Sources checks.
6. Record the rollback cause and open a follow-up issue.

