# Database Backup and Restore

This guide covers database backups for DMARQ deployments using SQLite or PostgreSQL. Back up the database before upgrades, before changing migrations, and on a regular schedule that matches how much DMARC history you can afford to lose.

## What To Back Up

Back up these items together:

- The DMARQ database: SQLite file or PostgreSQL database.
- The deployment configuration needed to reconnect the app to that database.
- The secret store or secret references used by the deployment. Do not copy raw secrets into backup notes, issue comments, or chat logs.

The database contains domains, parsed reports, report records, settings, mail source configuration, Gmail ingest state, and import history. It does not replace your deployment secrets, so keep secret backups in your password manager or secret-management system.

## Backup Cadence

Recommended minimums:

- Before every upgrade or migration.
- Daily for active production instances.
- Weekly for low-volume personal instances.
- After adding important domains or mail sources.

Keep at least one recent backup off the server that runs DMARQ. Periodically test restoring into a temporary database so backups are proven, not only present.

## SQLite Backups

SQLite is easiest to back up when the app is stopped. The `.backup` command is safer than copying a live database file because it asks SQLite to create a consistent copy.

### Docker Compose SQLite

```bash
mkdir -p backups
backup_file="backups/dmarq-$(date +%Y%m%d-%H%M%S).db"

docker compose stop app
sqlite3 data/dmarq.db ".backup $backup_file"
sqlite3 "$backup_file" "PRAGMA integrity_check;"
docker compose start app
```

Restore a SQLite backup:

```bash
docker compose stop app
cp data/dmarq.db "data/dmarq-before-restore-$(date +%Y%m%d-%H%M%S).db"
cp backups/dmarq-backup.db data/dmarq.db
docker compose start app
docker compose logs --tail=100 app
```

### Manual SQLite

```bash
sudo systemctl stop dmarq
mkdir -p /var/backups/dmarq
backup_file="/var/backups/dmarq/dmarq-$(date +%Y%m%d-%H%M%S).db"

sqlite3 /path/to/dmarq/data/dmarq.db ".backup $backup_file"
sqlite3 "$backup_file" "PRAGMA integrity_check;"
sudo systemctl start dmarq
```

Restore a manual SQLite backup:

```bash
sudo systemctl stop dmarq
cp /path/to/dmarq/data/dmarq.db "/path/to/dmarq/data/dmarq-before-restore-$(date +%Y%m%d-%H%M%S).db"
cp /var/backups/dmarq/dmarq-backup.db /path/to/dmarq/data/dmarq.db
sudo systemctl start dmarq
sudo journalctl -u dmarq -n 100
```

## PostgreSQL Backups

Use PostgreSQL custom-format dumps for normal operations. They restore cleanly with `pg_restore` and are easier to validate than plain SQL files.

### Docker Compose PostgreSQL

```bash
mkdir -p backups
backup_file="backups/dmarq-$(date +%Y%m%d-%H%M%S).dump"

docker compose exec -T db pg_dump \
  -U "${POSTGRES_USER:-dmarq}" \
  -d "${POSTGRES_DB:-dmarq}" \
  --format=custom \
  > "$backup_file"

pg_restore --list "$backup_file" >/dev/null
```

Restore a Docker Compose PostgreSQL backup:

```bash
docker compose stop app

cat backups/dmarq-backup.dump | docker compose exec -T db pg_restore \
  -U "${POSTGRES_USER:-dmarq}" \
  -d "${POSTGRES_DB:-dmarq}" \
  --clean \
  --if-exists \
  --no-owner

docker compose start app
docker compose logs --tail=100 app
```

### Manual PostgreSQL

If `DATABASE_URL` is available to your shell:

```bash
mkdir -p /var/backups/dmarq
backup_file="/var/backups/dmarq/dmarq-$(date +%Y%m%d-%H%M%S).dump"

pg_dump --dbname "$DATABASE_URL" --format=custom > "$backup_file"
pg_restore --list "$backup_file" >/dev/null
```

Restore a manual PostgreSQL backup:

```bash
sudo systemctl stop dmarq

pg_restore \
  --dbname "$DATABASE_URL" \
  --clean \
  --if-exists \
  --no-owner \
  /var/backups/dmarq/dmarq-backup.dump

sudo systemctl start dmarq
sudo journalctl -u dmarq -n 100
```

If you do not use `DATABASE_URL`, pass the database name, host, user, and port to `pg_dump` and `pg_restore` with the standard PostgreSQL flags.

## Before Upgrades

Use this checklist before upgrading DMARQ:

1. Create a fresh database backup.
2. Verify the backup can be listed or passes SQLite integrity checks.
3. Record the current DMARQ version and image tag.
4. Apply the upgrade and let migrations run.
5. Confirm the app starts, the dashboard loads, and recent reports are still visible.

## Restore Verification

After any restore, check:

- The app starts without database errors.
- Domain list and dashboard totals are present.
- Mail source import history is visible.
- Recent uploaded or imported reports appear in the UI.
- Background polling logs do not show repeated database failures.

For PostgreSQL production deployments with strict recovery requirements, also consider managed database snapshots or WAL archiving in addition to `pg_dump`.
