# Greenfield Deployment Verification

Use this checklist to validate DMARQ as a new operator with no project-specific
knowledge. It deliberately starts from the public repository instructions and
the published image instead of a maintainer workstation build.

## Clean Host

Test on a supported Linux host with no existing DMARQ containers, volumes, or
environment file. Record the operating-system, Docker Engine, Docker Compose,
DMARQ image, and image digest in the test notes. Do not record secret values.

Minimum acceptance environment:

- Ubuntu 22.04 or 24.04
- Docker Engine 24 or later
- Docker Compose v2.20 or later
- OpenSSL
- Python 3.10 or later for the Compose contract verifier
- outbound HTTPS and IMAPS access when mailbox ingestion is tested

## Stable Image Installation

Follow only the repository quick start:

```bash
git clone https://github.com/christianlouis/dmarq.git
cd dmarq
./scripts/bootstrap-docker-env.sh
docker compose pull
docker compose up -d --wait
```

Do not add unpublished variables or manually create database objects. The
bootstrap script must create `.env` with mode `0600` and must not print generated
secrets. The default image must resolve to
`ghcr.io/christianlouis/dmarq:docker-stable`.

## Infrastructure Checks

```bash
docker compose ps
docker compose images
docker compose port app 8080
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/v1/health
./scripts/verify-docker-compose.sh
```

Accept the deployment only when:

- the app and database are healthy;
- DMARQ is bound to the configured host address and port;
- PostgreSQL has no published host port;
- the setup page loads without a login loop;
- app logs contain no repeated startup, migration, or database errors; and
- the effective app image matches `DMARQ_IMAGE` in `.env`.

## Product Checks

Complete setup in the browser using an owner contact email. This address is not
a local username: local username/password authentication is not implemented.
Then:

1. Open the dashboard and all primary navigation destinations.
2. Add a monitored domain.
3. Upload a known-good DMARC aggregate XML report.
4. Confirm the domain, report count, message count, and compliance result match
   the uploaded fixture.
5. Restart both services and confirm setup, domains, and reports persist.
6. Change a non-secret `.env` value, recreate the app container, and confirm the
   new value is effective. A plain restart is not sufficient to reload `.env`.

The deterministic setup/import/persistence subset can be run against a fresh
instance with:

```bash
python3 scripts/verify-greenfield-product.py
docker compose up -d --force-recreate --wait app
python3 scripts/verify-greenfield-product.py --verify-existing
```

The verifier completes first-run setup, imports the repository DMARC fixture,
checks exact report/message/compliance totals, rejects a duplicate upload, and
then confirms the same state after the application container is recreated. Run
it only against a disposable, unconfigured acceptance instance.

## Gmail IMAP Check

Use a dedicated Google App Password, never the normal Google account password.
Add an IMAP Mail Source with `imap.gmail.com`, port `993`, SSL enabled, and the
full Gmail address. Keep deletion disabled during acceptance testing.

1. Run **Test connection** and require a successful result.
2. Run **Fetch now** and inspect import history.
3. Confirm at least one real DMARC aggregate report is parsed and persisted.
4. Run **Fetch now** again and confirm duplicate handling does not inflate the
   report or message totals.
5. Recreate the app container and confirm the encrypted mail source still works.
6. Wait through a configured polling interval and confirm a scheduled attempt is
   recorded without manual interaction.

Revoke the App Password after an ephemeral acceptance test. For a maintained
instance, store mailbox credentials through the deployment secret manager and
rotate them according to the operator policy.

## Image Channels

- `docker-stable`: normal installation channel, promoted only after the exact
  immutable image passes registry-based startup and DMARC fixture smoke tests.
- `docker-latest`: preview of a successfully built `main` image; useful for
  pre-release validation, not a rollback anchor.
- release or short-SHA tag: immutable deployment choice for Kubernetes, GitOps,
  production rollback, and auditability.

To test the preview channel, set `DMARQ_IMAGE` in `.env` to
`ghcr.io/christianlouis/dmarq:docker-latest`, then run `docker compose pull` and
`docker compose up -d --wait`. Restore `docker-stable` after the preview test.

## Kubernetes Contract

The same image must remain deployable in Kubernetes without Compose-only
variables. Validate that the workload still uses:

- container port `8080`;
- `/healthz` for liveness/readiness;
- the image entrypoint supplied by the repository Dockerfile;
- `DATABASE_URL` and application settings injected through Secrets/ConfigMaps;
- an immutable release or short-SHA image tag.

`DMARQ_BIND_ADDRESS`, `DMARQ_PORT`, and `POSTGRES_*` are Compose orchestration
values and are not required in a Kubernetes application pod.

## Release Evidence

Keep the following non-secret evidence with the release or issue:

- tested image reference and digest;
- clean-host platform versions and architecture;
- published Linux AMD64 and ARM64 manifest entries;
- Compose service health;
- health and release endpoint results;
- successful setup and fixture-import totals;
- Gmail connection, manual fetch, duplicate, persistence, and scheduled-poll
  results;
- Kubernetes manifest contract result; and
- any documentation gap found while following the guide literally.
