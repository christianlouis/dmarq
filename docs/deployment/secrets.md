# Secret Handling with 1Password

This guide describes the recommended production flow for injecting DMARQ secrets without copying raw values into source-controlled files, shell history, chat logs, or deployment notes.

Use 1Password Environments as the source of truth for sensitive environment variables. DMARQ reads standard environment variables at startup, so the deployment process only needs to make those variables available to the authorized process.

## Recommended Variables

Store these values in a 1Password Environment for each deployment target:

| Variable | Sensitivity | Notes |
|----------|-------------|-------|
| `SECRET_KEY` | Secret | Required for stable sessions. Use a strong random value. |
| `ADMIN_API_KEY` | Secret | Optional fixed admin API key. Use only when needed for automation. |
| `DATABASE_URL` | Secret when it contains credentials | Prefer this single URL for production PostgreSQL deployments. |
| `IMAP_PASSWORD` | Secret | Required when IMAP polling is enabled. |
| `LOGTO_APP_SECRET` | Secret | Required when Logto authentication is enabled. |
| `CLOUDFLARE_API_TOKEN` | Secret | Optional DNS inspection/integration token. |
| `FIRST_SUPERUSER_PASSWORD` | Secret | Only needed for bootstrap flows that create an initial local admin. |

Non-sensitive values, such as `IMAP_SERVER`, `IMAP_USERNAME`, `LOGTO_ENDPOINT`, `LOGTO_APP_ID`, and `BACKEND_CORS_ORIGINS`, may also live in the Environment so each deployment has one complete configuration bundle.

## Create the Environment

1. Open 1Password and enable the local MCP server or Environments feature if it is not already enabled.
2. Create a 1Password Environment named for the target, for example `DMARQ Preprod` or `DMARQ Production`.
3. Add the variables listed above. Mark secrets as concealed.
4. Grant access only to the operators and deployment systems that need that target.

## Local Development

For local runs, mount the 1Password Environment as a local `.env` file:

```bash
# Example mount path for a local checkout
/path/to/dmarq/.env
```

Then start DMARQ normally:

```bash
docker compose up -d
```

or, for a manual backend run:

```bash
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The mounted `.env` file is managed by 1Password. Do not copy its contents into commits, issues, pull requests, or chat messages.

## Docker Compose Production Pattern

For Docker Compose hosts, mount the Environment as the project `.env` file and keep `docker-compose.yml` using variable references:

```bash
docker compose pull
docker compose up -d
```

This lets Compose read the mounted `.env` file while 1Password remains the system that stores and syncs the actual secret values.

If your deployment runner supports command-level injection instead of local file mounts, run Compose inside that authorized injection context and avoid writing a `.env` file to disk.

## Systemd Production Pattern

For manual Linux deployments, prefer a 1Password-mounted env file referenced by the service:

```ini
[Service]
EnvironmentFile=/opt/dmarq/.env
WorkingDirectory=/opt/dmarq/backend
ExecStart=/opt/dmarq/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Restrict the service user and file permissions so only the DMARQ process and the operator account can read the mounted file.

## Rotation Checklist

1. Update the variable in the relevant 1Password Environment.
2. Restart the DMARQ process or container so it receives the new value.
3. Verify health checks and login/API behavior.
4. Revoke the old credential at the upstream provider when applicable.
5. Record that rotation happened, but do not record the secret value.

## Safety Rules

- Never commit `.env` files or secret values.
- Never paste mailbox passwords, OAuth secrets, API tokens, database passwords, or generated session keys into issues, pull requests, logs, or chat.
- Keep `AUTH_DISABLED=true` limited to local development or a deployment protected by a separate authentication proxy.
- Keep `LOGTO_SKIP_SSL_VERIFY=false` in production.
- Use separate 1Password Environments for development, preprod, and production.
