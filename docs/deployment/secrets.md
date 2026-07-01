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
| `AUTHENTIK_CLIENT_SECRET` | Secret | Required when Authentik direct OIDC authentication is enabled. |
| `OIDC_CLIENT_SECRET` | Secret | Required when generic OIDC authentication is enabled. |
| `CLOUDFLARE_API_TOKEN` | Secret | Optional DNS inspection/integration token. |
| `CLOUDFLARE_OAUTH_CLIENT_SECRET` | Secret | Optional Cloudflare OAuth connector secret for one-click zone import and ownership verification. |
| `HETZNER_DNS_API_TOKEN` | Secret | Optional read-only Hetzner DNS zone import token. |
| `LINODE_API_TOKEN` | Secret | Optional read-only Linode DNS domain import token. |
| `FIRST_SUPERUSER_PASSWORD` | Secret | Only needed for bootstrap flows that create an initial local admin. |

Non-sensitive values, such as `IMAP_SERVER`, `IMAP_USERNAME`, `LOGTO_ENDPOINT`,
`LOGTO_APP_ID`, `AUTHENTIK_ISSUER_URL`, `AUTHENTIK_CLIENT_ID`,
`OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `PUBLIC_BASE_URL`, and
`BACKEND_CORS_ORIGINS`, may also live in the Environment so each deployment has
one complete configuration bundle.

OAuth mail connectors can also store provider client secrets and refresh/access tokens in encrypted database fields after an administrator authorizes the source. Treat values such as `GMAIL_CLIENT_SECRET`, Microsoft 365 client secrets, refresh tokens, and access tokens as secrets even when they are provider-generated and short-lived.

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
- Never include provider tokens, authorization headers, client secrets, raw mailbox payloads, or message bodies in connector diagnostics, import history, webhook payloads, screenshots, or support notes.
- Keep `AUTH_DISABLED=true` limited to local development or a deployment protected by a separate authentication proxy.
- Use `AUTH_MODE=trusted_proxy` only when DMARQ is reachable exclusively through the trusted proxy or Authentik Outpost.
- Keep `LOGTO_SKIP_SSL_VERIFY=false` in production.
- Keep `OIDC_SKIP_SSL_VERIFY=false` in production.
- Use separate 1Password Environments for development, preprod, and production.

## Connector Development

New mail-source connectors must follow the shared connector contract in [Mail Connector Framework](../development/connectors.md). Use the shared sanitization helpers for provider errors and store only non-secret import context such as mailbox labels, folder labels, search windows, message IDs, filenames, domains, and report IDs.
