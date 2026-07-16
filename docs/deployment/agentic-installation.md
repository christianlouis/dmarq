# Agentic and Non-Interactive Installation

DMARQ includes a versioned installation contract and a standard-library control
tool for automation that must work before application dependencies are
installed. It supports Docker Compose and the checked-in Kubernetes Helm chart;
the Terraform module consumes the same chart.

## Contract

Start from the checked-in Compose example:

```text
docs/deployment/examples/agent-install.compose.json
```

The corresponding JSON Schema is:

```text
docs/deployment/schemas/install-v1.schema.json
```

Kubernetes automation starts from:

```text
docs/deployment/examples/agent-install.kubernetes.json
```

The contract separates non-secret installation intent from credentials. Secret
sources are either generated once or read from a named environment variable:

```json
{
  "secretKey": {"env": "DMARQ_SECRET_KEY"},
  "adminApiKey": {"generate": true}
}
```

DMARQ never prints the resolved value. For production, inject those environment
variables from the operator's secret manager. A generated or injected value is
preserved on repeat bootstrap runs so automation does not rotate encryption or
database credentials accidentally.

## Preflight

Run all host and configuration checks with deterministic JSON output:

```bash
python3 scripts/dmarqctl.py \
  --config docs/deployment/examples/agent-install.compose.json \
  --json preflight
```

For Compose, the result includes stable check codes for host architecture,
Docker Compose, the listen address, and writable storage. Kubernetes preflight
checks Helm, the active cluster context, the local chart, and the referenced
existing Secret.

## Bootstrap

Edit a copy of the example with the owner email, URL, bind address, and desired
profile, then run:

```bash
python3 scripts/dmarqctl.py --config install.json --json bootstrap
```

For Compose this command:

1. creates the configured environment file with mode `0600`;
2. generates missing local secrets without printing them;
3. preserves existing secret values on repeat runs;
4. pulls and starts the configured published image; and
5. completes the owner and system setup through the local API when setup is not
   already complete.

Use `bootstrap --no-start` to validate and render the environment without
starting containers. This is useful for plan, review, and secret-injection
stages. Use `bootstrap --setup-existing` after an external orchestrator has
started the stack to complete only the idempotent first-run API setup.

For Kubernetes, `bootstrap` performs an atomic, waiting Helm install or upgrade
with a temporary non-secret values file and the chart's idempotent setup Job.
The existing Kubernetes Secret is never read or returned by `dmarqctl`. See
[Kubernetes, Helm, and Terraform](kubernetes-terraform.md) for the complete
secret, storage, ingress, upgrade, drift, and destroy contract.

## Status

After startup, request one bounded readiness result:

```bash
python3 scripts/dmarqctl.py --config install.json --json status
```

The response contains health, setup completion, domain and mail-source counts,
and release identity. It contains no credential values.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Operation completed and the requested state is ready |
| `2` | Invalid or unsupported installation configuration |
| `3` | Host preflight requirement is not satisfied |
| `4` | DMARQ is unreachable or not ready |
| `5` | Bootstrap or API operation failed |

Automation should branch on the exit code and the structured `status`,
`checks`, or `error.code` fields. Human-readable output remains available by
omitting `--json`.

## Security Boundary

- Keep installation JSON free of raw secret values.
- Pass secret values through the named process environment only for the
  bootstrap process.
- Do not upload the generated environment file to support tickets or source
  control.
- Keep `AUTH_MODE=disabled` bound to localhost. Internet-facing installations
  must use a supported identity provider or trusted authentication proxy.
- Terraform installations reference existing Kubernetes Secrets or an External
  Secrets resource so normal plans do not contain credentials.
