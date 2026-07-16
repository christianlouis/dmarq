# Kubernetes, Helm, and Terraform

DMARQ ships one supported Helm chart and a Terraform module that consumes that
chart. Both use the same application image as Docker Compose and keep
credentials outside chart values and Terraform configuration.

## Prerequisites

- Kubernetes 1.28 or newer
- Helm 3.14 or newer
- an ingress controller and TLS issuer when the instance is exposed publicly
- a default StorageClass, or explicit storage classes in the values
- an existing Kubernetes Secret with the required application and database keys

Pin a release or short-SHA image for production. `docker-stable` is appropriate
for an initial test, but it is intentionally a moving installation channel.

## Secret Boundary

Create the Secret before installing DMARQ. The checked-in
`docs/deployment/examples/dmarq-kubernetes-secret.example.yaml` documents the
required keys without containing usable credentials:

- `DATABASE_URL`
- `SECRET_KEY`
- `ADMIN_API_KEY`
- `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` when bundled
  PostgreSQL is enabled

Prefer External Secrets, Sealed Secrets, SOPS, or the cluster's existing secret
delivery mechanism. The Helm chart and Terraform module reference the Secret by
name and never copy its values into Terraform state. The referenced Secret is
also loaded as application environment so it can carry OIDC or DNS-provider
credentials; do not mix unrelated credentials into it.

The bundled database service is named `<release>-postgresql`. For the default
release name, the database URL host is `dmarq-postgresql`. With an external
database, disable bundled PostgreSQL and provide its URL in the same Secret.

## Helm Install

Review `deploy/helm/dmarq/values.yaml`, then install with non-secret values:

```bash
helm upgrade --install dmarq deploy/helm/dmarq \
  --namespace dmarq \
  --create-namespace \
  --atomic \
  --wait \
  --set existingSecret=dmarq \
  --set image.tag=1.172.4 \
  --set config.environment=production \
  --set config.publicBaseUrl=https://dmarq.example.com \
  --set config.authMode=oidc \
  --set bootstrap.enabled=true \
  --set bootstrap.ownerEmail=owner@example.com
```

Production rendering fails when authentication is disabled unless the operator
explicitly accepts that unsafe mode. OIDC, Logto, Authentik, and trusted-proxy
credentials belong in an additional existing Secret listed under
`extraSecretEnvFrom`.

The optional bootstrap Job waits for DMARQ, creates the owner, completes system
setup, verifies the final state, and exits. Repeated Helm upgrades are
idempotent because the setup API reports completion before accepting new setup
writes.

## Agent-Controlled Install

Start from the Kubernetes contract example and update its URL, owner, image,
namespace, authentication mode, and existing Secret name:

```bash
python3 scripts/dmarqctl.py \
  --config docs/deployment/examples/agent-install.kubernetes.json \
  --json preflight
python3 scripts/dmarqctl.py --config install.json --json bootstrap
python3 scripts/dmarqctl.py --config install.json --json status
```

Preflight verifies the architecture, Helm, active Kubernetes context, chart,
and Secret. Bootstrap performs an atomic Helm install or upgrade and removes
its temporary non-secret values file. No Kubernetes credential or application
secret is returned in the machine-readable result.

## Terraform

The module is at `deploy/terraform/modules/kubernetes-dmarq`; a runnable example
is at `deploy/terraform/examples/kubernetes`.

```hcl
module "dmarq" {
  source = "../../modules/kubernetes-dmarq"

  existing_secret_name = "dmarq"
  public_base_url       = "https://dmarq.example.com"
  owner_email           = "owner@example.com"
  image_tag             = "1.172.4"

  ingress_enabled    = true
  ingress_class_name = "nginx"
  ingress_host       = "dmarq.example.com"
}
```

Apply and verify:

```bash
terraform init
terraform plan
terraform apply
kubectl --namespace dmarq rollout status deployment/dmarq
```

The module has no `local-exec` or `remote-exec` provisioners. A normal plan
contains only non-secret deployment intent. Upgrades change `image_tag` and run
through Helm's atomic upgrade path. `terraform plan -detailed-exitcode` is the
drift gate; `terraform destroy` removes the release but deliberately does not
delete the externally managed Secret.

## Runtime Verification

```bash
kubectl --namespace dmarq port-forward service/dmarq 8080:80
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/api/v1/setup/status
curl --fail http://127.0.0.1:8080/api/v1/health/release
```

After readiness, connect a report mailbox and ingest a real or fixture DMARC
aggregate report. A healthy pod alone does not prove the product workflow.
