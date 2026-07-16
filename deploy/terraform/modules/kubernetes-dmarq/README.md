# DMARQ Kubernetes Terraform Module

This module installs the checked-in DMARQ Helm chart. It does not create or
receive raw credentials. The referenced Kubernetes Secret must already exist,
normally through External Secrets, Sealed Secrets, SOPS, or an operator-managed
secret store.

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

The module deliberately contains no `local-exec` or `remote-exec`
provisioners. Helm performs declarative apply, upgrade, rollback, and destroy.
The chart's idempotent post-install job completes first-run product setup.

For an external database, set `postgresql_enabled = false` and point the
Secret's `DATABASE_URL` key at that database. Pin `image_tag` to an immutable
release or short SHA in production.
