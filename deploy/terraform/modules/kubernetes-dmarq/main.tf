locals {
  chart_path = var.chart_path != null ? var.chart_path : abspath("${path.module}/../../../helm/dmarq")

  values = {
    image = {
      repository = var.image_repository
      tag        = var.image_tag
    }
    existingSecret = var.existing_secret_name
    config = {
      projectName                   = var.project_name
      environment                   = var.environment
      publicBaseUrl                 = var.public_base_url
      language                      = var.language
      profile                       = var.profile
      authMode                      = var.auth_mode
      allowAuthDisabledInProduction = var.allow_auth_disabled_in_production
      extraEnv                      = var.extra_env
    }
    extraSecretEnvFrom = var.extra_secret_env_from
    bootstrap = {
      enabled    = true
      ownerEmail = var.owner_email
    }
    persistence = {
      enabled      = var.app_persistence_enabled
      size         = var.app_storage_size
      storageClass = var.storage_class
    }
    postgresql = {
      enabled = var.postgresql_enabled
      persistence = {
        enabled      = var.postgresql_enabled && var.database_persistence_enabled
        size         = var.database_storage_size
        storageClass = var.storage_class
      }
    }
    ingress = {
      enabled     = var.ingress_enabled
      className   = var.ingress_class_name
      annotations = var.ingress_annotations
      hosts = [{
        host = var.ingress_host
        paths = [{
          path     = "/"
          pathType = "Prefix"
        }]
      }]
      tls = var.ingress_tls
    }
  }
}

resource "helm_release" "dmarq" {
  name             = var.release_name
  namespace        = var.namespace
  create_namespace = var.create_namespace
  chart            = local.chart_path

  values = [yamlencode(local.values)]

  atomic          = var.atomic
  cleanup_on_fail = true
  wait            = true
  wait_for_jobs   = true
  timeout         = var.timeout_seconds
}
