variable "project_name" {
  type    = string
  default = "DMARQ"
}

variable "image_tag" {
  type    = string
  default = "docker-stable"
}

module "dmarq" {
  source = "../../modules/kubernetes-dmarq"

  existing_secret_name = "dmarq"
  public_base_url      = "http://dmarq.dmarq.svc.cluster.local"
  owner_email          = "owner@example.com"
  project_name         = var.project_name
  image_tag            = var.image_tag
  environment          = "development"
  auth_mode            = "disabled"

  app_persistence_enabled      = false
  database_persistence_enabled = false
}

output "release_status" {
  value = module.dmarq.status
}
