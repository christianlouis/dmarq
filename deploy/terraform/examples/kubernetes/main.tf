module "dmarq" {
  source = "../../modules/kubernetes-dmarq"

  existing_secret_name = var.existing_secret_name
  public_base_url      = var.public_base_url
  owner_email          = var.owner_email
  image_tag            = var.image_tag

  ingress_enabled    = var.ingress_enabled
  ingress_class_name = var.ingress_class_name
  ingress_host       = var.ingress_host
}
