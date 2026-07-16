output "release" {
  value = {
    name      = module.dmarq.release_name
    namespace = module.dmarq.namespace
    status    = module.dmarq.status
  }
}
