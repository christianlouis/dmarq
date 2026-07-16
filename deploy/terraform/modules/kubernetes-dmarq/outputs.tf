output "release_name" {
  description = "Installed Helm release name."
  value       = helm_release.dmarq.name
}

output "namespace" {
  description = "Kubernetes namespace containing DMARQ."
  value       = helm_release.dmarq.namespace
}

output "chart_version" {
  description = "Installed DMARQ chart version."
  value       = helm_release.dmarq.metadata.chart
}

output "status" {
  description = "Helm release status."
  value       = helm_release.dmarq.status
}
