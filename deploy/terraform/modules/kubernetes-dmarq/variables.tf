variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "dmarq"
}

variable "namespace" {
  description = "Kubernetes namespace for DMARQ."
  type        = string
  default     = "dmarq"
}

variable "create_namespace" {
  description = "Allow Helm to create the namespace."
  type        = bool
  default     = true
}

variable "chart_path" {
  description = "Optional path or published chart reference. Defaults to the chart in this repository."
  type        = string
  default     = null
  nullable    = true
}

variable "existing_secret_name" {
  description = "Existing Kubernetes Secret containing DMARQ and database credentials."
  type        = string

  validation {
    condition     = length(trimspace(var.existing_secret_name)) > 0
    error_message = "existing_secret_name must reference a pre-created Secret."
  }
}

variable "public_base_url" {
  description = "Externally visible absolute URL for DMARQ."
  type        = string

  validation {
    condition     = can(regex("^https?://", var.public_base_url))
    error_message = "public_base_url must be an absolute HTTP or HTTPS URL."
  }
}

variable "owner_email" {
  description = "Owner email used by the idempotent first-run bootstrap job."
  type        = string

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+$", var.owner_email))
    error_message = "owner_email must be a valid email address."
  }
}

variable "profile" {
  description = "DMARQ product profile."
  type        = string
  default     = "single-user"

  validation {
    condition     = contains(["single-user", "multi-workspace", "provider"], var.profile)
    error_message = "profile must be single-user, multi-workspace, or provider."
  }
}

variable "image_repository" {
  description = "DMARQ image repository."
  type        = string
  default     = "ghcr.io/christianlouis/dmarq"
}

variable "image_tag" {
  description = "DMARQ image tag. Pin a release or short SHA for production."
  type        = string
  default     = "docker-stable"
}

variable "project_name" {
  description = "Product name shown in the interface."
  type        = string
  default     = "DMARQ"
}

variable "language" {
  description = "Default product language."
  type        = string
  default     = "en"
}

variable "environment" {
  description = "Application environment."
  type        = string
  default     = "production"
}

variable "auth_mode" {
  description = "Authentication mode configured through non-secret application settings."
  type        = string
  default     = "oidc"

  validation {
    condition = contains(
      ["disabled", "logto", "oidc", "authentik", "trusted_proxy"],
      var.auth_mode
    )
    error_message = "auth_mode is not supported."
  }
}

variable "allow_auth_disabled_in_production" {
  description = "Explicitly permit an auth-disabled production instance. Keep false for exposed installs."
  type        = bool
  default     = false
}

variable "extra_env" {
  description = "Additional non-secret application environment values."
  type        = map(string)
  default     = {}
}

variable "extra_secret_env_from" {
  description = "Additional existing Secrets exposed as application environment variables."
  type        = list(string)
  default     = []
}

variable "postgresql_enabled" {
  description = "Deploy the bundled single-node PostgreSQL workload. Disable for an external database."
  type        = bool
  default     = true
}

variable "app_storage_size" {
  description = "Persistent storage request for DMARQ application data."
  type        = string
  default     = "5Gi"
}

variable "app_persistence_enabled" {
  description = "Persist DMARQ application data. Disable only for disposable tests."
  type        = bool
  default     = true
}

variable "database_storage_size" {
  description = "Persistent storage request for bundled PostgreSQL."
  type        = string
  default     = "8Gi"
}

variable "database_persistence_enabled" {
  description = "Persist bundled PostgreSQL data. Disable only for disposable tests."
  type        = bool
  default     = true
}

variable "storage_class" {
  description = "Optional storage class for application and bundled database claims."
  type        = string
  default     = ""
}

variable "ingress_enabled" {
  description = "Create a Kubernetes Ingress."
  type        = bool
  default     = false
}

variable "ingress_class_name" {
  description = "IngressClass name when ingress is enabled."
  type        = string
  default     = ""
}

variable "ingress_host" {
  description = "Ingress host when ingress is enabled."
  type        = string
  default     = "dmarq.local"
}

variable "ingress_annotations" {
  description = "Ingress annotations."
  type        = map(string)
  default     = {}
}

variable "ingress_tls" {
  description = "Ingress TLS blocks passed to the chart."
  type = list(object({
    secretName = string
    hosts      = list(string)
  }))
  default = []
}

variable "atomic" {
  description = "Roll back a failed Helm installation or upgrade automatically."
  type        = bool
  default     = true
}

variable "timeout_seconds" {
  description = "Maximum Helm operation duration."
  type        = number
  default     = 900
}
