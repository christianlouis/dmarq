variable "kubeconfig_path" {
  description = "Path to the kubeconfig used by the Helm provider."
  type        = string
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  description = "Optional kubeconfig context. Null uses the file's current context."
  type        = string
  default     = null
  nullable    = true
}

variable "existing_secret_name" {
  type    = string
  default = "dmarq"
}

variable "public_base_url" {
  type    = string
  default = "https://dmarq.example.com"
}

variable "owner_email" {
  type    = string
  default = "owner@example.com"
}

variable "image_tag" {
  type    = string
  default = "docker-stable"
}

variable "ingress_enabled" {
  type    = bool
  default = false
}

variable "ingress_class_name" {
  type    = string
  default = ""
}

variable "ingress_host" {
  type    = string
  default = "dmarq.example.com"
}
